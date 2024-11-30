#!/usr/bin/env python3
from scapy.all import *
from threading import Thread
from time import sleep
from datetime import datetime
import asyncio
import re
from pysnmp.hlapi.v3arch.asyncio import *
import time


# ******************************************************************
# *** SNMP FUNCTIONS
# ******************************************************************

#############################################
# SNMP CONNECTION TEST
#############################################
async def is_snmp_running(ip):
    """Tests if SNMP is running at a device with given IP"""
    snmpEngine = SnmpEngine()

    cmd = getCmd(
        snmpEngine,
        CommunityData("public", mpModel=0),
        await UdpTransportTarget.create((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )
    errorIndication, errorStatus, errorIndex, varBinds = await cmd
    snmpEngine.closeDispatcher()

    if errorIndication:
        return False
    elif errorStatus:
        return False
    else:
        return True


#############################################
# SNMP sysDescr
#############################################
async def get_snmp_sysDescr(ip):
    """Returns the description of this SNMP device"""
    snmpEngine = SnmpEngine()

    # Initialize the SNMP query
    iterator = getCmd(
        snmpEngine,
        CommunityData("public", mpModel=0),
        await UdpTransportTarget.create((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )

    # Perform the query
    errorIndication, errorStatus, errorIndex, varBinds = await iterator

    # Collect result strings
    result = []

    if errorIndication:
        result.append(str(errorIndication))
    elif errorStatus:
        result.append(
            "{} at {}".format(
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex) - 1][0] or "?",
            )
        )
    else:
        for varBind in varBinds:
            result.append(varBind[1].prettyPrint())

    snmpEngine.closeDispatcher()
    return "\n".join(result)


#############################################
# SNMP INTERFACES
#############################################
async def get_snmp_interfaces(ip):
    engine = SnmpEngine()
    interfaces = {}
    _objTypesMap = {
        "1.3.6.1.2.1.4.20.1.1": "ipAdEntAddr",
        "1.3.6.1.2.1.4.20.1.2": "ipAdEntIfIndex",
        "1.3.6.1.2.1.4.20.1.3": "ipAdEntNetMask",
        "1.3.6.1.2.1.4.20.1.4": "ipAdEntBcastAddr",
        "1.3.6.1.2.1.4.20.1.5": "ipAdEntReasmMaxSize"
    }

    async def _send_get_next(oid):
        errorIndication, errorStatus, errorIndex, varBinds = await nextCmd(
            engine,
            CommunityData('public'),
            await UdpTransportTarget.create((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        return varBinds[0][0].getOid().prettyPrint(), varBinds[0][1].prettyPrint()

    def _process_interface_record(oid, value):
        # First 10 number groups separated by the "." character
        objectType = re.search(r'^(\d+)([.]\d+){9}', oid).group(0)
        # Last 4 number groups separated by the "." character
        recordId = re.search(r'(\d+)([.]\d+){3}$', oid).group(0)

        if objectType not in _objTypesMap:
            raise Exception(f"Error: get_snmp_ipAddrEntry() - objectType {objectType} is not in the _objTypesMap.")
        typeOfRecord = _objTypesMap[objectType]
        # Uncomment on debug:
        # print(objectType, "\t", recordId, "\t", typeOfRecord, "\n")

        if recordId in interfaces:
            interfaces[recordId][typeOfRecord] = value
        else:
            interfaces[recordId] = {typeOfRecord: value}

    initial_oid = "1.3.6.1.2.1.4.20"
    oid = initial_oid
    responseValue = None

    nextRequestNum = 0
    while initial_oid in oid:
        if responseValue:
            print(f"get-response: {oid} = {responseValue}")
            _process_interface_record(oid, responseValue)

        oid, responseValue = await _send_get_next(oid)
        nextRequestNum += 1

    print(f"\nSent {nextRequestNum} get-next-request packets in total.")
    engine.closeDispatcher()

    return interfaces


#############################################
# SNMP ARP TABLE
#############################################
async def get_snmp_arp_table(ip):
    engine = SnmpEngine()
    arp_table_devices = set()

    async def _send_get_next(oid):
        errorIndication, errorStatus, errorIndex, varBinds = await nextCmd(
            engine,
            CommunityData('public'),
            await UdpTransportTarget.create((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        return varBinds[0][0].getOid().prettyPrint(), varBinds[0][1].prettyPrint()

    def _process_arp_record(oid, value):
        # First 10 number groups separated by the "." character
        objectType = re.search(r'^(\d+)([.]\d+){9}', oid).group(0)
        if objectType == "1.3.6.1.2.1.3.1.1.3":
            arp_table_devices.add(value)

    initial_oid = "1.3.6.1.2.1.3.1"
    oid = initial_oid
    responseValue = None

    nextRequestNum = 0
    while initial_oid in oid:
        if responseValue:
            print(f"get-response: {oid} = {responseValue}")
            _process_arp_record(oid, responseValue)

        oid, responseValue = await _send_get_next(oid)
        nextRequestNum += 1

    print(f"\nSent {nextRequestNum} get-next-request packets in total.")
    engine.closeDispatcher()

    return arp_table_devices


#############################################
# SNMP ROUTING TABLE PROCESSING
#############################################
class RoutingRecordsCache:
    """Datastructure for parsing and storing MIB object routing table info"""
    _objTypesMap = {
        "1.3.6.1.2.1.4.24.4.1.1": "ipCidrRouteDest",
        "1.3.6.1.2.1.4.24.4.1.2": "ipCidrRouteMask",
        "1.3.6.1.2.1.4.24.4.1.3": "ipCidrRouteTos",
        "1.3.6.1.2.1.4.24.4.1.4": "ipCidrRouteNextHop",
        "1.3.6.1.2.1.4.24.4.1.5": "ipCidrRouteIfIndex",
        "1.3.6.1.2.1.4.24.4.1.6": "ipCidrRouteType",
        "1.3.6.1.2.1.4.24.4.1.7": "ipCidrRouteProto",
        "1.3.6.1.2.1.4.24.4.1.8": "ipCidrRouteAge",
        "1.3.6.1.2.1.4.24.4.1.9": "ipCidrRouteInfo",
        "1.3.6.1.2.1.4.24.4.1.10": "ipCidrRouteNextHopAS",
        "1.3.6.1.2.1.4.24.4.1.11": "ipCidrRouteMetric1",
        "1.3.6.1.2.1.4.24.4.1.12": "ipCidrRouteMetric2",
        "1.3.6.1.2.1.4.24.4.1.13": "ipCidrRouteMetric3",
        "1.3.6.1.2.1.4.24.4.1.14": "ipCidrRouteMetric4",
        "1.3.6.1.2.1.4.24.4.1.15": "ipCidrRouteMetric5",
        "1.3.6.1.2.1.4.24.4.1.16": "ipCidrRouteStatus"
    }

    def __init__(self):
        self.routeDict = {}

    def parse_record(self, oid, value):
        # First 11 number groups separated by the "." character
        objectType = re.search(r'^(\d+)([.]\d+){10}', oid).group(0)
        # Last 13 number groups separated by the "." character
        recordId = re.search(r'(\d+)([.]\d+){12}$', oid).group(0)

        if objectType not in self._objTypesMap:
            raise Exception(f"Error: parse_record() - objectType {objectType} is not in the _objTypesMap.")
        typeOfRecord = self._objTypesMap[objectType]
        # Uncomment on debug:
        # print(objectType, "\t", recordId, "\t", typeOfRecord, "\n")

        # recordId serves as a unique identifier of this routing table record
        if recordId in self.routeDict:
            self.routeDict[recordId][typeOfRecord] = value
        else:
            self.routeDict[recordId] = {typeOfRecord: value}

    def get_table_entries(self):
        return self.routeDict


class SnmpRoutingTableProcessor:
    """Consolidates operations and parsing of the routing table into a single class"""

    def __init__(self, snmp_agent_ip):
        self.snmp_agent_ip = snmp_agent_ip
        self.records_cache = RoutingRecordsCache()
        self.engine = SnmpEngine()

    async def _send_get_next(self, oid):
        errorIndication, errorStatus, errorIndex, varBinds = await nextCmd(
            self.engine,
            CommunityData('public'),
            await UdpTransportTarget.create((self.snmp_agent_ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        return varBinds[0][0].getOid().prettyPrint(), varBinds[0][1].prettyPrint()

    async def get_snmp_ipCidrRouteTable(self):
        """Returns routing table information of this device"""
        initial_oid = "1.3.6.1.2.1.4.24.4"
        oid = initial_oid
        responseValue = None

        nextRequestNum = 0
        while initial_oid in oid:
            if responseValue:
                print(f"get-response: {oid} = {responseValue}")
                self.records_cache.parse_record(oid, responseValue)

            oid, responseValue = await self._send_get_next(oid)
            nextRequestNum += 1

        print(f"\nSent {nextRequestNum} get-next-request packets in total.")
        return self.records_cache.get_table_entries()


# ******************************************************************
# *** DHCP FUNCTIONS
# ******************************************************************

#############################################
# DHCP SNIFFING
#############################################
class DhcpSniffer:
    def __init__(self):
        self.serverIp = None

    def get_server_ip(self):
        return self.serverIp

    def handle_dhcp(self, pkt):
        """Print information about DHCP packets."""
        if DHCP in pkt:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            dhcp_type = pkt[DHCP].options[0][1]
            message_types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}
            msg = message_types.get(dhcp_type, "UNKNOWN")
            # Enable when debugging
            # print(f"[{timestamp}] DHCP {msg}: {pkt[DHCP].options}")

    def listen(self):
        """Sniff for DHCP packets."""
        sniff(
            filter="udp and (port 67 or port 68)",
            prn=self.handle_dhcp,
            stop_filter=self.stopfilter,
            store=0,
        )

    def stopfilter(self, x):
        """Stop when DHCP OFFER is received"""
        if DHCP in x:
            if x[DHCP].options[0][1] == 2:
                # Save the IP of our DHCP server
                self.serverIp = x[IP].src
                return True
            else:
                return False


#############################################
# DHCP DISCOVER
#############################################
def discover(iface, mac):
    """Send a DHCP Discover packet."""
    discover_pkt = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=RandInt())
            / DHCP(options=[("message-type", "discover"), "end"])
    )
    sendp(discover_pkt, iface=iface)


def get_dhcp_server_ip():
    """Gets the IP of our DHCP server"""
    conf.verb = 0
    INTERFACE = conf.iface
    MAC_ADDRESS = Ether().src

    mysniff = DhcpSniffer()
    listener = Thread(target=mysniff.listen)
    listener.start()
    sleep(1)  # TODO: Increase sleep if no offer is being caught
    discover(INTERFACE, MAC_ADDRESS)
    listener.join()

    return mysniff.get_server_ip()


# ******************************************************************
# *** MAIN PROGRAM LOGIC
# ******************************************************************

async def snmp_explore(ip, explored_router_ips, topology_routers):
    endpoint_devices_log = []
    interface_log = []
    discovered_routers = set()

    print("\n-------------------------------")
    print(f"Exploring {ip}...")
    print("-------------------------------\n")

    hasSnmp = await is_snmp_running(ip)
    print(f"Is {ip} an SNMP agent? Result: {hasSnmp}")
    if not hasSnmp:
        print("Cannot proceed further. This device doesn't support SNMP.")
        return None, None
    print("----------------------------------------------------------")

    print(f"Getting interface info for {ip} via SNMP...\n")
    interfaces = await get_snmp_interfaces(ip)
    for iface in interfaces:
        explored_router_ips.add(interfaces[iface]["ipAdEntAddr"])
        interface_log.append(
            f"{interfaces[iface]['ipAdEntIfIndex']}\t\t{interfaces[iface]['ipAdEntAddr']}\t\t{interfaces[iface]['ipAdEntNetMask']}")
    print("----------------------------------------------------------")

    print(f"Getting ARP table info for {ip} via SNMP...\n")
    arpTableEntries = await get_snmp_arp_table(ip)
    for endpointIp in arpTableEntries:
        if endpointIp not in explored_router_ips:
            endpoint_devices_log.append(endpointIp)
    print("----------------------------------------------------------")

    print(f"Getting routing table info for {ip} via SNMP...\n")
    rtProcessor = SnmpRoutingTableProcessor(ip)
    tableEntries = await rtProcessor.get_snmp_ipCidrRouteTable()
    for entry in tableEntries:
        nextHop = tableEntries[entry]["ipCidrRouteNextHop"]

        if nextHop in explored_router_ips:
            continue
        if nextHop == "0.0.0.0":
            continue

        discovered_routers.add(tableEntries[entry]["ipCidrRouteNextHop"])
    print("----------------------------------------------------------")

    print(f"Discovered unexplored routers: {discovered_routers}\n")
    router_info = {"ip": ip, "interfaces": interface_log, "endpoints": endpoint_devices_log}

    return discovered_routers, router_info

async def main():
    # Set containing IPs of all already explored router interfaces
    explored_router_ips = set()
    # Final results saved here. For each router we gather interface IPs and devices directly connected to it
    topology_routers = []

    dhcp_server_ip = get_dhcp_server_ip()

    print("\nLocal DHCP server's IP is:", dhcp_server_ip)
    print("----------------------------------------------------------")

    unexplored_routers = [dhcp_server_ip]
    while len(unexplored_routers) != 0:
        ip = unexplored_routers.pop()
        discovered, router_info = await snmp_explore(ip, explored_router_ips, topology_routers)
        if discovered is None:
            continue
        topology_routers.append(router_info)

        for e in discovered:
            if e not in unexplored_routers:
                unexplored_routers.append(e)

    print("\n-------------------------------")
    print("All routers have been explored.")
    print("-------------------------------")

    with open("out.txt", "w") as file:
        file.write(
            f"Result of network topology scan at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S ') + time.tzname[0]}\n")
        n = 1
        for router in topology_routers:
            file.write("\n####################################################\n")
            file.write(f"ROUTER No. {n} ({router['ip']})\n")
            file.write("\nEndpoints connected to this router:\n")
            for endpoint in router["endpoints"]:
                file.write(f"{endpoint}\n")
            file.write("\nInterfaces of this router:\n")
            file.write("No.\t\tIP\t\tMask\n")
            for iface in router["interfaces"]:
                file.write(f"{iface}\n")
            n += 1

    print("\n-------------------------------")
    print("Results written into ./out.txt")
    print("-------------------------------\n")


if __name__ == "__main__":
    # Start main function
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
