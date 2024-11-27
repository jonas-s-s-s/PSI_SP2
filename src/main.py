from pysnmp.hlapi import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.volatile import RandMAC
from scapy.all import sniff

def get_default_gateway_ip():
    # Create a DHCP discover packet
    discover = Ether(dst='ff:ff:ff:ff:ff:ff', src=Ether().src, type=0x0800) / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(
        dport=67, sport=68) / BOOTP(op=1, chaddr=Ether().src) / DHCP(options=[('message-type', 'discover'), ('end')])

    # Send the packet and wait for a response
    sendp(discover)
    pkt = sniff(filter=DHCP, count=10) 
    print (pkt.summary()) 
    return None


def main():
    # Initialize necessary components
    print("Starting network topology discovery...")

    # Step 1: Get IP of default gateway router via DHCP
    default_gateway_ip = get_default_gateway_ip()
    print(f"Default gateway IP: {default_gateway_ip}")

    # # Step 2: Get default gateway's routing table via SNMP
    # routing_table = get_routing_table(default_gateway_ip)
    # print(f"Routing table: {routing_table}")
    #
    # # Step 3: Save info about all devices connected to default gateway
    # devices_info = save_connected_devices_info(routing_table)
    # print(f"Connected devices info: {devices_info}")
    #
    # # Step 4: Get IPs of routers connected to default gateway
    # connected_routers_ips = get_connected_routers_ips(routing_table)
    # print(f"Connected routers IPs: {connected_routers_ips}")

    print("Network topology discovery completed.")


if __name__ == "__main__":
    main()
