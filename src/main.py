#!/usr/bin/env python3
from scapy.all import *
from threading import Thread, Event
from time import sleep
from datetime import datetime


###################################################################
# DHCP SNIFFING
###################################################################
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
            print(f"[{timestamp}] DHCP {msg}: {pkt[DHCP].options}")

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


###################################################################
# DHCP DISCOVER
###################################################################
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
    INTERFACE = conf.iface
    MAC_ADDRESS = Ether().src

    mysniff = DhcpSniffer()
    listener = Thread(target=mysniff.listen)
    listener.start()
    sleep(0.5)  # TODO: Increase sleep if no offer is being caught
    discover(INTERFACE, MAC_ADDRESS)
    listener.join()

    return mysniff.get_server_ip()


###################################################################
# MAIN
###################################################################
def main():
    dhcp_server_ip = get_dhcp_server_ip()
    print(dhcp_server_ip)


if __name__ == "__main__":
    main()
