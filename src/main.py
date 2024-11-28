#!/usr/bin/env python3
from scapy.all import *
from threading import Thread, Event
from time import sleep
from datetime import datetime

class DhcpTester:
    def __init__(self):
        self.stop_sniffer = Event()

    def listen(self):
        """Sniff for DHCP packets."""
        sniff(
            filter="udp and (port 67 or port 68)",
            prn=self.handle_dhcp,
            store=0,
            stop_filter=lambda _: self.stop_sniffer.is_set(),
        )

    def handle_dhcp(self, pkt):
        """Print information about DHCP packets."""
        if DHCP in pkt:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            dhcp_type = pkt[DHCP].options[0][1]
            message_types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}
            msg = message_types.get(dhcp_type, "UNKNOWN")
            print(f"[{timestamp}] DHCP {msg}: {pkt[DHCP].options}")

    def discover(self, iface, mac):
        """Send a DHCP Discover packet."""
        discover_pkt = (
                Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=RandInt())
                / DHCP(options=[("message-type", "discover"), "end"])
        )
        sendp(discover_pkt, iface=iface)

    def sniff_and_discover(self, iface, mac):
        """Run sniffing and send a DHCP Discover packet."""
        listener = Thread(target=self.listen)
        listener.start()
        sleep(0.5)
        self.discover(iface, mac)
        sleep(2)
        self.stop_sniffer.set()
        listener.join()

if __name__ == "__main__":
    INTERFACE = "eth0"
    MAC_ADDRESS = Ether().src

    dhcp_tester = DhcpTester()
    dhcp_tester.sniff_and_discover(INTERFACE, MAC_ADDRESS)
