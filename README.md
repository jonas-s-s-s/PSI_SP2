# PSI_SP2
 
# Todo
**Task:** Aplikace co automaticky zjistí topologii sítě
* Protokoly, které aplikace používá: **SNMP** (_RFC-1213_), **DHCP**
* Knihovny, které aplikace používá: **Scapy** (Packet manipulation library), PySNMP (SNMP lib for Python)

**Implementation:**
~~1) Download GNS3~~
2) Get IP of default gateway router via DHCP
3) Get default gateway's routing table vis SNMP
4) Save info about all devices connected to default gateway
5) Get IPs of routers connected to default gateway
