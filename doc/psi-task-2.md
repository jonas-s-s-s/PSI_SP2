# KIV/PSI 2024/2025

## 2. úloha – Topologie sítě

### Zadání:
Implementujte aplikaci, která automaticky zjistí topologii sítě.

### Popis:
Implementujte aplikaci v programovacím jazyce **Python**, která automaticky zjistí topologii sítě, ve které se nachází.  
Aplikace ke zjištění topologie využívá protokol **SNMP**, pomocí kterého získá ze směrovačů obsah směrovacích tabulek.

Nejprve pomocí **DHCP** získá adresu výchozího směrovače, adresy dalších směrovačů pak rekurzivním způsobem z obsahu směrovacích tabulek jednotlivých směrovačů. Je nutné si uvědomit, že směrovač má zpravidla více rozhraní a je tedy identifikován více IP adresami.

Relevantní **SNMP** objekty týkající se směrovací tabulky, rozhraní a IP adres směrovače najdete v dokumentu **RFC-1213**.

---

### Technické podmínky:
- K implementaci použijte referenční **GNS3 projekt**, který je dostupný na adrese:  
  [psi-example-project-1.gns3project](https://home.zcu.cz/~maxmilio/PSI/psi-example-project-1.gns3project).  
  Lze jej snadno naimportovat do GNS3 přes funkci „File/Import portable project“.

- Aplikaci implementujte v programovacím jazyce **Python (verze 3)** pomocí knihoven:
    - **Scapy**: [Scapy Documentation](https://scapy.net/)
    - **PySNMP**: [PySNMP Documentation](https://pysnmp.readthedocs.io/en/latest/)

- Aplikace bude zveřejněna ve veřejném repozitáři na **GitHub**, tak aby ji bylo možné na libovolném uzlu `psi-base-node-*` naklonovat a spustit.

- Všechny potřebné knihovny a nástroje jsou již předinstalovány v **GNS3 appliance** `psi-base-node`.

---

### Odevzdání:
- Dokumentace musí obsahovat stručný popis funkce implementovaného software, jak je možné aplikaci sestavit a spustit.

- Dokumentaci zpracujte ve formě souboru `README.md`, který umístíte v kořenovém adresáři repozitáře úlohy. K formátování dokumentace použijte značkovací jazyk **Markdown**.

- Zdrojové kódy nahrajte do repozitáře na **GitHub**.

- V **MS Teams** v týmu **KIV/PSI** svoji práci odevzdejte tak, že připojíte pouze odkaz do repozitáře.

---

### Zdroje informací:
- **Markdown Guide**  
  [Getting Started with Markdown](https://www.markdownguide.org/getting-started/)

- **Management Information Base for Network Management of TCP/IP-based internets: MIB-II**  
  [RFC-1213](https://www.rfc-editor.org/rfc/rfc1213.html)

- **Scapy**
    - [Scapy Homepage](https://scapy.net/)
    - [Scapy in 15 Minutes](https://github.com/secdev/scapy/blob/master/doc/notebooks/Scapy%20in%2015%20minutes.ipynb)
    - [Scapy API Documentation](https://scapy.readthedocs.io/en/latest/api/scapy.html)

- **SNMP Library for Python**  
  [PySNMP Documentation](https://pysnmp.readthedocs.io/en/latest/)

- **GNS3 appliance `psi-base-node`**  
  [GitHub Repository](https://github.com/maxotta/kiv-psi-base-docker)

---
