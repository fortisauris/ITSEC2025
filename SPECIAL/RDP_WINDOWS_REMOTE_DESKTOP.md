### **1.0.1 OBMEDZENIA**

- **Verzia Windows:** Remote Desktop (RDP) **nefunguje na Windows Home Edition** – je dostupný len v Pro, Enterprise a Education verziách.
- **Sieťové obmedzenia:** Počítač, ku ktorému sa pripojuješ, musí byť **na rovnakej lokálnej sieti** alebo musíš mať správne nastavený prístup z vonkajšej siete (viac v sekcii 1.0.4).
- **Dátový prevod:** RDP generuje **zbytočne veľký sieťový traffic**, čo môže spomaliť pomalšie pripojenia, najmä pri vysokom rozlíšení alebo graficky náročných aplikáciách.
- **Jedno súčasné prihlásenie:** Na jeden účet môže byť **iba jeden používateľ prihlásený naraz** (lokálne alebo diaľkovo). Ak sa diaľkový používateľ prihlási, lokálne relácia sa odhlási (okrem Windows Server, ktorý podporuje viacero súčasných relácií).
- **Grafické obmedzenia:** Niektoré grafické efekty, hardvérové akcelerácie alebo 3D aplikácie nemusia byť plne funkčné cez RDP.

---

### **1.0.2 AKTIVÁCIA**

1. **Povolenie Remote Desktop v systéme:**
    - **Nastavenia > Systém > Diaľkový prístup k počítaču > Povoliť Remote Desktop**
    - Alternatívne cez **SystemPropertiesRemote** (spustiť v dialógovom okne "Spustiť").
2. **Povolenie v Windows Firewall:**
    - **Nastavenia > Aktualizácia a bezpečnosť > Windows Security > Firewall a ochrana siete > Povoliť aplikáciu cez firewall**
    - Zaškrtni **Remote Desktop** pre súkromnú a/alebo verejnú sieť.
3. **Prístupové údaje:** Používaj **silné heslo** – RDP je častým cieľom útokov!

---

### **1.0.3 KOMERČNÉ ALTERNATÍVY**

- **TeamViewer** – populárny, jednoduchý na použitie, podporuje aj mobilné zariadenia, ale **obmedzený bezplatný režim** pre komerčné použitie.
- **AnyDesk** – rýchly, nízka latencia, vhodný pre technickú podporu, ale **bezpečnostné riziká** pri nesprávnom použití.
- **Splashtop** – optimalizovaný pre vzdialené pracoviská, podporuje 4K a zvuk.
- **Chrome Remote Desktop** – jednoduché riešenie cez Google účet, vhodné pre príležitostné použitie.

> [!warning] **POZOR!** Nástroje ako TeamViewer alebo AnyDesk sú **často zneužívané útočníkmi cez sociálne inžinierstvo** (napr. podvodné "technické podpory"). **Príbeh indického call centra:** Útočníci sa vydávajú za podporu Microsoftu, obete presvedčujú, aby nainštalovali TeamViewer a následne okradnú bankové účty alebo šíria malware.

---

### **1.0.4 NASTAVENIE NA PRÍSTUP Z INEJ SIETE**

Ak sa chceš pripojiť z inej siete (napr. z internetu), potrebuješ:

1. **Port Forwarding na routeri:**
    - Presmeruj **port 3389** (štandardný port pre RDP) z verejnej IP adresy routera na lokálnu IP adresu počítača (napr. **Router:7800 → PC:3389**).
    - **Bezpečnostné riziko:** Otvorený port 3389 je častým cieľom útokov! Používaj **nesštandardný port** a **silné heslo**.
2. **Verejná dynamická IP adresa:**
    - Ak nemáš statickú IP, používaj **DDNS službu** (napr. No-IP, DuckDNS) pre mapovanie meniacej sa IP adresy na doménové meno.
3. **VPN (odporúčané riešenie):**
    - Nastav si **VPN server** (napr. WireGuard, OpenVPN) a pripoj sa najprv cez VPN, potom používaj RDP lokálne – **bezpečnejšie ako otvorený port 3389!**
4. **RDP cez Web (RD Web, RD Gateway):**
    - **RD Web** umožňuje prístup cez webový prehliadač (HTTPS), bez potreby otvoreného portu 3389 priamo na internet.
    - **RD Gateway** (Remote Desktop Gateway) – zabezpečený prístup cez HTTPS, vhodný pre firemné prostredie.
5. **Cloudové riešenia:**
    - **Azure Virtual Desktop** alebo **AWS WorkSpaces** – diaľkové pracovné plochy hostované v cloude, bez potreby otvoreného portu doma.

---

**Tip:** Pre maximálnu bezpečnosť kombinuj **VPN + RDP** alebo používaj **MFA (multi-factor authentication)** pre RDP prihlásenie.