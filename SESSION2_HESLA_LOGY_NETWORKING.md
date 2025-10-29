#itsec #networking #log_management #pwd

#### CVICENIE 2 UZIVATELIA A PRAVA

Vytvorenie užívateľa:
```powershell
`$Password = Read-Host -AsSecureString "Enter the password for TestUser" 
New-LocalUser -Name "TestUser" -Password $Password -FullName "Test User" -Description "Test user account"`

# pridanie uzivatela k Adminom
`Add-LocalGroupMember -Group "Administrators" -Member "TestUser"`

# Pridanie usera do skupiny Users
`Add-LocalGroupMember -Group "Users" -Member "TestUser"`

```
#### PRAVA K ADRESARU

```powershell
`New-Item -Path "C:\Users\YourUsername\Desktop\TestFolder" -ItemType Directory`

`$folderPath = "C:\Users\YourUsername\Desktop\TestFolder" $user = "TestUser"  

`icacls $folderPath`

# Remove the user 
Remove-LocalUser -Name "TestUser"  

# Remove folder
Remove-Item -Path $folderPath -Recurse -Force`
```


## 3. OCHRANA HESLOM 2FA, BIOMETRIA, FIDO KEY
#pwd
3.1 Silne a zapamatatelne heslo:
``` sql
K@5d1_8tvrtoK_HLADAM_p@pucE
```

3.2 POUZITIE PASSWORD MANAGERA: 
ProtonPassword,
KeePass, 
1PASSWORD, 
LastPass
XPASS

STACI SI POTOM PAMATAT MASTER PASSWORD

>[! warning]
>Akonahle sa hacker dozvie kde mate svoje hesla pokusi sa ich ziskat !!!


#### 3.3 DARKWEB OBCHODOVANIE S HASHMI

Vacsina uniknutych hesiel pochadza z kradezi u velkych poskytovatelov sluzieb ako FB, Adobe atd.

[Have I Been Pwned: Check if your email has been compromised in a data breach](https://haveibeenpwned.com/)


### 3.4 BRUTEFORCE, SLOVNIKOVY UTOK, RAINBOW TABLES
#cracking
> [! info]
> Naco vylamovat zamky ked mate od chaty kluc ?

``` bash
echo -n heslo | md5sum > pwd.txt
md5sum SUBOR

cat pwd.txt
```

>[!warning]
>HACKER - Narozdiel od predstáv filmových fanúšikov sa nemusí hacker nikam ponáhľať. Má na prienik do systému more času na získanie hesiel, právomocí, prístupov, zbieranie dát

``` powershell
"hello world" | Get-Hash -Algorithm MD5
```
```


>[! warning] TOOLBOX>KALI LINUX : johntheripper - tradicny password cracker


``` bash
john --format=raw-md5 pwd.txt

john --incremental=ASCII --format=raw-md5 pwd.txt
cat .john/john.pot
```
POZNAMKA: Vyhodou johna je automaticka detekcia formatu a kodovania

>[! warning] TOOLBOX>KALI LINUX : hashcat - password cracker s vyuzitim automatickeho vykonu jadier Grafickych kariet 

``` bash
hashcat -b. # benchmark pocitaca
hashcat -m 0 -a 3 --show md5.txt
hashcat -m 0 -a 3 --show md5.txt ?l?d ?1?1?1?1?1
hashcat -m 0 -a 0 --show md5.txt /usr/share/wordlists/rockyou.txt

cat /local/share/hashcat/hashcat.potfilecd /
```

>[!info] TOOLBOX>KALI LINUX : rockyou.txt je dlhy wordlist v adresari [/usr/share/wordlists/]. Je standardne kompressovany v archive .gz
>

``` bash
cd /usr/share/wordlist/
sudo gzip -d rockyou.txt.gz
```

>[! warning] TOOLBOX>KALI LINUX : hydra - Slovnikovy utok priamo  priamo na REMOTE SERVER

``` bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt IP ssh
```

### 3.4.1 RAINBOW TABLES
Databaza Vsetky hashe vsetkych hesiel v roznych formatoch


>[! warning] NESIFROVANE  
[List of Rainbow Tables (project-rainbowcrack.com)](http://project-rainbowcrack.com/table.htm)




### 3.5 MULTI FACTOR AUTHENTIFICATION

MultiFactor autentifikacia je moderne riesenie autentifikacie uzivatela do PC alebo servisu.


Google Authentificator  Android APPKA
[google authenticator - Android Apps on Google Play](https://play.google.com/store/search?q=google+authenticator&c=apps)

Microsoft Authentificator APPKA
[microsoft authenticator - Android Apps on Google Play](https://play.google.com/store/search?q=microsoft%20authenticator&c=apps)

Yubi Key DEVICE  
[yubikey.sk – oficiálny predajca](https://yubikey.sk/)
[YubiKey.cz](https://yubikey.cz/)


>[! warning] VŽDY KUPUJTE PÁR 
Ak sa rozhodnete použiť toto riešenie vždy musíte mať náhradný kľúč



Windows Hello : )
BIOMETRIA : )

>[! info]
>APPLE vs. FBI a zablokovany iPhone


## 4. LOGOVANIE
#logs
Windows Log je pristupny cez eventViewer alebo cez Powershell:

``` powershell
Get-EventLog -list
Get-EventLog -LogName Systemn -Newest 10
Get-EventLog -LogName System -After '6/5/23 0:00'
Get-EventLog -LogName System -Message '*login*'
Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 | Select-Object TimeGenerated, Message | Format-Table -AutoSize

# moderny sposob
Get-Service -Name EventLog | Select-Object Name, Status
Get-WinEvent -ListLog *
Get-WinEvent -LogName System -MaxEvents 10
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 10
Get-Service -Name EventLog | Select-Object Name, Status
Start-Service -Name EventLog

```


``` powershell
Get-EventLog System -Source Microsoft-Windows-WinLogon -Newest 10
```
Get-EventLog System -Source Microsoft-Windows-WinLogon -Newest 10


Ukazka skriptovania v Powershell:
``` powershell

for ($i=1; $i -le 5; $i++) {
    if ($i -eq 3) {
        Write-Host "The value of i is $i. This is the third iteration."
    }
    else {
        Write-Host "The value of i is $i."
    }
}
```

``` python

for i in range(1,5):
	if i == 3:
		print(f'Hodnota i je {i} TOTO JE TRETIE V PORADI')
	else:
		print(f'Hodnota i je {i}')
```

LINUX ma viacero systemov ako zachytit logy.

najjednoduchsi je skopirovat vsetko z adresara :

``` bash
cp -R /var/log/*  /kamtochceme
cat /etc/passwd
```

DVA SYSTEMY PRISTUPU K LOGOM
``` bash
dmesg
journalctl
```

dmesg - log kernelu určený na debuggovanie kernelu

journalctl je log systemd určený na monitorovanie userov a počítača

PRIKLAD:
``` bash
dmesg | tail -n 150 | grep root
```

PRIKLAD:
``` bash
journalctl                  # Show all logs (newest first)
journalctl -b              # Show logs from current boot
journalctl -u nginx         # Show logs for a specific service (e.g., Nginx)
journalctl -p err           # Show only errors
journalctl --since "2023-10-01" --until "2023-10-02"  # Filter by time
journalctl -f               # Follow new logs (like `tail -f`)
journalctl --dmesg          # Show only kernel messages (similar to `dmesg`)

```

systemctl list-units --type=service --all

## 5. OCHRANA SYSTEMU POMOCOU HASH ALGORITMOV

VYPOCITAME HASHSTRINGY PRE JEDNOTLIVE SUBORY AJ CELE ADRESARE

``` powershell
Get-FileHash SUBOR -Algorithm md5
Get-FileHash SUBOR -Algorithm SHA256 | Out-File -FilePath SUBOR
Get-FileHash SUBOR -Algorithm SHA256 | Out-File -FilePath SUBOR -Append
Get-ChildItem -Path .\ADRESAR\ -Recurse -Filter *.* | Get-FileHash -Algorithm md5 | Out-File -FilePath .\pwd.hashes -Append
```

POROVNAME ICH POMOCOU JEDNODUCHEHO ALGORITMU
``` powershell
$hashe_stare = Get-FileHash C:\hashes1.txt
$hash_nove = Get-FileHash C:\hashes2.txt

if ($hashe_stare -eq $hashe_nove) {
    Write-Host "The files are identical."
} else {
    Write-Host "The files are different."
}
```

``` powershell
Compare-Object (Get-Content .\pwd.hashes) (Get-Content .\pwd2.hashes)
```



``` linux
md5sum ADRESAR/* > hashes.txt
find ADRESAR -type f -exec md5sum {} \; > hashes.txt
```

``` bash
diff hashes1.txt hashes2.txt
vimdiff hashes1.txt hashes2.txt
```

## 6. USB KLUCE, KABLE A ZARIADENIA  - HUMAN INTERFACE DEVICE 

### 6.1 RUBBER DUCKY

>[!warning] 
>VYZERA TO AKO KACKA + 
>KVAKA TO AKO KACKA =
>TAK TO BUDE KACKA !

RUBBER DUCKY ZA 5EUR

[GitHub - dbisu/pico-ducky: Create a USB Rubber Ducky like device using a Raspberry PI Pico](https://github.com/dbisu/pico-ducky)

### 6.2 AUTOMOUNT - AUTORUN - SLUZBA ALEBO PREKLIATIE
#mount
``` linux
sudo fdisk -l
mkdir USB_KLUC
mount /dev/sd?1 /USB_KLUC
umount USB_KLUC
```



# SIETE A VZNIK A TOPOGRAFIA SIETE
#lan
MODEM - Modulator-Demodulator BBS Bulletin Board System (TELEFÓNNA SIEŤ)
WAN - WIDE AREA NETWORK. {SAGE-RADARY US AIR FORCE, ARPANET IP adresy}
LAN - Local Area Network (Novell, Token Ring, Ethernet, MESH)

HVIEZDA

 ![ETHERNET TOPOLOGY ](LAN.png)
 
TOOLBOX:

# OPEN SYSTEM INTERCONECTION MODEL (OSI)
#osi
### 1. FYZICKÁ VRSTVA
Káble podľa tienenie

| Typ   | Stínenie                         | Maximálna rýchlosť  | Typické použitie                       | Poznámky                                |
| ----- | -------------------------------- | ------------------- | -------------------------------------- | --------------------------------------- |
| UTP   | Nestínené krútené páry           | Závisí od kategórie | Všeobecné siete, domáce/kancelárske    | Bez stínenia; náchylné na rušenie.      |
| STP   | Stínené medenou opletenou sieťou | Závisí od kategórie | Priemyselné prostredia, vysoké rušenie | Lepšia odolnosť voči rušeniu ako UTP.   |
| FTP   | Stínené fóliou                   | Závisí od kategórie | Kancelárske prostredia, stredné EMI    | Fólia obaluje všetky páry.              |
| S/FTP | Kombinácia STP a FTP stínenia    | Závisí od kategórie | Dátové centrá, vysoké EMI              | Najlepšie stínenie; najvyššia odolnosť. |
Káble podľa rýchlosti:

| Kategória | Maximálna rýchlosť | Maximálna šírka pásma | Typické použitie                   | Poznámky                                       |
| --------- | ------------------ | --------------------- | ---------------------------------- | ---------------------------------------------- |
| CAT5      | 100 Mbps           | 100 MHz               | Staršie siete, telefónne línie     | Zastarané pre moderné siete                    |
| CAT5e     | 1 Gbps             | 100 MHz               | Domáce/kancelárske siete, Gigabit  | Najčastejšie používané pre bežné použitie      |
| CAT6      | 1 Gbps             | 250 MHz               | Gigabit Ethernet, dátové centrá    | Znížené preslechy; vhodné pre vysoké rýchlosti |
| CAT6a     | 10 Gbps            | 500 MHz               | 10G Ethernet, podnikové siete      | Podporuje 10G do 100m                          |
| CAT8      | 40 Gbps            | 2000 MHz              | Dátové centrá, vysokovýkonné siete | Podporuje 25G/40G do 30m; vyžaduje stínenie    |


- **Stínenie**: Kábel **S/FTP** ponúka najlepšiu ochranu pred elektromagnetickým rušením (EMI), čo ho robí ideálnym pre dátové centrá a priemyselné prostredia.
- **Rýchlosť**: Len kategórie **CAT6a** a **CAT8** podporujú rýchlosti nad 10G, ale **CAT8** je obmedzený na 30m kvôli vysokej frekvencii.
- **Kompatibilita**: **CAT5e** je najrozšírenejšie používaný pre domáce/kancelárske siete, zatiaľ čo **CAT6** a vyššie sú vhodné pre podnikové a vysokovýkonné aplikácie.

| Connector | Max Speed                           | Typical Use                                        | Notes                                                               |
| --------- | ----------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------- |
| **RJ45**  | 10 Mbps, 100 Mbps, 1 Gbps, 2.5 Gbps | Computers, routers, switches, home/office networks | Standard Ethernet connector for twisted pair cables.                |
| **SFP**   | 4.25 Gbps                           | Switches, routers                                  | Small Form-factor Pluggable; used for fiber and copper connections. |
| **SFP+**  | 10 Gbps                             | Switches, routers, data centers                    | Enhanced version of SFP; supports higher speeds.                    |
PoE - Power over Ethernet - Možnosť napájania zariadení priamo cez CAT kábel.


### **2. Spojovacia vrstva – Data Link Layer**

**Úloha:** Spojovacia vrstva (Data Link Layer) je **druhá vrstva OSI modelu** a zabezpečuje **spojenie, prenos a kontrolu chýb** medzi dvoma uzlami v sieti. Jej hlavnou úlohou je **premeniť surové fyzické spojenie na spoľahlivý komunikačný kanál** pre vyššie vrstvy. Táto vrstva pracuje s **rámcami (frames)**, ktoré obsahujú:

- **Adresy zdroja a cieľa** (MAC adresy).
- **Kontrolné súčty** (CRC) pre detekciu chýb.
- **Riadiace informácie** pre synchronizáciu a prenos dát.

---

#### **Hlavné funkcie:**

1. **Rámcovanie (Framing):**
    
    - Rozdelenie dát z **sieťovej vrstvy (3. vrstva)** na **rámce (frames)**.
    - Pridanie **hlavičky (header)** a **zápatia (trailer)** pre identifikáciu začiatku a konca rámca.
    - Príklad: Ethernetový rámec obsahuje **MAC adresy**, **dĺžku rámca**, a **CRC kontrolný súčet**.
2. **Prístup k médiu (Media Access Control - MAC):**
    - Riadenie prístupu k **fyzickému médiu** (napr. káblu alebo bezdrátovému kanálu).
    - Protokol **CSMA/CD** (Carrier Sense Multiple Access with Collision Detection) sa používa v **Ethernete** pre detekciu kolízií.
    - Protokol **CSMA/CA** (Collision Avoidance) sa používa v **Wi-Fi** sieťach.
3. **Detekcia a korekcia chýb:**
    - Použitie **CRC (Cyclic Redundancy Check)** pre detekciu poškodených rámcov.
    - Opakované odosielanie poškodených rámcov (v prípade potvrdenia chyby).
4. **Logické spojenie (Logical Link Control - LLC):**
    - Zabezpečuje **multiplexovanie** (viacero protokolov na jednej fyzickej línii).
    - Riadi **prúdenie dát (flow control)** medzi odosielateľom a príjemcom.

---

#### **Protokoly a zariadenia:**

| Protokol/Zariadenie | Popis                                                                                           | Použitie                            |
| ------------------- | ----------------------------------------------------------------------------------------------- | ----------------------------------- |
| Ethernet            | Najrozšírenejší protokol pre drôtové siete; používa **MAC adresy** pre identifikáciu zariadení. | LAN, domáce/korporátne siete        |
| PPP                 | Protokol pre priame spojenie medzi dvoma uzlami (napr. cez telefónnu linku).                    | Dial-up, WAN spojenia               |
| Switch              | Zariadenie, ktoré **filtruje a smeruje rámce** na základe MAC adries.                           | LAN, zvyšovanie výkonu siete        |
| Bridge              | Spojuje dve alebo viac LAN segmentov a **filtruje rámce** medzi nimi.                           | Segmentácia siete, zníženie kolízií |


#### **Príklad rámca (Ethernet Frame):**

| Preamble (7B) | SFD (1B) | Destination MAC (6B) | Source MAC (6B) | Type (2B) | Data (46-1500B) | CRC (4B) |

- **Preamble a SFD:** Synchronizácia príjemcu.
- **Destination/Source MAC:** Adresy odosielateľa a príjemcu.
- **Type:** Určuje, aký protokol je zapuzdrený (napr. IPv4, IPv6).
- **CRC:** Kontrolný súčet pre detekciu chýb.

---

#### **Dôležité pojmy:**

- **MAC adresa:** Unikátny 48-bitový identifikátor sieťového zariadenia (napr. `00:1A:2B:3C:4D:5E`).
- **Broadcast:** Rámec odoslaný na **všetky zariadenia** v sieti (MAC `FF:FF:FF:FF:FF:FF`).
- **Unicast:** Rámec odoslaný **jednému špecifickému zariadeniu**.
- **Multicast:** Rámec odoslaný **skupine zariadení**.

ARP protokol  asociuje fyzicku MAC adresu s IP adresou. Tymto prikazom ukazeme vsetky MAC adresy, ktore pocitac pozna.
``` bash
arp -a
```

```powershell
arp -a 
```

### 2.1 VLAN na Layer 2

**VLAN (Virtual Local Area Network)** je technológia, ktorá umožňuje **logické rozdelenie fyzickej siete** na viacero **izolovaných virtuálnych sieti** na úrovni **Data Link Layer (2. vrstva OSI modelu)**. VLAN-y zlepšujú **bezpečnosť, výkon a správu siete** bez potreby fyzického rozdelenia zariadení.

---

#### **2.1.1 Základný princíp VLAN**

- **Fyzická sieť → Logické segmenty**: Jedno fyzické sieťové zariadenie (napr. **switch**) môže hostiť viacero VLAN-ov, ktoré sú od sebe **izolované** a komunikujú len v rámci svojho segmentu.
- **Komunikácia medzi VLAN-mi**: Ak chcú zariadenia z rôznych VLAN-ov komunikovať, potrebujú **router** alebo **Layer 3 switch** (ktorý vie smerovať medzi VLAN-mi).

---

####  **2.1.2 Ako VLAN funguje na Layer 2?**

VLAN funguje na **2. vrstve (Data Link Layer)** pomocou **tagovania rámcov**. Konkrétne sa používa štandard **IEEE 802.1Q**, ktorý pridáva do Ethernetového rámca **4-bajtový tag** s informáciou o príslušnosti k VLAN-u.

#### **Štruktúra rámca s VLAN tagom (802.1Q):**

 Copy

`| Preamble | SFD | Dest. MAC | Source MAC | 802.1Q Tag | Type/Length | Data | CRC |`

*SFD je Start Frame Delimiter


### 3. SIETOVA VRSTVA. - NETWORK LAYER

PACKETY 

> [! warning]
> TOOLBOX: WIRESHARK A PROMISC MODE!
> 

```bash
sudo ifconfig eth0 promisc
```

#### IP Internet Protocol ADRESY IPv4 a IPv6, IPSec

max 255.255.255.255 32bit dokopy 4.3 miliardy adries teoreticky
mnozstvo adries je rezervovana pre privatne siete a multicast

max ffff.ffff.ffff.ffff.ffff.ffff.ffff.ffff d 128bit dokopy **340,282,366,920,938,463,463,374,607,431,768,211,456 adries**

``` bash
ping 8.8.8.8
traceroute 8.8.8.8
netstat -a
```

ICMP - Internet Control Message Protocol {UNICAST}
IGMP - Internet Group Management Protocol  {host sa prihlasuje do MULTICAST}


> [! info]
> IPSEC tunel medzi dvoma routrami vsetko zasifrovane
> IPSEC transport obsah zasifrovany ale hlavicka NIE

>[!warning]
>POCITAC MOZE MAT AJ INTERNE IP ADRESY, ktore umoznuju aplikaciam poskytovat info napr cez browser ako keby boli na sieti http://localhost alebo
>http://127.0.0.1


ROUTER smerovac balickov  LAN<>WAN (pocitac)
DHCP - Lizingovka pre IP adresy (DHCP je bezpecnejsie ako static)
Maska siete = 255.255.255.0
GATEWAY = IP adresa routera


### **NAT (Network Address Translation) na 3. vrstve (Network Layer)**

NAT (preklad sieťových adries) je technológia **3. vrstvy (sieťová vrstva)**, ktorá umožňuje **viacerým zariadeniam v lokálnej sieti** zdieľať **jednu verejnú IP adresu** pri komunikácii s internetom. Hlavným dôvodom jeho použitia je **úspora verejných IPv4 adries**, keďže lokálne zariadenia používajú **súkromné IP adresy** (napr. `192.168.x.x`, `10.x.x.x`), ktoré nie sú prístupné z internetu. NAT tiež zvyšuje **bezpečnosť**, pretože skrýva vnútornú štruktúru siete pred vonkajším svetom.

Pri odosielaní dát z lokálnej siete na internet **NAT router** nahradí **zdrojovú IP adresu** v pakete z **súkromnej** (napr. `192.168.1.10`) na **verejnú** (napr. `203.0.113.5`). Zároveň priradí jedinečný **portový číslo** pre sledovanie spojenia, čo umožňuje správne vrátiť odpoveď späť k pôvodnému zariadeniu. Pri príjatí odpovede z internetu NAT router **preloží verejnú IP a port späť na súkromnú IP** a odovzdá paket správnemu zariadeniu v lokálnej sieti. Týmto spôsobom NAT zabezpečuje, že viacero zariadení môže súčasne komunikovať cez jednu verejnú IP adresu.


Staticka verejna IP vs. lokalna neverejna IP

### 4.TRANSPORTNA VRSTVA
SPOJENIA MEDZI IP ADRESAMI

#### 4.1 TCP - Autorizacia, Handshake SYN ACK FIN RST PSH
Na pochopenie TCP protokolu si uvedieme príklad kde sa dvaja ľudia stretnú na ulici:

1. Pozdravia sa a ak sa nepoznajú predstavia sa navzájom. 
2. Potrasú si rukami HANDSHAKE (SYN, SYN-ACK, ACK)
3. Komunikujú slovne (packety)
4. Ukončia komunikáciu, (FIN, ACK-FIN, ACK)
5. Rozlúčia sa a idú každý svojou cestou

Ak sa nechcú baviť RST. 

#### 4.2 UDP - Neautorizovany stream DAT medzi IP

Na pochopenie UDP môžeme použiť príklad keď sa dvaja ľudia pokúšajú na diaľku komunikovať kričaním. Ak by im záležalo na 100 percentnej komunikácií tak by k sebe prišli a podali by si ruky a komunikovali TCP. Ale to sa im nechce. 

Používa sa to napríklad v hrách alebo pri prenose videa. Ak sa nejaký ten obrázok stratí tak nevadí, komunikácia nie je prerušená a dáta idú ďalej. 


#### 4.3 Firewall - Ohnova stena s prisnymi pravidlami (RULES)

>[!warning] TOOLBOX>KALI LINUX : iptables - standardny FIrewall LINUX

```bash

sudo iptables -L 


sudo iptables-save > RULES
cat RULES

sudo iptables -P OUTPUT DROP  # DROPUJE vsetky packety na vystupe
sudo iptables -P INPUT DROP  # DROPUJE vsetky packety na vstupe
sudo iptables -P FORWARD DROP  # DROPUJE vsetky packety forwardovane zo siete (routre a fw)

sudo iptables -A INPUT -s 192.168.1.100 -j DROP  # Dropuje vsetko z IP adresy
sudo iptables -A OUTPUT -p tcp -d fortisauris.com -j ACCEPT

sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT

sudo iptables -F   # FLUSH ALL RULES

```

ufw

>[!warning] TOOLBOX>KALI LINUX : ufw - nekomplikovana nadstavba pre iptables 

```bash
sudo service ufw status  # old school
sudo systemctl status ufw  # po novom
sudo ufw enable

sudo ufw deny OUT 22
sudo ufw deny IN 22

sudo ufw status verbose  # zobrazi RULES

sudo ufw reset

```



``` powershell
Import-Module -Name 'NetSecurity'

Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action -First 10
```

``` powershell
$Params = @{ "DisplayName" = 'Block WINS' "Direction" = 'Inbound' "Action" = 'Block' "RemoteAddress" = 'WINS' }

New-NetFirewallRule @Params

New-NetFirewallRule -DisplayName "OUT SSH Port 22" -Direction Outbound -LocalPort 22 -Protocol TCP -Action Block
```

**WINS (Windows Internet Name Service)** is a **legacy Microsoft protocol** používaný **NetBIOS na rozlišovanie mien vo Windows networks. Bol navrhnutý na rozlišovanie mien  NetBIOS a ich dynamické priradenie k IP adresám, podobne ako DNS. 

```powershell

Set-NetFirewallRule -DisplayName 'OUT SSH' -Action Allow
Remove-NetFirewallRule -DisplayName "OUT SSH"
```

INE METODY: Disable, Enable, Rename, Show, Copy

```powershell
Get-NetFirewallProfile
Get-NetFirewallSetting
```
INE METODY: Set


Vsetky balicky co nesplnia podmienky zhoria na Ohnivej stene.
DPI Deep Packet Inspection. WAN a LAN

**Deep Packet Inspection (DPI)** je **pokročilá technika analýzy a filtrovania sieťovej prevádzky**, ktorá neprezerá len hlavičky paketov (ako klasické firewally), ale **preniká až do obsahu samotných dát** (payload) a analyzuje ich obsah v reálnom čase. DPI sa používa na **identifikáciu, klasifikáciu, blokovanie, alebo priorizáciu** sieťovej prevádzky na základe konkrétnych pravidiel, aplikácií, alebo obsahu.


4.5. ČÍSLA SEKVENCIE 
Aby sme PACKETY vedeli pospájať sú im pridelené poradové čísla sekvencie. Takýmto spôsobom vie počítač zložiť posielané dáta do ich pôvodnej formy. Napr. obrázku alebo dokumentu.

### 5. SESSION LAYER - 

**Session Layer (5. vrstva OSI modelu)** zabezpečuje **vytváranie, udržiavanie a ukončovanie komunikácie** medzi dvoma aplikáciami alebo procesmi v sieti. Jej hlavnou úlohou je **koordinovať a synchronizovať dialóg** medzi aplikáciami, čo umožňuje **spravovať a obnovovať spojenia** v prípade prerušenia (napr. pri výpadku siete). Táto vrstva tiež poskytuje služby pre **autentifikáciu, autorizáciu a šifrovanie** (napr. pomocou protokolov ako **NetBIOS, RPC, SIP, PPTP** alebo **TLS/SSL** v kombinácii s vyššími vrstvami). V praxi sa stará o to, aby komunikácia medzi aplikáciami prebiehala **spoľahlivo a bezpečne**, napríklad pri prenosoch súborov, videokonferenciách alebo prihlásení sa do sieťových služieb. Bez nej by aplikácie nemohli udržiavať dlhodobé a stabilné spojenia.

X.225 alebo ISO 8327 

PROTOKOLY, KTORE VYUZIVAJU TUTO VRSTVU:

<li>RPC Remote Procedure Call</li>
<li>SQL Structured Query Languague</li>
<li>SOCKS Proxy</li>
<li>SCP Session Control Protocol</li>
<li>RTPC Realtime Transport Control Protocol</li>
<li>PPTP Point2Point Tunelling Protocol</li>
<li>NetBIOS </li>
<li>L2TP Layer2 Tunelling Protocol</li>
<li>Apple Talk Session and Data STream Protocols</li>


#### 5.1 CO JE SESSION. Application Programm Interface
synchronizacne sluzby a posielanie na sockety  IP plus PORT plus PROTOCOL
Komunikacia s API alebo sietovym portom

#### 5.2 SIETOVE PORTY

SIETOVE PORTY POCITACA. 
Spolu 65535 portov. Kazdy z nich moze prijimat a posielat packety s informaciami.
<ul>
<li>ftp = port 20 & 21</li>
<li>ssh = port 22</li>
<li>telnet = port 23</li>
<li>smtp = port 25</li>
<li>dns = port 53</li>
<li>http = port 80</li>
<li>pop3 = port 110 & 995 s SSL/TLS</li>
<li>imap = port 143 & 993 s SSL/TLS</li>
<li>https = port 443</li>
</ul>

### 6. PREZENTACNA VRSTVA
### **6. Prezentačná vrstva (Presentation Layer)**

Prezentačná vrstva je **šiestou vrstvou OSI modelu** a zabezpečuje **formátovanie, šifrovanie a kompresiu dát** pred ich odoslaním na **aplikačnú vrstvu (7. vrstva)** alebo pred ich predaním na **relačnú vrstvu (5. vrstva)**. Jej hlavnou úlohou je **zabezpečiť, aby dáta boli pre príjemcu číateľné a použiteľné**, bez ohľadu na to, aký typ zariadenia alebo operačného systému používa. Táto vrstva sa stará o **konverziu dátových formátov** (napr. medzi rôznymi kódovaniami textu, obrázkov alebo videí), čo umožňuje komunikáciu medzi rôznymi systémami. Okrem toho tu prebieha aj **šifrovanie dát**, čo je kľúčové pre zabezpečenú komunikáciu.

---

Jedným z najdôležitejších protokolov na tejto vrstve je **SSL (Secure Sockets Layer)** a jeho nástupca **TLS (Transport Layer Security)**. Tieto protokoly zabezpečujú **šifrovanie komunikácie** medzi klientom a serverom pomocou **kryptografických kľúčov a certifikátov**. SSL/TLS sa používa napríklad pri **HTTPS** spojeniach, kde zabezpečuje, že dáta odoslané medzi prehliadačom a webovým serverom sú chránené pred odpočúvaním alebo manipuláciou. Certifikáty, ktoré sú vydávané **dôveryhodnými certifikačnými autoritami (CA)**, overujú identitu servera a zabezpečujú, že komunikácia prebieha s očekávaným partnerom, nie s podvodným serverom.

---

Ďalším dôležitým protokolom na prezentačnej vrstve je **SSH (Secure Shell)**, ktorý umožňuje **bezpečný vzdialený prístup** k príkazovému riadku (shell) na vzdialenom počítači. SSH šifruje celú komunikáciu medzi klientom a serverom, čo zabezpečuje, že heslá, príkazy a ďalšie citlivé dáta nie sú vystavené útokom. SSH sa často používa pre **správu serverov**, bezpečný prenos súborov (napr. cez **SCP** alebo **SFTP**) a vytváranie **bezpečných tunelov** pre sieťovú komunikáciu. Na rozdiel od starších protokolov ako **Telnet**, ktorý odosielal dáta v nezašifrovanej podobe, SSH poskytuje **silné šifrovanie** a autentizáciu, čo ho robí nepostrádateľným pre správu vzdialených systémov.


#### 6.1 SSH - SECURE SHELL {BEZPEČNÝ SHELL}

Na cielovom pocitaci musi bezat ssh server. Oblubené su OpenSSH a Dropbear.

>[!info]
>Vacsina serverov bezi 24/7 v tzv. HEADLESS mode. Je mozne sa k nim pripojit lokalne cez KVM konzolu, alebo na dialku pomocou ssh.



```bash
ssh user@ip
```

pri prvom nadviazani spojenia si pocitace vymenia kryptografické kľúče a dohodnú sa na sifrovani. Tento kluc sa ukladá do suboru:

```bash
.ssh\known_hosts
```

Standardne pozaduje zadanie hesla uzivatela.

>[!warning] !!! POZOR 
>prihlasovať sa cez ssh ako root je nebezpecné !

SSH vieme nastavit aby miesto hesla akceptoval dvojicu ktyprografickych klucov.
privatny na strane klienta   a verejny na strane serveru

```bash

ssh-keygen
ssh-copy-id username@host_ip
ssh username@host_ip

```

Na strane servera mozeme vypnut Autentifikaciu pomocu hesla v subore [/etc/ssh/sshd_config] pridame alebo zmenime riadok:

```sshd_config
PasswordAuthentication no
```

Teraz sa mozeme pripajat bez pouzitia hesla za pouzitia kryptografickeho verejneho kluca. 
>[!info] 
>KRYPTOGRAFIU BUDEME PREBERAT V TOMTO KURZE V DALSICH LEKCIACH :)


---

Na prezentačnej vrstve sa tiež nachádzajú protokoly zabezpečujúce **prístup k e-mailom**, ako je napríklad **IMAP (Internet Message Access Protocol)**. IMAP umožňuje klientom (napr. e-mailovým aplikáciám) **čítať a spravovať e-maily** priamo na serveri, bez potreby ich sťahovať. Na rozdiel od protokolu **POP3**, ktorý e-maily sťahuje a odstraňuje zo servera, IMAP synchronizuje stav e-mailovej schránky medzi serverom a klientom, čo je výhodné pre používanie viacerých zariadení. Pre zabezpečenú komunikáciu sa často používa **IMAPS** (IMAP Secure), čo je IMAP kombinovaný so šifrovaním pomocou SSL/TLS. Táto vrstva tak hrá kľúčovú úlohu v **zabezpečenej a efektívnej komunikácii** medzi rôznymi systémami a aplikáciami.

### 7. APLIKAČNÁ VRSTVA
Sietova vrstva pomocou ktorej ma interakciu so sietovou prevadzkou prostrednictvom aplikacii ktore vyuzivaju priamo obsah balickov

#### 7.1 LEGACY PROTOKOLY  !!!

HTTP - HYPER TEXT TRANSFER PROTOCOL {}
FTP - FILE TRANSFER PROTOCOL {STAHOVANIE A UPLOAD SUBOROV NA REMOTE}
TELNET {SHELL}

>[!warning]
>FTP a TELNET nemaju sifrovanie a preto komunikacia cez nich tecie v packetoch v otvorenej reci. NEPOUZIVAT !!! 
>HTTP je internetovy protokol na komunikaciu s webserverom bez sifrovania. Pripajanie sa k strankam bez sifrovania nepovazujeme za BEZPECNE !!! 

#### 7.2 IRC - INTERNET RELAY PROTOCOL {CHAT}
Oblubeny sposob chatovania pomocou lokalne alebo verejne umiestneneho servera IRC

#### 7.3 SFTP - SECURE FILE TRANSFER PROTOCOL {SIFROVANY PRENOS SUBOROV}

sftp vyuziva sluzby ssh serveru. Umoznuju stahovat subory GET alebo posielat subory PUT na server kde bezi  ssh server.

``` powershell
sftp username@host_ip
help
```

SFTP nam umoznuje prezerat subory na LOKALNOM pocitaci pomocou !dir aj na REMOTE pomocou dir. 

``` powershell
get SUBOR KAM # stiahne SUBOR zo SERVERU 
put subor KAM # posle SUBOR z LOKALNEHO POCITACA NA SERVER
```

SFTP nám umožňuje manipulovať so súbormi a adresármi na oboch koncoch TCP spojenia. Vymazávať, presúvať, vytvárať adresáre a pod.

SCP Secure Copy tiez vyuziva SSH server na kopirovanie suborov a adresarov.

``` bash
scp SUBOR username@hostname:KAM
```

>[!info]
>Alternativa SCP funguje aj v Powershell avsak nepouziva SSH ale HTTPS na to potrebuje mat Certifikaty a kluce cieloveho servera. 



#### 7.4 DNS - DOMAIN NAME SERVER {ZLATE STRANKY IP ADRIES}

DNS je zjednodusene povedane telefonny zoznam. Ak do browseru alebo hocikam kde mozno vlozit adresu URL napr: [https:\\fortisauris.com](https:\\fortisauris.com)
Pocitac skontroluje v DNS zaznamoch mena domen a presmeruje spojenie na IP adresu, ktoru si tak nemusime pamatat. 

A RECORD - SMEROVANIE DOMENY NA VEREJNU STATICKU IP ADRESU
CNAME - SMEROVANIE WEB HOSTINGU NA DOMENU
MX - SMEROVANIE DOMENY NA MAILOVY SERVER

#### 7.5 DNS SEC

>[!warning] DNSEC je bezpecnejsia verzia DNS, ktora zabezpecuje, ze nebude Vas pocitac presmerovany na inu 'FALOSNU' domenu ci IP adresu. 


**DNSSEC (Domain Name System Security Extensions)** je rozšírenie protokolu DNS, ktoré pridáva **kryptografickú ochranu** pre overenie autenticity a integrity dát v systéme doménových mien. Jeho hlavným cieľom je **zabrániť útokom**, ako sú napríklad _DNS spoofing_ (podvrhnutie DNS odpovedí) alebo _man-in-the-middle_ útoky, ktoré by mohli presmerovať používateľov na podvodné weby. DNSSEC používa **digitálne podpisy** a **verejnú kryptografiu** na overenie, že DNS odpoveď pochádza skutočne od oprávneného servera a nebola počas prenosu zmenená. Týmto spôsobom zabezpečuje, že používateľ navštíví skutočnú webovú stránku alebo službu, ktorú hľadá, a nie jej podvrhnutú verziu.

---

DNSSEC funguje na princípe **reťazca dôvery** (_chain of trust_), kde každá doména je overená prostredníctvom **digitálneho podpisu** od nadradenej domény, až k **koreňovým DNS serverom**. Keď klient požiada o DNS záznam, server vráti ne len samotnú IP adresu, ale aj **kryptografický podpis**, ktorý overuje jeho pravosť. Klient (napr. operačný systém alebo DNS rezolver) následne overí tento podpis pomocou **verejného kľúča** uloženého v nadradenej doméne. Ak je podpis platný, DNS odpoveď je považovaná za dôveryhodnú. DNSSEC však **nešifruje** komunikáciu (na to slúži napr. **DNS over TLS** alebo **DNS over HTTPS**), ale iby zabezpečuje, že dáta neboli zmenené alebo podvrhnuté. Jeho implementácia je dôležitá pre zabezpečenie kritickej infraštruktúry internetu, ako sú bankové služby, vládne portály alebo e-mailové servery.
#### 7.6 HTTPS - HYPERTEXT TRANSFER PROTOCOL SECURE

Preferovaný štandard pre pripájanie sa k webovým stránkam a API zabezpečene:
1. Server a klient si vymenia verejné šifrovacie kľúče.
2. Platné certifikáty potvrdia, že sa jedná o pravé kľúče.
3. Server s klientom sa dohodnú na šifrovaní.
4. ODTERAZ je obsah packetov zašifrovaný SSL \ TLS(TRANSPORT LAYER SECURITY)

>[!warning]
>VIZUÁLNA KONTROLA V BROWSERI = 
><li>NAĽAVO OD ADRESY SVIETI ZAMKNUTÁ VISIACA ZÁMKA.</li>
><li>SKONTROLUJ PLATNOST CERTIFIKATU</li>
><li>!!! POZOR !!! OKREM PLATNOSTI SKONTROLUJ CI CERTIFIKAT BOL VYDANY NA CIELOVU DOMENU   go.ogle.com NIE JE google.com !!!</li>

#### 7.6.1 MAN IN THE MIDDLE ATTACK
MITM - MAN IN THE MIDDLE - Utok hackerov kde podstrcia obeti svoj certifikat a kluc cim sa dostanu k nezasifrovanemu obsahu sifrovaneho spojenia. Obet ani cielovy SERVER povazuju komunikaciu za zabezpecenu. Jedina vec co nesedi je, ze CERTIFIKAT je vydany na inu domenu. 


 ![MAN IN THE MIDDLE ATTACK ](MITM.png)


### 7.6.0 KOMUNIKÁCIA POMOCOU HTTP REQUESTOV

HTTP a HTTPS komunikujú so serverom pomocou tzv. REQUESTOV tzv požiadaviek. Pochopenie tohoto konceptu je aj pochopenie moderneho Internetu.

##### 7.6.1. GET request

Najčastejšia požiadavka je GET request, ziskaj obsah stranky. 

Na posielanie requestov použijeme program curl , ktorý dokáže komunikovať s mnohými protokolmi. Možnosti sú až desivé.
``` bash
curl https:\\fortisauris.online
curl https://httpbin.org/get
curl -v -H "User-Agent: MyDemoAgent" https://httpbin.org/get
curl "https://httpbin.org/get?param1=value1&param2=value2"


curl -X POST https://fortisauris.com -d "param1=value1&param2=value2"

curl -X PUT https://fortisauris.com/resource/1 -d "param1=value1&param2=value2"

curl -X DELETE https://example.com/resource/1

```
Ak server náš request vybavil vráti sa OK kód 200 a požadovaný obsah zo serveru, ktorý možno zobraziť v browseri alebo kde treba : )

``` powershell
Invoke-WebRequest -Uri "https://httpbin.org/get"
Invoke-RestMethod -Uri "https://httpbin.org/get" | Format-List

```

Odpoveď obsahuje HEADERS a CONTENT v HTML alebo inom formate.

Ak náš request smeruje na neexistujúcu url adresu vráti sa FILE NOT FOUND a  kód 404. To znamená, že požadovaná stránka alebo súbor neexistuje.

##### 7.6.2 POST request

HTTP protokol nám umožňuje informácie nielen sťahovať zo serveru ale aj posielať informácie na server prostredníctvom POST requestu. Týmto spôsobom sa môžeme logovať, vypĺňať všakovaké formuláre, feedbacky, vkladať informácie do databáz, chatovať, blogovať, reagovať a pod.
```bash
curl -X POST https://httpbin.org/post -d "key1=value1&key2=value2"
curl -X POST -H "Content-Type: application/json" -d '{"key1":"value1", "key2":"value2"}' https://httpbin.org/post
#hhtpie
http POST https://httpbin.org/post Content-Type:application/json key1=value1 key2=value2

http POST https://httpbin.org/post Content-Type:application/json key1=value1 key2=value2

```

``` powershell
$formData = @{
    "key1" = "value1"
    "key2" = "value2"
}
Invoke-WebRequest -Uri "https://httpbin.org/post" -Method Post -Body $formData


$jsonData = @{
    "key1" = "value1"
    "key2" = "value2"
} | ConvertTo-Json
Invoke-RestMethod -Uri "https://httpbin.org/post" -Method Post -Body $jsonData -ContentType "application/json"

```

https://httpie.io/app
##### 7.6.3 INE requesty
Okrem týchto dvoch najčastejších requestov HTTP a HTTPS poznajú aj PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT a TRACE

* ***API (Application Programming Interface)** je všeobecný pojem pre **rozhranie**, ktoré umožňuje komunikáciu medzi dvoma softvérovými systémami (napr. medzi aplikáciou a serverom), pričom definuje **spôsob, ako sa dajú žiadať a vraciať dáta** (napr. pomocou funkcií, protokolov alebo špeciálnych požiadaviek). **REST API (Representational State Transfer API)** je konkrétny **typ API**, ktorý používa **štandtardizované HTTP protokoly** (napr. `GET`, `POST`, `PUT`, `DELETE`) a **státeless** (bez uchovávania stavu) komunikáciu, kde každá požiadavka obsahuje všetky potrebné informácie. Na rozdiel od ostatných API (napr. SOAP, GraphQL), REST API používá **jednotné URL adresy (endpoints)** pre prístup k zdrojom (napr. `/users` pre zoznam používateľov) a vracia dáta vo formátoch ako **JSON** alebo **XML**. REST API je obľúbené pre svoju **jednoduchosť, škálovateľnosť a univerzálnosť**, čo ho robí ideálnym pre webové služby a mobilné aplikácie.
##### 7.6.4 JEDNODUCHA AUTENTIFIKACIA

``` bash & powershell
# meno a heslo
curl -u username:password https://httpbin.org/basic-auth/user/passwd


# bearer token
curl -H "Authorization: Bearer YOUR_TOKEN" https://httpbin.org/bearer

```

**Autorizácia pomocou Bearer Tokenu** je mechanizmus, ktorý umožňuje **overenie identity klienta** pri prístupe k chráneným zdrojom (napr. API endpointom) bez nutnosti posielania prihlasovacích údajov (ako mená a heslá) pri každej požiadavke. Po úspešnom prihlásení (napr. pomocou užívateľského mena a hesla) server vygeneruje **unikatný token** (reťazec znakov), ktorý klient následne pridáva do **hlavičky HTTP požiadavky** v tvare `Authorization: Bearer <token>`. Server tento token overí a ak je platný, povolí prístup k požadovanému zdroju. Bearer Tokeny sú bežne používané v **REST API**, pretože sú **státeless** (nesúvisia s konkrétnou reláciou na serveri) a umožňujú **bezpečnú a efektívnu autorizáciu** bez nutnosti opakovane zadávať prihlasovacie údaje. Typicky majú **obmedzenú platnosť** (expiráciu) a môžu byť **zrušené** (revoked) v prípade kompromitácie. Príkladom ich použitia sú **OAuth 2.0** a **JWT (JSON Web Tokens)**.

>[!warning]
>CSRF (Cross-Site Request Forgery) je útok, pri ktorom útočník prinúti užívateľa, aby nevedomky vykonal neželanú akciu na webovej stránke, na ktorú je prihlásený. Útočník využije dôveryhodnosť, ktorú má prehliadač voči cieľovej stránke, a pošle škodlivú požiadavku s platnými autentifikačnými údajmi obete. Tento útok môže spôsobiť napríklad neúmyselný prevod peňazí alebo zmenu údajov bez vedomia obete.

``` html
<a href="https://bank.com/transfer?amount=1000&to=attacker">Click here for a free gift!</a>

```



#### 7.7 SMB Server Message Block protokol

Protokol, ktorý nám umožňuje zdieľať rôzene zariadenia na sieti ako disky, tlaciarne a pod. 

7.7.1 Install SAMBA server


NA STRANE LINUXOVEHO SERVERA
``` bash
sudo apt-get update
sudo apt-get install samba

sudo nano /etc/samba/samba.conf

sudo smbpasswd -a user

sudo service smdb restart
```

NA STRANE LINUXOVEHO KLIENTA:

```bash
smbclient -U user //host_ip/user
smbclient -U user%heslo //host_ip/user

```

``` samba
get file

recurse ON
mget *
```

```powershell
Get-SmbShare

New-SmbMapping -RemotePath '\\server\share' -Username '\domain\username' -Password 'heslo'

New-PSDrive -Name 'X' -PSProvider 'Filesystem' -Root '\\server\share' -Credential () #



```


### 8. ZAKLADNA SEGMENTACIA SIETE
 ![[LANwDMZ.png]]
8.1 Chránená LAN - interná sieť s daným stupňom ochrany
Intranet, databazove servery, pocitace obsahujuce citlive data.

8.2 Guest Network - 

8.3 DMZ - demilitarizovana zona - miesto kde su umiestnene servery volne pristupne z internetu


 #### POKRACUJEME
 [[SESSION3_NETWORK_DEVICES_VPN_WIFI]]