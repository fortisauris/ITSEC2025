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

``` linux
sudo fdisk -l
mkdir USB_KLUC
mount /dev/sd?1 /USB_KLUC
umount USB_KLUC
```



# SIETE A VZNIK A TOPOGRAFIA SIETE

MODEM - Modulator-Demodulator BBS Bulletin Board System (TELEFÓNNA SIEŤ)
WAN - WIDE AREA NETWORK. {SAGE-RADARY US AIR FORCE, ARPANET IP adresy}
LAN - Local Area Network (Novell, Token Ring, Ethernet, MESH)

HVIEZDA

 ![ETHERNET TOPOLOGY ](LAN.png)
 
TOOLBOX:

# OPEN SYSTEM INTERCONECTION MODEL (OSI)

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
