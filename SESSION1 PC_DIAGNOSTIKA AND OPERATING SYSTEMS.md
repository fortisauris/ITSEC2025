

#itsec #hardware


## PREDSTAVENIE: 

FORTIS AURIS o.z.

	Fortis auris je občianske združenie, ktoré sa zameriava na vzdelávanie detí a dospelých v oblasti IT a hackingu, s dôrazom na etiku, slobodu a anonymitu. Na webe ponúkame kurzy a priestor pre projekty a rôzne spôsoby participácie.

	Našim hlavným cieľom je vychovať novú generáciu hackerov s úctou k ľudským právam a životu. Naše aktivity zahŕňajú aj verejnú komunikáciu cez GitHub, kde zdieľame vzdelávacie materiály a projekty. 

### Princípy kurzu:

Tento kurz vychádza z prípravných materiálov na certifikácie CompTIA A+, COmpTIA Networking, CompTIA Security a +casto sa budeme odvolávať tiež na ISO27001 

1. Raz skúsiť je viacej ako 5 krát vidieť.
2. Rozne aspekty IT SEC (Developer, Admin, IncidentResponder, Hacker)
3. PC, Sieť, IoT a Incident Response
4. SERVERY A ENDPOINTY
5. Prikazovy riadok > program s GUI

### Preco by ste sa mali stat WhiteHat Hackermi

1. Hackeri hladaju a odhaluju bezpecnostne diery - zvedavost
2. Hackeri povazuju vsetko za hacknutelne - kriticke myslenie
3. Hackeri dbaju na bezpecnost a anonymitu -

>[!info]
>Open Source, Open Hardware  a Open Education - LINUX
>1. Vznikol 25.augusta 1988 a jeho autor je Linus Torvalds
>2. Škálovateľnosť a robustnosť
>3. Administracia a CENA :0

## POTREBY KURZU

A. Notebook alebo počítač:

WINDOWS ALEBO LINUX (UPDATOVANÝ  WIN-X > SETTINGS > WINDOWS UPDATE )
AMD alebo Intel s podporou VTx
WSL, Docker alebo VM, Podman
8GB RAM
ZOOM CLIENT
Anglicka klavesnica
NIE BITLOCKER A SECURE BOOT


> [! warning]
> ZÁLOHUJTE SI VŠETKO CENNÉ Z POČÍTAČA:
> 1. ZÁLOHA NA 3 miesta : USB FLASHDISK, EXTERNÝ HDD a CLOUD
> 2. POČÍTAČU BUDEME ROBIŤ ZLE.
> 3. NASTAVOVAŤ A INŠTALOVAŤ, SKENOVAŤ
> 4. SKÚŠAŤ, SPÚŠŤAŤ A PROGRAMOVAŤ
> 5. HROZÍ RIZIKO  BSOD 




# 1. Digitálne technológie  na ktorých stojí PC:
#hardware

### 1.0.1 DIGITALNE DATA

1. Prvé počítače používali relé, ktoré sú neefektívne a energeticky náročné.   Fungujú na princípe dvoch okruhov, jeden slapší spína relé pomocou elektromagnetu.
2. Neskôr počítače začali používať vákuové elektrónky, ktoré sú okrem energetickej náročnosti aj nespoľahlivé.
3. Rozmach počítačov umožnila až masová výroba tranzistorov. Elektronických súčiastok, ktoré boli spoľahlivé a dokázali uchovať informáciu True alebo False teda 1 alebo 0 pomocou CMD pinu.


### 1.0.2 NÁRAST KOMPONENTOV V PROCESOROCH (CPU)
#hardware #cpu

1978 Intel 8086 mal 29000 trazistorov IBM PC

1993 Intel Pentium  3.3mil

2002 Intel Pentium 4 Northwood - 50mil 

2023 Intel i9-13900K  ma 25.9 miliard tranzistorov pri hustote 101mil na 1mm stvorcovy

2025 Apple M4 Ultra 184 miliard tranzistorov (POZOR INA ARCHITEKTURA)

Špičkové serverové CPU Epyx, Xeon prekrocili hranicu 50 miliard tranzistorov


> [!alert]
> AKÉ ARCHITEKTÚRY PROCESOROV POZNÁME ?


### 1.0.3 FREKVENCIA PROCESORA

Výkon procesora nám určuje aj frekvencia na akou dokáže vykonávať svoju prácu:

1978 Intel 8086 - max 4MHZ

2023 Intel Core i9-13900K  - max 6GHz

Tranzistor dokaze ukladat iba najmensiu digitalnu jednotku a to je 1 alebo 0 t.j. bit

>[!todo]
>SKUS NATLACIT CO NAJVIAC INFORMACII DO 8 BITOV
>

> [! warning]
> STATUS BYTE MALVERU
> 1. užívateľ sedí za počítačom True
> 2. PC má webkameru True
> 3. PC má aktívny browser False
> 4. PC je pripojené na Internet True
> 5. PC má nainštalovaný MS Office True
> 6. PC má nastavený Firewall False
> 7. PC je pripojené cez WiFI True
> 8. Je pracovny den

VÝSLEDOK je 219 t.j. 11011011 odoslaných z Vašeho počítača na iný počítač.

### 1.0.3  AKO PRACUJE PROCESOR

> [!alert]
> LOGICKE OPERACIE  -  
AND &
XOR ^
NOT ~ 
OR |
REGISTRE 64,32,16,8
CYKLY  - opakovanie instrukcii
LOGIKA  - podmienky a vetvenie naseho programu

``` powershell
C:\Get-ComputerInfo
```

# 1.2 JADRÁ,  VLÁKNA A PROCESY
#cpu

#### 1.2.1 PROGRAMY NA PREZERANIE PROCESOV
Linux: 
``` bash
ps
ps aux
top
htop
```
WIN: Task Manager

WINDOWS:

>[!warning]
>PID je rodné číslo procesu, nájdete ho v Task Manageri v detailnom výpise. Ktorýkoľvek Task môžete ukončiť príkazom kill PID. POZOR aby to nebol nejaký process JADRA OS, lebo Vás čaká pád systému.

``` powershell

tasklist
# wmic process list full
Get-Process | Format-Table -AutoSize

Get-Process | Export-Csv -Path "C:\processes.csv" -NoTypeInformation




tasklist /m /fi 'pid eq PID'
tasklist /m

# wmic process where processid=PID get commandline
```


#### 1.2.2 BUDUCE PROCESY

Pri zisťovaní stavu počítača nás nezaujímajú len aktuálne bežiace procesy ale aj plánované procesy, ktoré sa sami spúšťajú podľa nastaveného harmonogramu: 

WINDOWS:
``` powershell
C:\schtasks.exe 
```



LINUX:
``` bash
crontab -l
```

Na niektorých Linux serveroch ešte beží Legacy príkaz at, ktorý umožňuje tiež spúšťať procesy v určitom čase. Nezabudnite si ho skontrolovať.


### 1.2 RAM Random Access Memory

#memory
>[!info]
> PRVE POCITACE NEMALI PAMAT - pouzivali dierovaciu pasku alebo štítky

BIT najmenšia jednotka pamäti teda 0 alebo 1.  True alebo False
BYTE minimálne 8bitov obsahuje hexadecimálnu hodnotu od 00 do FF   t.j. 0 do 255
8bitov potrebujeme na ulozenie ZNAKU alebo celeho cisla INTEGER od 0 do 255



Prvý komerčne predávaný chip:
Oct. 1970  Intel 1103 DRAM 1024 bitov

Súčasný stav:
moduly DDR5 pouziva 64Gbit chipy a max 48GB moduly




>[!info]
>#### INCIDENT RESPONDER
>Kopia pamati beziaceho pocitaca MEMDUMP


SYSTEM CONFIGURATION > Boot > Advanced Options



# 1.3 HDD SDD UKLADANIE DAT
#storage

### 1.3.1 HDD DISKY - platne magneticke az 10000 rpm 

> [!warning]
> !!! POZOR !!!
> Nachylne na otrasy a EMP

### 1.3.2 SSD, Flash a eMMc DISKY - chip
#stotage
> [!warning]
> !!! POZOR !!!
> EMP a obmedzena zivotnost



Ukladanie MBR Master Boot Record max4 partition, max 2.2TB
GPT - GUID az 128 partitions na win, ZB miliarda terabytov


TOOL: JEDNODUCHÁ Mazacka  v pythone ?? 

WIN : chkdsk /f 

LINUX:   fsck /dev/sdb  OR touch /forcefsck

PARTITION rovná sa SKLAD
SKLADOVÝ SOFTVÉR = rôzny spôsob ukldadania dát NTFS, AFS, FAT32, EXFAT, LX4, 

> [!info]
> ZFS Zettabyte File System
> Najnovsi FileSystem umoznujuci replikovanie  a snimkovanie (snapshot)


### 1.3.3 RAID diskové polia
RAID0 - kapacitne spojenie dvoch diskov 1+1 bez zvysenia pristupu a rychlosti
RAID1 - jeden data, druhy zrkadlo - dvojnasobna rychlost pristupu,  jeden nahraditeľný bez ohrozenia dát
RAID5 - dva data a jeden XOR  = trojnásobok rýchlosti a jeden nahraditeľný disk

RAID radiče serverov umožňujú výmenu poškodených diskov za chodu úložiska. Vložený čistý disk sa pomaly zosynchronizuje

> [!warning]
> RAID neslúži ako BACKUP


#### 1.3.4 SECURE BOOT
#endpoint
Nastavenie ze pocitac nastartuje iba z certifikovaneho bootovacie media ako WBM
Windows Boot Manager

confirm-SecureBootUEFI


#### UEFI Unified Extensible Firmware Interface nasledovnik BIOSu
UEFI (Unified Extensible Firmware Interface) is a firmware interface that is used to boot up a computer system. [It is the successor to BIOS (Basic Input/Output System) and is designed to be more flexible and secure than BIOS](https://www.howtogeek.com/56958/HTG-EXPLAINS-HOW-UEFI-WILL-REPLACE-THE-BIOS/)[1](https://www.howtogeek.com/56958/HTG-EXPLAINS-HOW-UEFI-WILL-REPLACE-THE-BIOS/). [UEFI supports larger hard drives, faster boot times, more security features, and—conveniently—graphics and mouse cursors](https://en.wikipedia.org/wiki/UEFI)[2](https://en.wikipedia.org/wiki/UEFI). [The UEFI specification defines a protocol known as Secure Boot, which can secure the boot process by preventing the loading of UEFI drivers or OS boot loaders that are not signed with an acceptable digital signature](https://en.wikipedia.org/wiki/UEFI)

#### 1.3.5 SYSTÉM SÚBOROV = FILESYSTEM

#### Adresáre a súbory

Vytvorenie prazdneho adresara a suboru v Linuxe
``` bash
mkdir ADRESAR
cd ADRESAR
touch SUBOR
cd ..
```

Vytvorenie prazdneho adresara a suboru vo Windowse:
``` powershell
mkdir ADRESAR
cd ADRESAR
New-Item subor -ItemType file 
New-Item -Type Directory -Name TEST
cd ..

Remove-Item test.txt
```

#### Prezeranie adresárov

``` bash
ls -al
```

``` powershell
Get-ChildItem -File
```



Detailné dáta o súboroch a adresároch
Powershell: 
```sql
d - Directory
a - Archive
r - Read-only
h - Hidden
s - System
l - Reparse point, symlink, etc.
```

#### Stromová štruktúra adresára

``` powershell
tree ADRESAR
```

## 1.4 Zbernice a Specialne Zariadenia pocitaca
#hardware

#### 1.4.1 PCi-Express a stara PCI


WIN: Device manager, dxdiag
LINUX: lspci, lshw

DIAGNOSTIKA SLOTOV PCiE POMOCOU SPECIALIZOVANEJ KARTY

#### 1.4.2 RTC Modul

Modul ktory ma na starosti udrziavanie casu počas vypnutia počitaca.
Väčšina PC sa pri bootovaní synchronizacia s NTP  / sieťový čas 


#### 1.4.2 TPM 2.0 Trusted Platform 

Počítač v počítači, ktorý zabezpečuje uloženie kryptografických kĺúčov a certifikátov a jednoduchých kryptografických funkcií. 

Win I >apps> Optional features > TPM Diagnostics
``` powershell
C:\TpmDiagnostics.exe getdeviceinformation

Get-Tpm
tpm.msc

```


## 1.5 Rozsirena diagnostika systemu Windows

WIN GUI reliability monitor
power

``` powershell
Install-Module -Name Microsoft.DiagnosticDataViewer
```


``` powershell
Enable-DiagnosticDataViewing
Get-DiagnosticData
```



## 1.6 Teplota Procesora DIagnostika
#cpu
``` powershell
# wmic /namespace:\\root\wmi PATH MSAcpi_ThermalZoneTemperature get CurrentTemperature

Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature | Select-Object CurrentTemperature

```

``` powershell
# wmic path Win32_Fan get
# wmic path Win32_TemperatureProbe get
# wmic path win32_VoltageProbe get

Get-CimClass -Namespace root/CIMv2 | Where-Object { $_.CimClassName -match "Fan|Temperature|Voltage" }
Get-CimInstance -ClassName Win32_Fan
Get-CimInstance -ClassName Win32_TemperatureProbe
Get-CimInstance -ClassName Win32_VoltageProbe


```


``` bash
sudo apt-get install lm_sensors
sensors-detect

sensors
```


## 1.7 Python - Svajciarsky nozik kazdeho hackera

Python pomáha automatizovať úlohy, pochopiť koncepty šifrovania, ochrany, vytvárať jednoduché servery a aplikácie. 

Demonštrácia hashovacie algoritmu pomocou python3

>[!info]
>Python si nainštalujte z Microsoft Store a program spustíte zo súboru pomenovaného hash_it.py


pomocou príkazu v POWERSHELLI:
``` Powershell
python.exe hash_it.py
```

Na Linuxe alebo Macu
``` bash
python3 hash_it.py
```

>[! info]
>K Pythonu budete potrebovať nejaký editor v ktorom môžete písať a editovať kód: Sublime Text 4, VSCode, Pycharm Community. 
>
>VŠETKY TRI SÚ ZADARMO



``` python
import hashlib   # pridavame do pythonu prikazy modulu na hashovanie


def hash_it(data):  # vytvarame jednoduchu funkciu, ktora funguje ako mixer
	databytes = bytes(data, encoding='utf8')  # menime text na byte
	h = hashlib.md5()  # vytvarame objekt s hashovacim algoritmom MD5
	h.update(databytes)  # vkladame data do mixeru
	return h.hexdigest()  # vraciame hexadecimalny retazec


if __name__ == '__main__':  # toto je finta ktora nam spusti kod iba ked je skript spusteny ako hlavny
	while True:  # takto sa v ythone robi nekonecny cyklus
		heslo = input('ZADAJ HESLO')  # poziada uzivatela o zadanie hesla
		print(hash_it(heslo))  # vytlaci vygenerovany retazec do shellu


```



## 1.8 Intel VTx a podpora virtualizácie počítačov

### 1.8.1 Hypervisor

program, ktorý nám umožňuje rozdeliť výkonný počítač na viacero menších počítačov s vlastným OS, diskom, RAM aj určeným počtom procesorom. Potrebujeme:

1. počítač s aspoň 16GB pamäti RAM a procesorom podporujúcim VTx
2. Hypervisor napr. Oracle Virtualbox
3. Inštalačku OS vo formáte ISO, alebo kópiu disku.

> [!warning]
> Pomocou VM si môžeme vytvoriť pieskovisko SANDBOX v ktorom môžeme vytvoriť počítač alebo celú sieť LAN, kde budeme pozorovať a skúmať obsah počítača, ktorý by mohol byť infikovaný, alebo napadnutý. !!! POZOR !!! NIKDY NA TENTO SANDBOX NEPOUŽITE POČÍTAČ V CHRÁNENEJ ZÓNE ALEBO OBSAHUJÚCI CITLIVÉ DÁTA.

### 1.8.2 Kontajnerizácia

Vytváranie VM má svoje obmedzenia, napríklad keď pevne určíme koľko má mať disku a pamäti nemôžeme konfiguráciu flexibilne meniť. To znamená, že keď je VM bez záťaže, berie nám časť zdrojov Resourcov aj keď ju nepotrebuje.

Na efektívnejšie využívanie použijeme kontajnerový hypervisor Docker, ktorý spúšťa OS alebo servery s pythonom, webservery, databázy v optimalizovaných a izolovaných kontajneroch. Tieto si ukroja z našeho výkonu iba toľko koľko potrebujú na svoju prácu. 

>[!info]
>Okrem bezpečnostných benefitov ako je izolácia aplikácie a presné určenie prístupu k dátam, je obrovskou výhodou možnosť pri záťaži vytvoriť paralelný kontajner, ktorý preberie prácu ak už náš kontajner nestíha.


### 1.8.3 Superkomputerizácia pomocou KUBERNETES

Kubernetes je softvér, ktorý dokáže rozdeľovať prácu kontajnerom aj keď fyzicky nebežia na jednej mašine. Dokáže tak vytvoriť tzv. CLUSTER serverov, ktoré vykonávajú prácu s desiatkami, stovkami a tisíckami kontajnerov.


## 1. OPERAČNÉ SYSTÉMY

Operačný systém počítača sa skladá z troch základných častí:

1. KERNEL aka JADRO
2. SHELL aka ŠKRUPINA
3. GUI
### 1.1 MS-DOS / WINDOWS 95

### 1.2 WIN10 s  integraciou WSL2 (Windows Subsystem for Linux)

wsl --install


### 1.3 PODIEL NA TRHU PC
WIN10 74% trhoveho podielu PC
MacOS cca 17% ostatne LINUX a pod

### PODIEL NA TRHU SERVEROV
SERVERY viac ako 80% su LINUX

> [!info] 
> SPECIALNE LINUX DISTRIBUCIE :
> KALI, 
> PARROT, 
> SECURITYONION
> 
> AJ VO VERZII *LIVE* S FORENSIC MODOM MOZETE MAT NA USB KLUCI VSADE SO SEBOU A MAT VSETKY POTREBNE NASTROJE NA DIAGNOSTIKU, DETEKCIU A PENETRACNE TESTOVANIE

[! war]

## 2. PATCHE A UPDATE PRE SOFTVER A HARDVER

### 2.1 FAKTY:
1. Neupdatovany a nezapatchovany pocitac je plny bezpecnostnych dier CAS BEZI
2. Tisice developerov pracuju na stabilite a bezpecnosti systemov KAZDY DEN
3. Nespoliehajte sa na uzivatelov - PATCH MANAGEMENT  ITARIAN

### 2.2 PROBLEM S PATCHOVANIM PRODUKCNYCH SERVEROV

DEVELOPER > DEVOPS > SYSADMIN

Predstavujeme DEVOPS - partia ktora ma na starosti testovanie softveru skor ako ho pustime na produkcny server


Security Patche a Updaty su klucovym faktorom ochrany Vaseho pocitaca 
CYKLUS SOFTVERU - ISSUES AND TICKETS

Preco nie su updatovane a patchovane pocitace ENDPOINTY A SERVERY 

UZIVATELIA ENDPOINTOV NEZNASAJU UPDATE A POVAZUJU ICH ZA ZBYTOCNE

ZRANITELNOSTI
https://github.com/CVEProject/cvelist.git

ZERO DAY ZRANITELNOSTI A EXPLOITY

WIN10 najnapadanejsia platforma  - uzavrety system, tlak developerov a hackerov



## 2. UZIVATELIA A ICH PRISTUPOVE PRAVA

>[!warning]
>ROOT je absolutny vladca pocitaca - !!! POZOR nikomu inemu nedavaj root pristup
>SUDO je zemepan - v skupine sudo moze byt viac uzivatelov, ktori mozu administrovat system


### 2.1 Spravime si uzivatela:

``` bash
sudo adduser test
sudo usermod -aG sudo test
sudo deluser test

```

``` powershell
$password = Read-Host -AsSecureString
$date = Get-Date -Year 2022 -Month 06 -Day 10
$username = 'test'
# Creating the user
New-LocalUser -Name "$username" -Password $password -AccountExpires $date -FullName "$username" -Description "Novy uzivatel"
Set-LocalUser -name '$username' -Description 'Jozo z uctovneho'
```


``` python
-Name : meno uzivatela max 20 characters|
-Password : Heslo
-Description : popis noveho uzivatela
-AccountExpires : Datum kedy user expiruje
-AccountNeverExpires: Nastavenie uzivatel nikdy neexpiruje
-Disabled : nastavenie uctu ako vypnuty
-FullName : Zobrazuj plne meno uzivatela
-PasswordNeverExpires : Heslo nikdy neexpiruje
-UserMayNotChangePassword : Uzivatel si nemoze nastavit heslo
```

### 2.2 SKUPINY
``` bash
groups
groups jozo
```


WINDOWS:
``` powershell
Get-LocalGroup
Get-LocalGroupMember Users
Add-LocalGroupMember -Group Users -Member "test"
```


### 2.3 PRISTUP K SUBOROM

``` sql
d - directory
r - read
w - write
x - execute

(USER GROUP OTHERS)  = ugo
```

``` bash
chown jozo SUBOR
chgrp GROUP SUBOR


chmod u+w SUBOR

chmod 777 SUBOR  # daj vsetko vsetkym
```


``` powershell
takeown /F '.\archive (1).csv'
$Acl = Get-Acl "FILE"  # premenna s pristupmi
$Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("forti","FullControl","Allow")
$Acl.SetOwner([System.Security.Principal.NTAccount]"forti")
$Acl.SetAccessRule($Ar)
Set-Acl "FILE" $Acl

```

## SILNÝ NÁSTROJ PRE NASTAVOVANIE SKUPINOVÝCH PRAVIDIEL VO WIN11

powershell WIN PRO 
``` powershell
gpedit.msc
```

## CVICENIE 1

DIAGNOSTIKA PC>

```powershell
# PC
Get-ComputerInfo
# CPU
Get-WmiObject -Query "SELECT * FROM Win32_Processor"
# Pamat
`Get-WmiObject -Class Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory`

`Get-WmiObject -Class Win32_PhysicalMemory`

# DISK
`Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, @{Name="Used(GB)";Expression={[math]::round($_.Used / 1GB, 2)}}, @{Name="Free(GB)";Expression={[math]::round($_.Free / 1GB, 2)}}`

`Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"`
```

# POKRAČUJEME ...

[[SESSION2_HESLA_LOGY_NETWORKING]]