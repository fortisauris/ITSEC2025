## C. KRYPTOGRAFIA

### C.1 Historické šifry
a.  Scytale 
b. Cézarova šifra a ROT13
c. Albertiho Sifrovaci disk 
Nihilist

#### C.2 Vernamova šifra (OTP)

Používaná sovietskymi špiónmi až do 70tych rokov

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


C.4 HAGELIN 

Elektromechanický šifrovací stroj používaný ako nástupca Enigmy až do nástupu počítačového šifrovania do 60tych rokov.

C.5 DES = DATA ENCRYPTION STANDARD
Symetrická šifra vyvinutá IBM používaná od 1977 do 2001 ako šifrovací štandard.

C.6 AES - ADVANCED ENCRYPTION STANDARD

Elektromechanické šifry na báze rotorov slúžili až do 70tych rokov. Potom ich postupne nahrádzala počítačová kryptografia v podobe algoritmu DES a neskôr Triple DES. V 1997 roku NIST (National Institute of Standard and Technology) vypísala súťaž o nový šifrovací štandard. Do súťaže sa prihlásilo viacero kryptografických algoritmov. Vyhral algoritmus menom Rjijandel od Belgických autorov, druhý bol Serpent.

AES256 sa stalo štandardom šifrovania pre priemysel a ochranu utajovaných skutočností. 

V súčasnosti sa uvažuje už o novom štandarde šifrovania. Favoritom sa stáva algoritmus ChaCha.

### C.7 PRINCIPY MODERNÝCH ALGORITMOV
Moderné šifrovanie je založené na jednoduchých matematických a logických operáciach ako je XOR, posun bitov, miešanie matric a podobne. Tieto operácie sa opakujú niekoľkokrát aby ich nebolo možné bez kľúča prelomiť.

#### C.7.1   OPERACIA XOR A NAHODNE CISLA

Ukážeme si jednoduchú operáciu XOR v Pythone
``` python

import random   # NEPOUZIVAT NA KRYPTOGRAFIU !!! 


def apply_xor_operation(value : str, key : str):
    """
    Funkcia aplikuje vypocet bitwise XOR hodnoty a kluca hexadecimalne cislo 0x00 do 0xff v STRINGU.
    Vysledkom je hexadecimalne cislo od 00 do FF tj. 0 do 255.
    parameter::: value - STRING s hex cislom od 0x00 do 0xff
    parameter::: key - STRING s hex cislom od 0x00 do 0xff
    return ::: vysledok vypoctu - hex cislom od 0x00 do 0xff
    """
    value = eval(value)
    key = eval(key)
    return hex(value ^ key)  # tuto sa deju zazraky 


if __name__ == "__main__":
    value = hex(random.randint(0,255))
    key = hex(random.randint(0,255))
    print("VALUE : ", value, " KEY : ", key," RESULT : ",apply_xor_operation( value, key))
```

Aby moderné šifry správne fungovali a kľúče ktoré sa používajú sú tvorené z vygenerovaných náhodných čísel. Ak by čisla neboli dostatočne náhodné dal by sa vytvoriť vzorec a množstvo pravdepodobných kľúčov by sa nám podstatne zúžilo. Preto treba používať generátory pseudonáhodných čísel určené na kryptografiu a nie python modul `random`.


**Zraniteľnosť eliptickej krivkovej kryptografie (ECC)** sa vzťahuje predovšetkým na nesprávnu implementáciu alebo útok na matematické základy, na ktorých ECC stojí.

#### C.7.2 VYSOKÉ PRVOČÍSLA

Vysoké prvočísla majú v modernej kryptografii špecifickú úlohu. Ich vlastnosťou je, že sú všade rovnako vypočítateľné a pritom jedinečné. 

#### C.7.3 RYCHLE SIFROVANIE DATOVYCH STREAMOV

AES256 je algoritmus, ktorý môžeme použiť na šifrovanie súboru, disku USB kľúča, mailu a pod. Nie je však vhodný na šifrovanie obrovských streamov dát z jednej IP na druhú ako je VIDEO, ZVUK a pod. Napriek tomu potrebujeme tieto dáta ochrániť. Použijeme jednoduchšie a rýchlejšie formy šifrovania.

``` python
# PRINCIP SBOXU
sbox = [45, 12, 56,9,11,78,120,]
znak_na_zasifrovanie = 65 # ASCII HODNOTA A

def sbox_enc(sbox, znak_na_zasifrovanie)
	'''
	Funkcia SBOX prechadza SBOXOM a zakazdym hodnotu XORuje s dalsim cislom v SBOXE
	SBOXOV byva niekolko za sebou a operacii vela. Vysledkom je totalne
	modifikovana hodnota 65
	'''
	enc = znak_na_zasifrovanie # 
	for i in sbox:
		enc = enc ^ i
	print('VYSLEDOK JE: ', enc)
	# NA DESIFROVANIE STACI OTOCIT PORADIE SBOXU A PREHNAT HODNOTU NASPAT
	return enc

def jednoduchy_permutacny_box(hex_cislo):
	'''
	Hexadecimalna hodnota vstupuje do PERMABOXU nemodifikovana a podla nastavenej 
	modifikacie vychadza z PERMABOXU pozmenena. Opakovaniami v kombinacii s
	dalsimi operaciami mozno vstupnu hodnotu zmenit niekolkokrat. Funguje podobne
	 ako Enigma PLUGBOARD
	'''
	if hex_cislo == '0x0':
		return '0x5'
	if hex_cislo == '0x1':
		return '0xa'
	if hex_cislo == '0x2':
		return '0x3'
	if hex_cislo == '0x3':
		return '0xa'
	if hex_cislo == '0x4':
		return '0xf'
	else:
		return hex_cislo
	
if __name__ == "__main__":
	sbox_enc(sbox, znak_na_zasifrovanie)
	jednoduchy_permutacny_box('0x4')

```



#### C.7.4 ASYMETRICKÁ VÝMENA KĽÚČOV

Problém symetrického šifrovania je, že obe strany musia disponovať rovnakým kľúčom. TO je celkom technická výzva ako tento kľúč doručiť niekomu bez toho aby nemohlo dôjsť ke jeho kompromitácii. 

Asymetricke šífrovanie je postavené na pároch vygenerovaných kľúčov a pomocou zložitého matematického výpočtu si vedia počítače dohodnúť spoločný kľúč. Pomocou neho môžu prejsť na symetrické šifrovanie, ktoré je oveľa rýchlejšie.

PUBLIC = verejný kľúč môžete poslať hocikomu
PRIVATE = súkromný kľúč musíte chrániť ako oko v hlave.

``` python
# ASYMETRICKA VYMENA KLUCOV DIFFIE-HELLMAN

# ALICA
AlicineTajomstvo = 75433

# BOB
BoboTajomstvo = 56575

# Server
g = 5472437625635634658438583468564336543654365346546534 # nahodne vybrane cislo
n = 911 # prvocislo

# Alica ide poslat Bobovi kluc
A_posiela =(g ** AlicineTajomstvo) % n
print("ALICA POSIELA", A_posiela)
# Bob ide poslat kluc Alici
B_posiela = (g ** BoboTajomstvo) % n
print("BOB POSIELA", B_posiela)

# Alica otvara Bobov kluc
Bobov_kluc = (B_posiela ** AlicineTajomstvo) % n
print("Bobov zdielany kluc",Bobov_kluc)

# Bob otvara Alicin kluca
Alicin_Kluc = (A_posiela ** BoboTajomstvo) % n
print("Alicin Zdielany kluc",Alicin_Kluc)
```


#### C.7.5 CERTIFIKÁCIA KRYPTOGRAFICKÝCH KĽÚČOV

Kryptografické certifikáty a klúče sú základným stavebným kamenom bezpečnej digitálnej komunikácie a autentifikácie. Ich hlavná úloha spočíva v **overovaní identity** (napr. webových stránok, serverov, používateľov) a v **zabezpečení dát** prostredníctvom šifrovania. Bez nich by bolo takmer nemožné dôveryhodne overiť, či komunikujete so skutočným partnerom (napr. bankou, e-shopom) a nie s podvodníkom.

**Kľúčové výhody:**

- **Autentifikácia:** Certifikáty potvrdzujú, že daná entita (napr. webová stránka) je skutočne tým, za koho sa vydáva.
- **Šifrovanie:** Kryptografické klúče zabezpečujú, že dáta sú prenesené v zašifrovanej podobe a nie sú prístupné neoprávneným osobám.
- **Integrita dát:** Certifikáty a digitálne podpisy zaručujú, že dáta neboli počas prenosu zmenené.
- **Dôvera:** Certifikačné autority (CA) vydávajú certifikáty, čo umožňuje vytvoriť reťaz dôvery v digitálnom svete.

Bez certifikátov a klúčov by internetové transakcie, online bankovníctvo, e-mailová komunikácia a mnohé ďalšie služby boli extrémne zraniteľné voči útokom, ako je phishing, man-in-the-middle alebo podvrhnutie identity. Preto sú nevyhnutné pre bezpečnú a dôveryhodnú digitálnu infraštruktúru.

#### C.7.6 BUDUCNOST

Moderné metódy šifrovanie strážia nielen naše tajomstvá, ale aj súkromie, biometrické dáta či zdravotné záznamy. V súčasnosti sme si hovorili o ZERO TRUST trende v IT SEC. Aká je budúcnosť šifrovania ? Šifrovanie bude naďalej zohrávať kľúčovú rolu v našom živote. 

Kvantové počítače len zvýšia tlak na vytváranie nových a mocnejších šifier. Šifrovacie algoritmy sú obávaným nepriateľom Autokratických systémov kde je ľuďom upieraná sloboda. Často sú za použitie šifrovacieho algoritmu vysoký trest. Preto slobodne šifrujte ... 


# **A. SKUMANIE INCIDENTU ON SITE**

Dnes bude rušný deň. Ranný telefonát, ktorý prišiel ešte pred svitaním, neveští nič dobrého. Niečo sa deje na našej sieti. Podľa prvých informácií ide o **kybernetický útok**, ktorý sa práve rozvíja. Podľa predom dohodnutého plánu reakcie na incidenty sa **IRT (Incident Response Team)** dáva do pohybu smerom k serverovni. Cestou sa ešte zastavujeme na kávu – **TakeAway**, lebo bez kofeínu by sme neboli schopní efektívne riešiť túto krízovú situáciu.


## **A.1 PASÍVNY PRIESKUM**

### **Cieľ pasívneho prieskumu**

Našou prioritou je **zhromaždiť čo najviac informácií o incidente bez zásahu do bežnej prevádzky siete (LAN)**. Pasívny prieskum znamená, že nebudeme aktívne meniť konfigurácie, vypínať zariadenia alebo iným spôsobom ovplyvňovať chod siete. Naším úlohou je **analyzovať dostupné dáta**, identifikovať stopy útoku a zistiť, ako daleko sa útočník dostal.

### **Rozdelenie do skupín**

Pre efektívny prieskum sa rozdelíme do **troj skupín**, z ktorých každá bude mať špecifické úlohy:

1. **Skupina 1: Analýza Suricata IDS**
    
    - **Úloha**: Prehľadávať a analyzovať **`eve.json`**, ktorý je výstupom z **Suricata IDS** (Intrusion Detection System).
    - **Cieľ**: Identifikovať podozrivé udalosti, ako napríklad:
        - Neobvyklé sieťové pripojenia.
        - Pokusy o prihlásenie s neúspešnými heslami.
        - Komunikácia s známymi škodlivými IP adresami.
    - **Postup**: Ak sa niečo nájde, okamžite informovať ostatné skupiny a zistiť **čas, miesto a aktérov** (IP/MAC adresy).

 **Skupina 2: Analýza logov**
    
    - **Úloha**: Prehľadávať **centralizované logy** z rôznych systémov (Windows Event Log, Linux syslog, aplikácie).
    - **Cieľ**: Nájdenie stôp po útoku, ako napríklad:
        - Neobvyklé prihlasovacie pokusy.
        - Zmeny v konfigurácii systémov.
        - Spustenie podozrivých procesov.
    - **Postup**: Ak sa nájde niečo podozrivé, zaznamenať **čas, typ udalosti a príslušné IP/MAC adresy**.

**Skupina 3: Analýza sieťových záznamov (.pcap)**
    
    - **Úloha**: Prehľadávať **sieťové záznamy (.pcap)**, ktoré sú nahrané buď priamo na Suricata alebo z 24/7 monitoringu.
    - **Cieľ**: Zistiť, ako presne prebiehal útok, aké protokoly a nástroje útočník používal.
    - **Postup**: Analyzovať komunikáciu medzi zariadeniami a identifikovať podozrivé pakety.

---
NetTap 

### **Zistenia z pasívneho prieskumu**

Z prvých analýz vyplýva, že **útok sa udial v čase, keď bola väčšina koncových zariadení (endpoitov) vypnutá**. To znamená, že **sieťová komunikácia bola minimálna**, čo môže znamenať, že útočník ešte neprešiel do aktívnej fázy útoku. Je možné, že sa nachádza v **RECON fáze** (zber informácií o sieti), kde skúma našu infraštruktúru a hľadá zraniteľné miesta.

Vďaka **IDS (Suricata)** a **centralizovaným logom** sme schopní rýchlo reagovať. Zatiaľ sa nezdá, že by útočník narazil na naš **HONEYPOT** v chránených segmentoch LAN, čo by mohlo znamenať, že ešte nevedia o našich obranných mechanizmoch.

### **Zdroje pre pasívny prieskum**

Pre našu analýzu využívame nasledujúce zdroje:

1. **Nahraté .pcap súbory**
    
    - Sieťové záznamy z **Suricata IDS** alebo 24/7 monitoringu.
    - Obsahujú všetky sieťové pakety, ktoré prechádzali cez našu sieť v danom časovom úseku.
2. **Log Management**
    
    - **Centralizované logy** z rôznych systémov (Windows Event Log, syslog, aplikácie).
    - Umožňujú nám sledovať udalosti na jednotlivých zariadeniach.
3. **Suricata Events**
    
    - **Udalosti z IDS**, ktoré signalizujú potenciálne útoky alebo podozrivé aktivity.
    - Obsahujú informácie o zdrojových a cieľových IP adresách, protokoloch a typu útoku.

---


### **Ďalšie kroky**

1. **Zdieľanie informácií medzi skupinami**: Ak ktorákoľvek skupina nájde niečo podozrivé, okamžite informovať ostatné a zaktualizovať spoločnú databázu nálezov.
2. **Záznam času a miest udalostí**: Presné zaznamenanie času, miesta a aktérov (IP/MAC adresy) je kľúčové pre ďalšiu analýzu.
3. **Príprava na aktívny prieskum**: Ak sa potvrdí prítomnosť útočníka, príprava na **aktívny zásah** (izolácia zariadení, blokovanie IP adres).

### **Záver**

Pasívny prieskum je **prvým krokom** v riešení kybernetického incidentu. Jeho cieľom je **zhromaždiť čo najviac informácií bez zásahu do bežnej prevádzky**. Na základe týchto informácií budeme schopní rozhodnúť, ako ďalej postupovať – či už ide o **izoláciu napadených systémov**, **blokovanie útočníkov** alebo **obnovenie systémov z záloh**.

**Ďalší krok**: Po zhromaždení dostatočného množstva informácií prejdeme do **aktívnej fázy**, kde budeme priamo zasahovať do siete a odstraňovať hrozby.

## A.2 AKTIVNY PRIESKUM
#live_forensics

### A.2.1  MEMORY DUMP BEZIACEHO POCITACA
#live_forensics
Ak je na napdnutom počítači nejaký škodlivý kód aktívny bude určite spustený v nejakom bežiacom procese, alebo schovaný niekde v pamäti počítača. Najrozumnejšie preto je, skôr ako podnikneme ďalšie kroky získať kópiu pamúti pomocou špecálneho forenzného nástroja pre Windows alebo v Linuxe pomocou príkazu:

``` bash
cat /dev/mem  
memdump -h

```


Ak beží počítač vo VM v Sandboxe môžeme ho spustiť v tzv. Debugger móde a skúmať jeho obsah.
``` powershell
C:\Program Files\Oracle\VirtualBox>vboxmanage startvm "kali_nessus" -E VBOX_GUI_DBG_AUTO_SHOW=true -E VBOX_GUI_DBG_ENABLED=true
```

DEVOPS: DEBUGGER je program, ktorý nám umožňuje pomocou BREAKPOINTOV a KROKOVANIA umožňuje zastavovať a skúmať vnútro bežiaceho programu. Tieto programy sa používajú na nájdenie chýb v kóde, ale aj na pochopenie jeho aktivít ako je to pri REVERZNOM INŽINIERSTVE. 

Ak sa nám podarilo získať kópiu pamäte môžeme ju preskúmať úžasným pythonovským nástrojom Volatility:
https://github.com/volatilityfoundation/volatility

## **A.2.1 MEMORY DUMP BEŽIACEHO POČÍTAČA**

### **Prečo je dôležité získavať pamäťový dump?**

Ak je na napadenom počítači **aktívny škodlivý kód**, bude pravdepodobne spustený v **bežiacom procese** alebo skryty niekde v pamäti. **Memory dump** (kópia pamäte) nám umožní:

- Identifikovať **skryté procesy** a **malware**.
- Získať informácie o **bežiacich spojeniach** a **sieťovej aktivite**.
- Analyzovať **zmeny v systéme**, ktoré útočník spôsobil.

---

### **Nástroje na získanie memory dumpu**

#### **1. Windows**

Na **Windows** systémoch môžeme použiť nasledujúce nástroje:

- **FTK Imager** (Forensic Toolkit Imager) – bezplatný nástroj od AccessData.
- **Magnet RAM Capture** – jednoduchý nástroj na získanie pamäte.
- **Dumpert** – nástroj od Microsoftu na získanie pamäte pre forenznú analýzu.

**Príklad použitia Dumpert:**
``` powershell
Dumpert64.exe -f C:\memory_dump.dump
```

#### **2. Linux**

Na **Linux** systémoch môžeme použiť:

- **`/dev/mem`** – priamy prístup k pamäti (vyžaduje root práva).
- **`memdump`** – nástroj na získanie pamäte.
- **`avml`** (Acquire Volatile Memory for Linux) – nástroj od volatilityfoundation.

**Príklad použitia:**
``` bash
sudo dd if=/dev/mem of=memory_dump.bin bs=1M
```

alebo

``` bash
sudo memdump -h > memory_dump.bin
```


---

### A.2.2 **Analýza memory dumpu pomocou Volatility**

Ak sme úspešne získali **memory dump**, môžeme ho analyzovať pomocou **Volatility** – mocného Pythonového nástroja pre forenznú analýzu pamäte.

#### **Inštalácia Volatility**
``` bash
git clone https://github.com/volatilityfoundation/volatility.git 
cd volatility 
python setup.py install

# POUZITIE

# Zistenie profilu OS
python vol.py -f memory_dump.bin imageinfo

# Zoznam beziacich procesov
python vol.py -f memory_dump.bin --profile=<profil> pslist

# Zistenie sietovych pripojeni
python vol.py -f memory_dump.bin --profile=<profil> netscan

# Zistenie skrytych procesov
python vol.py -f memory_dump.bin --profile=<profil> psxview

# Analyza pritomnosti malware
python vol.py -f memory_dump.bin --profile=<profil> malfind

```
    

---

### **Debugger mód v VirtualBox**

Ak beží napadený počítač vo **virtuálnom prostredí (VM)**, môžeme ho spustiť v **Debugger móde**, čo nám umožní **krokovať** a **analyzovať** bežiaci kód.

**Príkaz na spustenie VM v Debugger móde:**

`C:\Program Files\Oracle\VirtualBox>vboxmanage startvm "kali_nessus" --debug`

alebo

`C:\Program Files\Oracle\VirtualBox>vboxmanage startvm "kali_nessus" -E VBOX_GUI_DBG_AUTO_SHOW=true -E VBOX_GUI_DBG_ENABLED=true`

#### **Čo je Debugger?**

- **Debugger** je program, ktorý nám umožňuje **zastavovať** a **skúmať** bežiaci program pomocou **breakpointov** a **krokovania**.
- Používa sa na **nájdenie chýb v kóde** alebo na **reverzné inžinierstvo** (skúmanie, ako funguje škodlivý kód).

[[S8A_MEMORY_DUMP_Z_VirtualBoxVM]]
---

## **A.2.2 NMAP ATTACK MODE**

### **Prečo používať Nmap?**

**Nmap** (Network Mapper) je silný nástroj na **skenovanie siete**, ktorý nám pomôže:

- Zistiť **aktívne zariadenia** v sieti.
- Identifikovať **otvorené porty** a **služby**.
- Zistiť **zraniteľnosti** v sieťových zariadeniach.

---

### **Použitie Nmap v Attack Mode**

Pre **aktívny prieskum** môžeme použiť Nmap v **agresívnom móde** (`-A`), ktorý nám poskytne **podrobné informácie** o zariadeniach v sieti.

**Príklad skenovania celej podsiete:**

`nmap -T4 -A -v 192.168.1.0/24`

#### **Význam parametrov:**

Parameter

`-T4` Rýchle skenovanie (agresívny mód).

`-A` Agresívne skenovanie (zistenie OS, verzií služieb, atď.).

`-v` Podrobný výstup (verbose).

`192.168.1.0/24` Rozsah IP adries na skenovanie.


### **Čo hľadáme?**

1. **Neobvyklé otvorené porty** (napr. 4444, 31337 – často používané malware).
2. **Zariadenia s neaktualizovaným softvérom** (zraniteľné na útoky).
3. **Podozrivé služby** (napr. neznáme HTTP servery, proxy).
4. **Zmeny v sieťovej topológii** (neznáme zariadenia).



### **1. Windows Forensic Toolchest (WFT)**

- **Posledná verzia z roku 2014** – už nie je udržiavaný.
- **Funkcie**:
    - Získavanie **memory dumpov**.
    - Analýza **registrov**.
    - Získavanie **sieťových informácií**.
- **Problémy**:
    - Nemusí fungovať na **Windows 10/11**.
    - Chýbajúca podpora pre **moderné súborové systémy** (ReFS).

> ⚠️ **POZOR NA STARÝ SOFTVÉR** Nástroje ako **WFT** alebo **WinPE** sú zastarané a nemusia fungovať správne. Odporúča sa použiť **moderné alternatívy** ako **FTK Imager**, **Kape** alebo **Velociraptor**.

---


### **2. Moderné alternatívy**
| Nástroj                         | Popis                                                    | Odkaz                                                                                  |
| ------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **FTK Imager**                  | Forenzný nástroj na získavanie dát z diskov a pamäte.    | [AccessData](https://accessdata.com/product-download)                                  |
| **Kape**                        | Lightweight nástroj na získavanie forenzných dát.        | [GitHub](https://github.com/EricZimmerman/Kape)                                        |
| **Velociraptor**                | Open-source nástroj na forenznú analýzu.                 | [Velociraptor](https://www.velocidex.com/)                                             |
| **Autopsy**                     | Grafický forenzný nástroj pre analýzu diskov.            | [Autopsy](https://www.autopsy.com/)                                                    |
| **Volatility**                  | Pythonový nástroj pre analýzu pamäte (memory forensics). | [Volatility](https://github.com/volatilityfoundation/volatility)                       |
| **Magnet RAM Capture**          | Lightweight nástroj na získanie pamäte Windows.          | [Magnet Forensics](https://www.magnetforensics.com/resources/magnet-ram-capture/)      |
| **LiME**                        | Loadable Kernel Module pre získanie pamäte v Linuxe.     | [GitHub](https://github.com/504ensicsLabs/LiME)                                        |
| **WinDbg**                      | Debugger pre Windows, podporuje analýzu pamäte.          | [Microsoft Docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) |
| **Rekall**                      | Alternatíva k Volatility pre analýzu pamäte.             | [GitHub](https://github.com/google/rekall)                                             |
| **Belkasoft Live RAM Capturer** | Nástroj na získanie RAM pre Windows.                     | [Belkasoft](https://belkasoft.com/get)                                                 |

---

### **3. Postup pri zbieraní dát**

1. **Získajte memory dump** (pomocou `FTK Imager` alebo `Kape`).
2. **Získajte kópiu disku** (pomocou `dd` alebo `FTK Imager`).
3. **Analyzujte registry** (pomocou `RegRipper` alebo `Eric Zimmerman’s Tools`).
4. **Prehľadajte logy** (Windows Event Log, Sysmon logs).
5. **Skúmajte sieťové aktivity** (pomocou Wireshark alebo Suricata).



## **A.2.4 ĎALŠIE AKTÍVNE KROKY**

### **1. Izolácia napadených systémov**

Ak sme identifikovali **napadené zariadenia**, je dôležité ich **izolovať** od siete, aby sme zabránili ďalšiemu šíreniu útoku.

**Postup:**

- Odpojiť zariadenie od siete (fyzicky alebo cez firewall).
- Zablokovať IP adresy útočníkov.


### **2. Blokovanie škodlivej komunikácie**

Ak sme identifikovali **IP adresy alebo domény**, ktoré útočník používa, môžeme ich **zablokovať** na firewalle alebo v sieti.

**Príklad blokovania IP v Linuxe:**

`sudo iptables -A INPUT -s <attacker_IP> -j DROP`

---


### **3. Obnova systémov z záloh**

Ak sme zistili, že systém bol **kompromitovaný**, najlepším riešením je **obnoviť ho z čistej zálohy**.

**Postup:**

1. Vypnite napadený systém.
2. Nainštalujte čistú verziu OS alebo obnovte z **zálohy**.
3. Aktualizujte všetky balíčky a opravte zraniteľnosti.

##### 4Monitorovanie a detekcia ďalších útokov**

Po odstránení hrozby je dôležité **monitorovať sieť** a **detekovať ďalšie pokusy o útok**.

**Nástroje na monitorovanie:**

- **Suricata** (IDS/IPS).
- **Wazuh** (SIEM).
- **OSSEC** (HIDS).

## **ZÁVER**

**Aktívny prieskum** je kľúčovou časťou reakcie na kybernetický incident. Pomocou **memory dumpov**, **sieťového skenovania** a **forenznej analýzy** sme schopní **identifikovať a odstrániť hrozby**. Dôležité je **rýchlo a efektívne** reagovať, aby sme minimalizovali škody a zabránili ďalšiemu šíreniu útoku.

**Ďalšie kroky:**

- Izolovať napadené systémy.
- Blokovať škodlivú komunikáciu.
- Obnoviť systémy z čistých záloh.
- Monitorovať sieť na ďalšie útoky.

### **1. Velociraptor**

**Popis:**

- **Open-source** nástroj na vzdialené skúmanie a forenznú analýzu.
- Podporuje **Windows, Linux, a macOS**.
- Nevyžaduje databázový server (ako GRR), používa **SQLite** alebo **PostgreSQL** (voliteľne).
- Má **grafické rozhranie** a podporuje **automatizované skripty** pre zbieranie dát.

**Inštalácia (Docker):**

``` bash
`docker run -d --name velociraptor -p 8000:8000 -p 8001:8001 velociraptor/velociraptor`

```



- Prístup cez prehliadač: `http://<IP>:8000`

**Inštalácia klienta:**

- Stiahnite a spustite inštalačný skript pre daný OS:
    
 ``` bash
curl -fsSL https://raw.githubusercontent.com/Velocidex/velociraptor/master/velociraptor-client | bash
 
 ```
    
    
**Odkaz:** [Velociraptor](https://www.velocidex.com/)

. Kape (Kroll Artifact Parser & Extractor)**

**Popis:**

- **Lightweight** nástroj na získavanie forenzných dát z Windows systémov.
- Nevyžaduje server, beží priamo na klientovi.
- Podporuje **automatizované zbieranie dát** (napr. pamäť, registry, logy).

**Inštalácia:**

- Stiahnite **Kape** z GitHubu:

``` powershell
Invoke-WebRequest -Uri "https://github.com/EricZimmerman/Kape/releases/latest/download/Kape.zip" -OutFile "Kape.zip" Expand-Archive Kape.zip

```
    
- Spustite `Kape.exe` a vyberte, ktoré dáta chcete zhromaždiť.

**Odkaz:** [Kape](https://github.com/EricZimmerman/Kape)

### A.2.5 DALSIE UZITOCNE PRIKAZY PRE WINDOWS

``` Powershell
netstat -naob  # vypise vsetky sietove spojenia a pouzivane porty 
taskmgr.exe  # Task Manager ako ho lubime  
Get-HotFix  # zobrazi posledne bezpecnostne zaplaty tzv HotFixy
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
Get-Package

sigverif

```


### A.2.6 WAZUH

SIEM and XDR riesenie na Endpointy aj na server
[[S8B_WAZUH_SIEM_SECURITY_INFORMATION_AND_EVENT_MANAGEMENT]]


### A.2.7 BITSCOUT NETESTOVALI SME
https://github.com/vitaly-kamluk/bitscout


## A.2.8 Fast Incident Response  NETESTOVALI SME
https://github.com/certsocietegenerale/FIR


### A.2.9 Mozzila Mig
https://github.com/mozilla/mig


## A.4  DERATIZACIA
UKAZKA - MALWAREBYTES A SPYBOT Search and Destroy

DEZINFEKCIA TOOLS
malwarebytes.com
SPYBOT Search and Destroy -  safer-networking.com
SOPHOS
ClamAV

### A.5  UROBENIE KOPIE NAKAZENEHO SYSTEMU
WINDOWS : Passmark ImageUSB a potom  winiso
KALI - GUYMAGER robi specialne dd alebo svoje kopie

``` bash
dd if=/disk.dd of=/disk.iso bs=512
```




# B. FORENZIC MODE v KALI
#reverse_eng 

### B.1  HASHDEEP  - KRAL HASHOV

Pomocou hashovacích algoritmov vieme urobiť otlačok každého spistiteľného súboru v počítači. Hashdeep vie aj analyzovať a porovnávať súbory, adresáre či v nich nedošlo k zmene. 

``` bash
hashdeep -r ADRESAR > subor_s_hashmi
hashdeep -a -k subor_s_hashmi -r ADRESAR
```


### B.2 BINWALK - POROVNAVANIE DUMPOV

Ak sme vytvorili zoznam modifikovaných súborov a ak máme niekde originál súboru s inštalačky systému, môžeme ich porovnať pomocou programu BINWALK. Tento program nám dokáže rýchlo nájsť rozdiely  a zozbraziť ich v požadovanom formáte.

``` bash 
binwalk -W FILE FILE
```


BINWALK vie porovnávať viacero súborov naraz.

POZOR NA ROZNE VERZIE TOHO ISTEHO PROGRAMU. MUSIME VŽDY POROVNAVAŤ ROVNAKÉ VERZIE 


### B.3 AUTOPSY

Na forenzné prezeranie diskov a ich imidžov použijeme AUTOPSY. Tento softvér je určený pre profesionálov akými sú súdni znalci a pod. VIeme prechádzať disk po sektoroch, robiť si poznámky, vyhľadávať reťazce a súbory (ÁNO AJ TIE VYMAZANÉ) a pod. 



# C. REVERSE ENGENEERING

Reverzné inžinierstvo sa zapodieva spätným rozoberaním programov, ktoré by mohli obsahovať škodlivý kód alebo zraniteľnosť. 

STROJOVÝ KÓD  > ASSEMBLY > C > JAVA >  PYTHON

KOMPILOVANÝ KÓD je keď zdrojový kód programu pomocou kompilera preložíme do strojového kódu.


C.1 NASM - NETWIDE ASSEMBLER

TO čo je pre normálneho hackera Python3 je pre reverzného inžiniera C a ASSEMBLY. Znalosť týchto jazykov a použitia Debuggerov nám pomôže rozoberať programy na drobné a analyzovať ich zraniteľnosti aj účel. 

[NASM](https://nasm.us/)
ROZNA ARCHITEKTURA = ROZNA SADA INSTRUKCII


``` asm

## Hello World

section	.text
	global _start       ;must be declared for using gcc
_start:                     ;tell linker entry point
	mov	edx, len    ;dlzka spravy
	mov	ecx, msg    ;sprava na zapisanie
	mov	ebx, 1	    ;co s tym (stdout)
	mov	eax, 4	    ;systemove volanie (sys_write)
	int	0x80        ;zavolaj kernel a vykonaj
	mov	eax, 1	    ;systemove volanie (sys_exit)
	int	0x80        ;zavolaj kernel a vykonaj

section	.data

msg	db	'Hello, world!',0xa	;nas text ulozeny v bytoch
len	equ	$ - msg			;vypocitana dlzka naseho textu

```

``` bash 
nasm -f elf64 -o hello.o hello.asm  # skompiluje objekt file
xxd hello.o
ld -s -o hello hello.o  # zlinkuje objekt file na executable
./hello
binwalk -W hello hello.o
```

info ARCHITEKTÚRA 

### C.2 RADARE2 = SKUMANIE BINARNYCH SUBOROV A PROCESOV

**Rádio-Radare2 (R2) – Rýchly manuál pre Kali Linux** _(Pre analýzu a reverzný inžiniering binárnych súborov)_

---

### **1. Základné príkazy**

- **Info o súbore:**
    ``` bash
    rabin2 -I FILE.bin
    ```

