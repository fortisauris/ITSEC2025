#git

Práca s programom git je podmienkou schopností každého proigramátora a IT špecialistu. Umožňuje sledovať zmeny v čase a ukladať cenné programy a nastavenia inkrementálne mimo počítača. Môžu to byť napríklad nastavenia, zoznamy nainštalovaných programov a pod.

Repozitár by nemal obsahovať citlivé a osobné údaje.

Github.com účet je zadarmo Repozitáre sú verejné a súkromné
Repozitár môžete hostovať aj na iných službách

https://git-scm.com/install/windows

## 1. KLONOVANIE REPOZITÁRA



Základné použitie je:

``` bash
git clone https:\\github.com\fortisauris\ITSEC2025.git
```

Týmto príkazom stiahneme repozitár zo stránky kde sú uložené programy... github.com, ktorá je vlastnená Microsoftom

Programy môžeme spúšťať, inštalovať a používať v súlade s ich LICENČNOU ZMLUVOU.

Použitie programu je popísané v separátnej dokumentácií a v README súbore.

## 2. INICIOVANIE VLASTNÉHO REPOZITÁRA

V adresári, ktorého zmeny chceme začať sledovať spustíme:

``` bash
git init
```

## 3. PRIDÁVANIE ZMIEN

``` bash
git add *  # pridaj vsetky nove a modifikovane zmeny do commitu

git commit -m "popis co si spravil"  # vytvor balik zmien commit a priprav na ososlanie

git push  # potlac zmeny do repozitara ak mas opravnenie

``` 



4. SŤAHOVANIE ZMIEN DO NAKLONOVANÉHO REPOZITÁRA

``` bash
git pull  # stiahni zmeny z repozitara do lokalneho adresara
```

5. VYMAZANIE ZMIEN V LOKÁLNOM REPOZITÁRI

``` bash
git reset --hard  # vymaz vsetky zmeny a vrat sa k povodnej poslednej stiahnutej verzii
```