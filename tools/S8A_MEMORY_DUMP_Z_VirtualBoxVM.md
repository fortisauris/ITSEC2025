### **Ďalšie možnosti získania memory dumpu z VirtualBox VM**

## **1. Úvod**

Získanie **memory dumpu** (kópie pamäte) z virtuálneho stroja (VM) vo VirtualBoxe je užitočné pre **forenznú analýzu**, **debugging**, alebo **skúmanie malware**. Existuje niekoľko metód, ako to urobiť.

---

## **2. Metóda 1: Použitie `VBoxManage`**

Najjednoduchší spôsob je použitie príkazového nástroja **`VBoxManage`**, ktorý je súčasťou VirtualBoxu.

### **Postup:**

1. **Získajte zoznam bežiacich VM**:
    
    `VBoxManage list runningvms`
    
    _(Výstupom bude zoznam VM s ich názvami a UUID.)_
    
2. **Vytvorte memory dump**:
    
    `VBoxManage debugvm <VMName|UUID> dumpvmcore --filename=C:\cesta\k\suboru\memory.dump`
    
    _(Nahradíte `<VMName|UUID>` názvom alebo UUID vašej VM a zadajte cestu, kam sa má dump uložiť.)_
    
3. **Analyzujte dump**:
    
    - Použite nástroje ako **Volatility** alebo **Rekall** na analýzu získaného dumpu.

---

## **3. Metóda 2: Použitie forenzných nástrojov vnútri VM**

Ak nemôžete použiť `VBoxManage`, môžete získať memory dump priamo z vnútra VM.

### **Pre Windows VM:**

1. **Stiahnite a spustite nástroj na získanie pamäte** (napr. **Magnet RAM Capture** alebo **FTK Imager**).
2. **Uložte dump** do súboru a skopírujte ho na hostitelský systém.

### **Pre Linux VM:**

1. **Použite `dd`** (ak je `/dev/mem` prístupný):
    
    `sudo dd if=/dev/mem of=/tmp/memory.dump bs=1M`
    
    _(Pozor: Na moderných jadrách je `/dev/mem` obmedzený, preto je lepšie použiť **LiME**.)_
    
2. **Použite LiME** (pre moderné jadrá):
    
    `sudo insmod lime.ko "path=/tmp/memory.dump format=lime"`
    
    _(Stiahnite LiME z [GitHubu](https://github.com/504ensicsLabs/LiME).)_
    
3. **Skopírujte dump** na hostitelský systém.
    

---

## **4. Metóda 3: Použitie VirtualBox Debug Mode**

Ak potrebujete detailnejšie informácie, môžete spustiť VM v **debug móde**.

### **Postup:**

1. **Spustite VM v debug móde**:
    
    `VBoxManage startvm <VMName> --debug`
    
2. **Použite externý debugger** (napr. **WinDbg** alebo **GDB**) na pripojenie k VM a získanie pamäte.
    

---

## **5. Analýza memory dumpu**

Po získaní dumpu môžete použiť nasledujúce nástroje na jeho analýzu:

Nástroj

Popis

Použitie

**Volatility**

Pythonový nástroj pre analýzu pamäte (Windows/Linux).

`python vol.py -f memory.dump imageinfo`

**Rekall**

Alternatíva k Volatility.

`rekall analyze memory.dump`

**Autopsy**

Grafický nástroj pre forenznú analýzu.

Importujte dump a analyzujte ho.

---

## **6. Časté problémy a ich riešenie**

Problém

Riešenie

`VBoxManage` nerozpoznáva názov VM

Použite **UUID** VM namiesto názvu. Získajte ho príkazom `VBoxManage list vms`.

Memory dump je poškodený

Uistite sa, že VM beží a príkaz `dumpvmcore` je správne zadaný.

Nemôžem prístupovať k `/dev/mem`

Použite **LiME** namiesto `dd`.

`VBoxManage dumpvmcore` nefunguje

Skúste aktualizovať VirtualBox alebo použiť alternatívne metódy (forenzné nástroje vnútri VM).

---

## **7. Právne a etické aspekty**

- **Súhlas**: Uistite sa, že máte **právne oprávnenie** na získanie pamäte z VM (napr. súhlas majiteľa).
- **Ochrana súkromia**: Memory dump môže obsahovať **citlivé údaje**. Zachádzajte s ním opatrne.
- **Dokumentácia**: Pre forenzné účely **dokumentujte** celý proces získavania dumpu (reťazec úschovy dôkazov).

---

## **8. Záver**

Získanie **memory dumpu** z VirtualBox VM je možné pomocou:

1. **`VBoxManage dumpvmcore`** (najjednoduchší spôsob).
2. **Forenzných nástrojov vnútri VM** (Magnet RAM Capture, LiME).
3. **Debug módu** (pre pokročilú analýzu).

Po získaní dumpu môžete použiť nástroje ako **Volatility** alebo **Rekall** na jeho analýzu. Vždy dodržujte **právne a etické zásady** pri práci s citlivými údajmi.