#### Wazuh SIEM: Základné použitie a Threat Hunting 
---  
##### 1. Čo je Wazuh? 
Wazuh je **open-source platforma** pre **monitorovanie bezpečnosti, detekciu hrozieb a compliance**. Kombinuje **SIEM, XDR, HIDS** a **log management**. Je postavený na **Elastic Stack** (Elasticsearch, Kibana) a je **100% zadarmo**. 
##### Kľúčové funkcie: 
✅ **Detekcia hrozieb v reálnom čase** (malware, útoky, anomálie). 
✅ **Monitorovanie súborov a registrov** (FIM). 
✅ **Centralizované zbieranie a analýza logov**. 
✅ **Compliance** (PCI DSS, GDPR, HIPAA, NIST). 
✅ **Aktívne reakcie** (blokovanie IP, izolácia zariadení). 
✅ **Integracia s cloudom** (AWS, Azure, Google Cloud). ---  
##### 2. Základné komponenty    

##### 3. Základné možnosti Wazuh 
##### 3.A. Monitorovanie súborov (FIM) 

Sledovanie **zmeny v súboroch** (konfigurácie, binárky, logy). 

##### 3.B. Detekcia hrozieb

Pravidlá pre detekciu **brute-force útokov, malware, podozrivých procesov**.
### 3.C. Log Management

Zbieranie a analýza **systémových a aplikačných logov**.

### 3.D. Aktívne reakcie

Automatické **blokovanie IP, izolácia zariadení, spustenie skriptov**.

### 3.E. Compliance

Podpora pre **PCI DSS, GDPR, HIPAA, NIST**.

---

## 4. Threat Hunting s Wazuh

**Threat Hunting** je **proaktívny prístup** k vyhľadávaniu skrytých hrozieb.

### 4.A. Nástroje pre Threat Hunting


	**Wazuh Kibana** Grafické rozhranie pre vyhľadávanie a analýzu udalostí.
	**Sigma Rules** Open-source pravidlá pre detekciu hrozieb.
	**OSQuery** SQL dotazy pre skúmanie systémov.
	**Elasticsearch** Pokročilé vyhľadávanie v logoch.

---

### 4.B. Príklady Threat Huntingu

#### 1. Vyhľadávanie podozrivých procesov
#### 2. Detekcia laterálneho pohybu
#### 3. Vyhľadávanie sieťových pripojení

#### 4. Použitie Sigma pravidiel

---

### 4.C. Pokročilé techniky

- **Korelácia udalostí** (napr. viaceré neúspešné prihlásenia + spustenie podozrivého procesu).
- **Machine Learning** (integracia s Elastic ML pre detekciu anomálií).

---

### 4.D. Tipy pre efektívny Threat Hunting

✅ **Definujte jasné hypotézy** (napr. "Je v sieti prítomný ransomware?"). 
✅ **Používajte Sigma a OSQuery** pre pokročilé vyhľadávanie. 
✅ **Monitorujte neobvyklé aktivity** (prihlásenia v neobvyklý čas, podozrivé procesy). 
✅ **Aktualizujte pravidlá** (Sigma, YARA). 
✅ **Dokumentujte nálezy** pre ďalšiu analýzu.

---

## 6. Záver

Wazuh je **výkonný nástroj** pre **monitorovanie bezpečnosti, detekciu hrozieb a threat hunting**. Pomocou **Kibana, Sigma pravidiel a OSQuery** môžete **proaktívne vyhľadávať hrozby** a **predchádzať útokom**. 🚀