#iot

# **OWASP IoT Top 10 – Bezpečnostné riziká internetu vecí (IoT)**

## **1. Slabé alebo defaultné heslá (Weak/Default Passwords)**

- **Problém:** Mnoho IoT zariadení používa pevne nakódované alebo jednoduché heslá (napr. `admin:admin`).
- **Rizieko:** Útočníci môžu ľahko získať prístup k zariadeniu a ovládať ho na diaľku.
- **Riešenie:**
    - Vynútiť zmenu hesla pri prvom prihlásení.
    - Používať silné, jedinečné heslá a multi-factor autentifikáciu (MFA).
    - Implementovať politiky expiracie hesiel.

---

## **2. Nezabezpečené sieťové služby (Insecure Network Services)**

- **Problém:** Otvorené a nezabezpečené sieťové porty (Telnet, FTP, HTTP) bez šifrovania.
- **Rizieko:** Odpočúvanie, útoky typu Man-in-the-Middle (MITM), vzdialené ovládanie.
- **Riešenie:**
    - Používať šifrované protokoly (SSH, HTTPS, MQTTS).
    - Zablokovať nepotrebujúe porty vo firewalli.
    - Pravidelne skenovať zariadenie na otvorené služby.

---

## **3. Nezabezpečené rozhrania (Insecure Interfaces)**

- **Problém:** Webové, mobilné alebo cloudové rozhrania bez autentifikácie alebo s chybami.
- **Rizieko:** Útočníci môžu zneužiť API alebo webové rozhrania na ovládanie zariadenia.
- **Riešenie:**
    - Implementovať silnú autentifikáciu a autorizáciu.
    - Testovať rozhrania na zranitelnosti (OWASP ZAP, Burp Suite).
    - Používať tokeny a rate limiting.

---

## **4. Chýbajúce bezpečnostné aktualizácie (Lack of Security Updates)**

- **Problém:** Výrobcovia neposkytujú aktualizácie firmware alebo opravy zraniteľností.
- **Rizieko:** Zariadenie ostáva zraniteľné na známe útoky.
- **Riešenie:**
    - Implementovať mechanizmus OTA (Over-The-Air) aktualizácií.
    - Upozorňovať používateľov na dostupné aktualizácie.
    - Podporovať zariadenia po celú dobu ich životnosti.

---

## **5. Používanie zastaralých komponentov (Use of Outdated Components)**

- **Problém:** Zastarané knižnice, OS alebo firmware so známymi zraniteľnosťami.
- **Rizieko:** Exploitácie známych chýb (napr. Heartbleed, Shellshock).
- **Riešenie:**
    - Pravidelne aktualizovať všetky komponenty.
    - Používať nástroje na skenovanie zraniteľností (Nessus, OpenVAS).

---

## **6. Nedostatočná ochrana súkromných údajov (Insufficient Privacy Protection)**

- **Problém:** Zariadenia zbierajú a ukladajú citlivé údaje (lokalizácia, zdravotné údaje) bez šifrovania.
- **Rizieko:** Únik údajov, porušenie GDPR.
- **Riešenie:**
    - Šifrovať uložené aj prenášané údaje.
    - Minimalizovať zbieranie údajov.
    - Implementovať anonymizáciu údajov.

---

## **7. Nezabezpečené prenосы a úložiská dát (Insecure Data Transfer and Storage)**

- **Problém:** Údaje sú prenášané alebo uložené v nešifrovanej podobe.
- **Rizieko:** Odpočúvanie, krádež alebo manipulácia s dátami.
- **Riešenie:**
    - Používať šifrovanie (TLS, AES).
    - Overovať integritu dát (digitálne podpisy, hashovacie funkcie).

---

## **8. Nedostatočná správa zariadení (Lack of Device Management)**

- **Problém:** Chýbajúce mechanizmy na vzdialenú správu, monitorovanie alebo deaktiváciu zariadení.
- **Rizieko:** Strata kontroly nad zariadením, útoky z vnútra siete.
- **Riešenie:**
    - Implementovať MDM (Mobile Device Management) riešenia.
    - Umožniť vzdialenú deaktiváciu zariadenia.
    - Vedenie logov a monitorovanie aktivít.

---

## **9. Nedostatočné fyzické zabezpečenie (Insufficient Physical Security)**

- **Problém:** Útočník môže fyzicky prístupom k zariadeniu extrahovať údaje alebo manipulovať s firmware.
- **Rizieko:** Únik citlivých údajov, manipulácia s funkciami zariadenia.
- **Riešenie:**
    - Používať bezpečné bootovanie (Secure Boot).
    - Chrániť fyzické rozhrania (UART, JTAG).
    - Implementovať detekciu manipulácie (tamper detection).

---

## **10. Nedostatočná ochrana proti útokom (Lack of Protection Mechanisms)**

- **Problém:** Chýbajúce ochrany proti DDoS, brute-force alebo fyzickým útokom.
- **Rizieko:** Znefunkčnenie zariadenia, zneužitie v botnetoch.
- **Riešenie:**
    - Implementovať ochranu proti brute-force (napr. Fail2Ban).
    - Používať IDS/IPS (Intrusion Detection/Prevention Systems).
    - Šifrovať firmware a použiť digitálne podpisy.

---

### **Záver**

Bezpečnosť IoT zariadení je **komplexný proces**, ktorý vyžaduje kombináciu technických opatrení, pravidelných aktualizácií a povedenia používateľov. Dodržiavaním **OWASP IoT Top 10** môžete významne znížiť riziká a chrániť svoje zariadenia pred útočníkmi.

**Ďalšie zdroje:**

- [OWASP IoT Project](https://owasp.org/www-project-internet-of-things/)
- [IoT Security Foundation](https://www.iotsecurityfoundation.org/)