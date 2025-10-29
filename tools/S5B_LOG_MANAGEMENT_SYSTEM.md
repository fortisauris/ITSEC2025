
LOG MANAGEMENT je softver, ktory zbiera logy a centralne ich uklada na bezpecnom serveri.

Utocnici tak nevedia manipulovat zaznamy v logoch a tym zbierame informacie o nich a ich aktivitach pre lepsie pochopenie incidentu a jeho forenznu analyzu. 

SYSLOG-NG je Open-Source riesenie pre Linux servery a endpointy. Pokial chcete zbierat data z Windows Endpointov a serverov musite siahnut po platenej verzii.

sudo apt-get install syslog-ng

syslog-ng -version

>[!info] ALTERNATIVA: Greylog, 


# KONFIGURACIA 

SERVER CONFIG>/etc/syslog-ng/basic.conf

Pridaj riadok na koniec syslog-ng.conf

```  server

# basic server configuration

# source of logs

source lan_nodes {
	network (
	ip("0.0.0.0")
	transport("tcp")
	port(5140)
	);
};

destination local_msg {
	file( "/var/log/messages" );
};

log { source(lan_nodes); destination(local_msg); };

```

>[! info ]
>KONTROLA SYNTAXU
> ``` syslog-ng --syntax-only ```
> ``` syslog-ng -Fdev ```


#### RESTARTUJ SERVER
``` bash
systemctl restart syslog-ng.service
```

Teraz sa mozeme pustit do konfiguracie KLIENTA:

``` client

#basic client configuration

# source s_authlog {
file("/var/log/auth.log")
};

# destination
destination d_logserver {
	network(
	"IP SERVER")
	transport('tcp')
	port(5140)
);
};

# log
log {
	source(s_authlog);
	destination(d_logserver);
};
```

#### RESTARTUJ SERVER
``` bash
systemctl restart syslog-ng.service
```


> [! warning]
> Tato konfiguracia nepouziva ziadne sifrovanie. Na ostru prevadzku potrebujeme KLUCE A CERTIFIKATY aby sa prenasali data zasifrovane cez TLS (TRANSPORT LAYER SECURITY )!!!



## **Konfigurácia Syslog-NG s TLS Šifrovaním pre Log Management**

Tento návod popisuje, ako nastaviť **Syslog-NG** tak, aby **klienti (Linux/Windows) odosielali logy na centrálny server** cez **šifrované TLS spojenie**. Týmto spôsobom zabezpečíte, že útočníci nebudú schopní manipulovať s logmi alebo ich odpočúvať.

---

## **1. Inštalácia Syslog-NG**

### **Na Serveri (Linux)**

 ``` bash
 sudo apt-get update sudo apt-get install syslog-ng syslog-ng-core syslog-ng --version
 ```

### **Na Klientovi (Linux)**


``` bash
sudo apt-get update sudo apt-get install syslog-ng syslog-ng-core
```


---

**Alternatívne riešenia:**

- **Graylog** (Open-Source, podporuje Windows klientov)
- **Fluentd** (Open-Source, flexibilné)
- **ELK Stack** (Elasticsearch, Logstash, Kibana)

---

## **2. Generovanie Kľúčov a Certifikátov pre TLS**

Pre zabezpečenie komunikácie medzi klientom a serverom použijeme **TLS šifrovanie**. Potrebujeme vygenerovať:

- **CA (Certificate Authority)** – certifikačná autorita
- **Serverový certifikát** – pre Syslog-NG server
- **Klientské certifikáty** – pre každého klienta

---

### **2.1. Inštalácia OpenSSL**

 

``` bash
sudo apt-get install openssl
```

---

### **2.2. Generovanie CA (Certifikačná Autorita)**

1. Vytvorte adresár pre certifikáty:
    
     Copy
    ``` bash
    mkdir -p /etc/syslog-ng/ca cd /etc/syslog-ng/ca
    ```
    ```
1
1. Generujte **súkromný kľúč CA**:

    ``` bash 
    openssl genrsa -out ca.key 4096
    ```
2. Generujte **certifikát CA**:
    
    ``` bash
    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=MySyslogCA"`
```
```
```

### **2.3. Generovanie Serverového Certifikátu**

1. Generujte **súkromný kľúč pre server**:
    
    ``` bash
    openssl genrsa -out server.key 2048
    ```
    
2. Generujte **CSR (Certificate Signing Request)**:
    

``` bash
    `openssl req -new -key server.key -out server.csr -subj "/CN=syslog-server.example.com"
```
    
3. Podpíšte certifikát pomocou CA:
    
    
    `openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650`
    

---

### **2.4. Generovanie Klientského Certifikátu**

1. Generujte **súkromný kľúč pre klienta**:
    
    ``` bash
    openssl genrsa -out client.key 2048
    ```
    
2. Generujte **CSR pre klienta**:
``` bash
    openssl req -new -key client.key -out client.csr -subj "/CN=syslog-client.example.com"`
    
```
1. Podpíšte certifikát pomocou CA:
    
``` bash
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650
```    

---

### **2.5. Kopírovanie Certifikátov**

- **Na server** skopírujte:
    ``` bash
    sudo cp ca.crt /etc/syslog-ng/ca/ 
    sudo cp server.key /etc/syslog-ng/ca/ 
    sudo cp server.crt /etc/syslog-ng/ca/`
    
```
- **Na klienta** skopírujte:
    
	``` bash
    sudo cp ca.crt /etc/syslog-ng/ca/ 
    sudo cp client.key /etc/syslog-ng/ca/ 
    sudo cp client.crt /etc/syslog-ng/ca/
	```

---

## **3. Konfigurácia Syslog-NG Servera**

Upravte konfiguračný súbor `/etc/syslog-ng/syslog-ng.conf` na **serveri**:

 
``` bash
@version: 3.38 

# Zariadenie pre ukladanie logov destination d_local {     
	file("/var/log/messages"); 
}; 

# Zdroj pre prijímanie logov cez TLS source s_network_tls {     
	network(         
		ip("0.0.0.0")         
		transport("tls")         
		port(6514)         
		tls(             
			key-file("/etc/syslog-ng/ca/server.key")             
			cert-file("/etc/syslog-ng/ca/server.crt")             
			ca-dir("/etc/syslog-ng/ca/")             
			peer-verify(required-trusted)         
		)     
	); 
}; 

# Logovacie pravidlo log {     
	source(s_network_tls);     
	destination(d_local); };`
```
---

**Kontrola syntaxu:**

``` bash
syslog-ng --syntax-only
```

---

**Restartujte servis:**

``` bash
sudo systemctl restart syslog-ng
```

---

**Povolte port 6514 v firewalli:**

``` bash
sudo ufw allow 6514/tcp
```

---

## **4. Konfigurácia Syslog-NG Klienta**

Upravte konfiguračný súbor `/etc/syslog-ng/syslog-ng.conf` na **klientovi**:


``` bash
@version: 3.38 

# Zdroj pre lokálne logy source s_local {     
	file("/var/log/auth.log");     
	file("/var/log/syslog"); }; 
	
	# Cieľ pre odosielanie logov cez TLS destination d_server {     
	network(         
		"IP_SERVERA"         
		transport("tls")         
		port(6514)         
		tls(             
			key-file("/etc/syslog-ng/ca/client.key")             
			cert-file("/etc/syslog-ng/ca/client.crt")             
			ca-dir("/etc/syslog-ng/ca/")             
			peer-verify(required-trusted)         
		)     
	); 
}; 

# Logovacie pravidlo log {     
	source(s_local);     
	destination(d_server); 
};
```
---

**Kontrola syntaxu:**


``` bash
syslog-ng --syntax-only
```

---

**Restartujte servis:**

``` bash
sudo systemctl restart syslog-ng
````

---

## **5. Overenie Funkčnosti**

### **Na Serveri**

Skontrolujte, či prichádzajú logy:

``` bash
tail -f /var/log/messages
````

### **Na Klientovi**

Skontrolujte, či sa logy odosielajú:

``` bash
logger "Testovacia sprava"
```

---

**Ak logy neprichádzajú:**

- Skontrolujte **firewall** na serveri a klientovi.
- Skontrolujte **syntax konfiguračných súborov**.
- Skontrolujte, či sú **certifikáty správne nainštalované**.

---

## **6. Konfigurácia Windows Klientov**

Pre Windows klientov potrebujete **platnú verziu Syslog-NG** alebo alternatívne riešenie ako **NXLog** alebo **Winlogbeat**.

### **Inštalácia NXLog (Open-Source Alternatíva WINDOWS)**

1. Stiahnite a nainštalujte [NXLog](https://nxlog.co/).
2. Upravte konfiguračný súbor `C:\Program Files (x86)\nxlog\conf\nxlog.conf`:
    
    
    ``` powershell
    <Extension _syslog>
         Module  xm_syslog 
	</Extension> 
	
	<Input in>     
		Module  im_msvistalog 
	</Input> 
	<Output out>     
		Module  om_ssl     
		Host    IP_SERVERA     
		Port    6514     
		CAFile  C:\certs\ca.crt     
		CertFile C:\certs\client.crt     
		CertKeyFile C:\certs\client.key     
		AllowUntrusted TRUE 
	</Output> 
	<Route 1>     
		Path    in => out 
	</Route>`
    ```
    
3. Skopírujte certifikáty do `C:\certs\`.
4. Restartujte službu NXLog:
    

    
    `Restart-Service nxlog`
    

---

## **7. Bezpečnostné Tipy**

1. **Omezte prístup** k portu 6514 len pre dôveryhodné IP adresy.
2. **Pravidelne kontrolujte logy** na serveri.
3. **Aktualizujte certifikáty** každý rok.
4. **Používajte silné heslá** pre súkromné kľúče.

---

**Poznámka:** Ak potrebujete **zbierať logy z Windows**, odporúčam použiť **NXLog** alebo **Winlogbeat** (súčasť ELK Stacku).