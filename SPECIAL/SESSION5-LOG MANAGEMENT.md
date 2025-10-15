
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

