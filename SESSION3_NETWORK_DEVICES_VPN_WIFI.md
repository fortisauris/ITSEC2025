
## 1. ROUTERS

Typicky je ROUTER zariadenie prideľujúce IP adresy a preto je na 3 sieťovej vrstve

Pokiaľ riešime malú sieť SOHO (SMALL OFFICE \ HOME OFFICE) približne do 10 zariadení tak si vystačíme s obyčajným routrom s WiFi alebo bez. 

Typicky takýto router obsahuje:
1. 4x RJ45 porty LAN
2. 1x RJ45 port WAN
3. DHCP server
4. DNS server pre LAN
5. Wifi s rôznymi bezpečnostnými protokolmi WEP, WPA1 až WPA3, WPS a pod.
6. Firewall rôznej kvality.
7. Autonómna sieť pre Hostí GUEST NETWORK
8. DMZ Demilitarizovaná zóna

Pri výbere zohľadňujeme okrem rýchlosti, množstva ENDPOINTOV a premávky Trafficu aj softvérový základ. 
OpenWRT je routerová verzia odľahčeného Linuxu a je OPEN SOURCE.
Kvalita a frekvencia UPDATOV A PATCHOV


Pre **elimináciu "Single Point of Failure" (SPoF)** v sieti je potrebné navrhnúť **redundantnú a odolnú infraštruktúru**, ktorá zabezpečí **kontinuitu prevádzky** aj v prípade zlyhania jedného zložky.

## 2. SWITCHES AND HUBS

**2.1  ACCESS LAYER**

HUB je LEGACY zariadenie = SEN KAŽDÉHO HACKERA
Typicky je SWITCH zariadenie rozdeľujúce PACKETY na Layer 2 

**2.2 DISTRIBUTION LAYER** 

MULTI LAYER SWITCH a Layer 3 Switche
Su manazovatelne switche s webovym rozhranim a ssh, ktore mozno nakonfigurovat na zrkadlenie portov, pokrocile smerovanie a pod. Su ovela drahsie a vykonnejsie ako klasicke switche.

**2.3 CORE LAYER**

SUPER SWITCHE Tbps trafficu
