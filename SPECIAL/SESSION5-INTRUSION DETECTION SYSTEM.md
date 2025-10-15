

SURICATA je oblubeny open source IDS/IPS system, ktory loguje a hlasi 

``` bash
sudo apt-get update
sudo apt-get install suricata jq
```

SURICATA SA UPDATUJE viac ako 37000 RULES na alerty

``` bash
sudo suricata-update
```

SURICATA SA RESTARTUJE A ZISTUJEME CI BEZI
``` bash
systemctl restart suricata.service
systemctl status suricata.service
```


TAKTO MOZEME VIDIET ZAKLADNE VYSTUPY A LOGY SURICATY
``` bash
tail -f /var/log/suricata/suricata.log
tail -f /var/log/suricata/stats.log
tail -f /var/log/suricata/fast.log
```

SURICATA VIE ALE OVELA VIAC - pomocou jq, vieme vyhladavat vo vystupoch v datovom formate json a vyhodnocovat alerty a dalsie udalosti z logov

``` bash
sudo tail -f  /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats")|.stats.capture.kernel_packets'
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats")'