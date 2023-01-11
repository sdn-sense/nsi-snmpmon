docker run \
       -dit --name nsi-snmpmon \
       -v $(pwd)/config/config.yaml:/etc/snmp-mon.yaml \
       --net=host \
       sdnsense/nsi-snmpmon:latest
