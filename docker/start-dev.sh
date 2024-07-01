
echo "Dont forget to update the snmp-mon.yaml file with the correct parameters"
echo "Dont forget to update the cert and privkey file with certificates"

docker run \
  -dit --name nsi-snmpmon \
  -v $(pwd)/../:/opt/devnsisnmpmon/:rw \
  -v $(pwd)/../config/snmp-mon.yaml:/etc/snmp-mon.yaml \
  -v $(pwd)/cert.pem:/etc/httpd/certs/cert.pem:ro \
  -v $(pwd)/privkey.pem:/etc/httpd/certs/privkey.pem:ro \
  --restart always \
  -e LISTEN_SNMPMON_PORT=8443 \
  nsi-snmpmon
