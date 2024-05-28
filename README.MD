# NSI SNMPMonitor

This is a simple SNMP monitor that uses the Python3 SNMP library to monitor a device and expose SNMP Metrics in Prometheus format. It also runs a simple web server to expose the metrics and authenticate the user based on the user's certificate.

## How to run

To run the SNMPMonitor, you need to have a valid certificate and key. You can generate a certificate using Let's Encrypt (https://letsencrypt.org) or any other certificate authority of your choice.

In case of Docker, you can run the following command to start the SNMPMonitor:

```bash
cd examples/docker/
# 1. Please make sure to update cert.pem and privkey.pem with your certificate and key inside conf/ directory
# 2. Please make sure to update the SNMPMonitor configuration inside conf/snmp-mon.yaml
# 3. Run the following command to start the SNMPMonitor
./run.sh -i latest
```

In case of Kubernetes, you can run the following command to start the SNMPMonitor:

```bash
cd examples/kubernetes/
# 1. Please make sure to update cert.pem and privkey.pem with your certificate inside the kube-template.yaml file. If you use Cert-Manager, you can use the provided certificate secret.
# 2. Please make sure to update the SNMPMonitor configuration inside the kube-template.yaml file too.
# 3. Please make sure you change namespace to your desired namespace.
# 4. Run the following command to start the SNMPMonitor
kubectl apply -f kube-template.yaml
```
