FROM almalinux:8

MAINTAINER Justas Balcas <jbalcas@caltech.edu>

RUN mkdir -p /opt/snmpmon/output/

RUN yum -y install git python39 python39-pyyaml python39-devel gcc net-snmp-libs net-snmp-devel

RUN cd /opt/snmpmon/ && git clone https://github.com/sdn-sense/nsi-snmpmon
RUN cd /opt/snmpmon/nsi-snmpmon && pip3 install -r requirements.txt || exit $?
RUN cd /opt/snmpmon/nsi-snmpmon && python3 setup.py install || exit $?

COPY run-wrapper.sh /usr/local/bin/run-wrapper.sh
ENTRYPOINT ["/usr/local/bin/run-wrapper.sh"]
