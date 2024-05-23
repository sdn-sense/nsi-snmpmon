 FROM almalinux:8

MAINTAINER Justas Balcas <jbalcas@caltech.edu>

RUN yum -y install git python39 python39-pyyaml python39-devel gcc net-snmp-libs net-snmp-devel openssl-devel httpd httpd-devel python39-mod_wsgi mod_ssl cronie python3-pyOpenSSL fetch-crl && yum clean all

RUN mkdir -p /opt/snmpmon/output/ & \
    mkdir -p /etc/grid-security/certificates & \
    mkdir -p /var/log/supervisor & \
    mkdir -p /etc/supervisord.d/ & \
    rm -f /etc/httpd/conf.d/ssl.conf

RUN rpm -i https://repo.opensciencegrid.org/osg/23-main/el8/release/x86_64/osg-ca-certs-1.118-1.osg23.el8.noarch.rpm

# Install pip, supervisor and superlance (upgrade it)
RUN pip3 install --no-cache-dir --upgrade setuptools pip && \
    pip3 install --no-cache-dir supervisor superlance

WORKDIR /opt/snmpmon/
RUN git clone https://github.com/sdn-sense/nsi-snmpmon
WORKDIR /opt/snmpmon/nsi-snmpmon
RUN pip3 install -r requirements.txt || exit $?
RUN python3 setup.py install || exit $?
# Copy all supervisord fils
COPY packaging/etc/supervisord.conf /etc/
COPY packaging/etc/supervisord.d/* /etc/supervisord.d/

EXPOSE 80 443

CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf"]
