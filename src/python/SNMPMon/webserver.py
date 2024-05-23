#!/usr/bin/env python3
"""
    WebServer for SNMP Data Exposure in Prometheus format

Authors:
  Justas Balcas jbalcas (at) caltech.edu

Date: 2022/11/21
"""
import os
import os.path
import time
from datetime import datetime
from datetime import timezone
from prometheus_client import generate_latest, CollectorRegistry
from prometheus_client import Gauge
from SNMPMon.utilities import getStreamLogger
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import isValFloat
from SNMPMon.utilities import getUTCnow
from SNMPMon.utilities import getConfig


class Authorize():

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.allowedCerts = []
        self.loadAuthorized()

    def loadAuthorized(self):
        """Load all authorized users for FE from git."""
        for item in self.config.get('authorize_dns', []):
            self.allowedCerts.append(item)

    @staticmethod
    def getCertInfo(environ):
        """Get certificate info."""
        out = {}
        for key in ['SSL_CLIENT_V_REMAIN', 'SSL_CLIENT_S_DN', 'SSL_CLIENT_I_DN', 'SSL_CLIENT_V_START', 'SSL_CLIENT_V_END']:
            if key not in environ:
                self.logger.debug('Request without certificate. Unauthorized')
                raise Exception('Unauthorized access. Request without certificate.')
        out['subject'] = environ['SSL_CLIENT_S_DN']
        out['notAfter'] = int(datetime.strptime(environ['SSL_CLIENT_V_END'], "%b %d %H:%M:%S %Y %Z").timestamp())
        out['notBefore'] = int(datetime.strptime(environ['SSL_CLIENT_V_START'], "%b %d %H:%M:%S %Y %Z").timestamp())
        out['issuer'] = environ['SSL_CLIENT_I_DN']
        out['fullDN'] = f"{out['issuer']}{out['subject']}"
        return out

    def checkAuthorized(self, environ):
        """Check if user is authorized."""
        if environ['CERTINFO']['fullDN'] in self.allowedCerts:
            return self.allowedCerts[environ['CERTINFO']['fullDN']]
        self.logger.info(f"User DN {environ['CERTINFO']['fullDN']} is not in authorized list. Full info: {environ['CERTINFO']}")
        raise Exception(f"User DN {environ['CERTINFO']['fullDN']} is not in authorized list. Full info: {environ['CERTINFO']}")

    def validateCertificate(self, environ):
        """Validate certification validity."""
        timestamp = int(datetime.now(timezone.utc).timestamp())
        if 'CERTINFO' not in environ:
            raise Exception('Certificate not found. Unauthorized')
        for key in ['subject', 'notAfter', 'notBefore', 'issuer', 'fullDN']:
            if key not in list(environ['CERTINFO'].keys()):
                self.logger.info(f'{key} not available in certificate retrieval')
                raise Exception('Unauthorized access')
        # Check time before
        if environ['CERTINFO']['notBefore'] > timestamp:
            self.logger.info(f"Certificate Invalid. Current Time: {timestamp} NotBefore: {environ['CERTINFO']['notBefore']}")
            raise Exception(f"Certificate Invalid. Full Info: {environ['CERTINFO']}")
        # Check time after
        if environ['CERTINFO']['notAfter'] < timestamp:
            self.logger.info(f"Certificate Invalid. Current Time: {timestamp} NotAfter: {environ['CERTINFO']['notAfter']}")
            raise Exception(f"Certificate Invalid. Full Info: {environ['CERTINFO']}")
        # Check DN in authorized list
        return self.checkAuthorized(environ)

class Frontend(Authorize):

    def __init__(self):
        self.config = getConfig('/etc/snmp-mon.yaml')
        self.logger = getStreamLogger(**self.config.get('logParams', {}))
        self.headers = [('Cache-Control', 'no-cache, no-store, must-revalidate'),
                        ('Pragma', 'no-cache'), ('Expires', '0'), ('Content-Type', 'text/plain')]
        Authorize.__init__(self, self.config, self.logger)

    def metrics(self):
        """Return metrics view"""
        registry = self.__cleanRegistry()
        self.__getSNMPData(registry)
        data = generate_latest(registry)
        return iter([data])

    @staticmethod
    def __cleanRegistry():
        """Get new/clean prometheus registry."""
        registry = CollectorRegistry()
        return registry

    def __getLatestOutput(self):
        fName = os.path.join(self.config['tmpdir'], 'snmp-multiworker-latest.json')
        retryCount = 0
        while retryCount < 5:
            try:
                out = getFileContentAsJson(fName)
                if out:
                    return out
            except Exception as ex:
                self.logger.debug(f'Got Exception: {ex}')
            retryCount += 1
            time.sleep(0.2)
        return {}

    def __getSNMPData(self, registry):
        """Add SNMP Data to prometheus output"""
        # Here get info from DB for switch snmp details
        output = self.__getLatestOutput()
        runtimeInfo = Gauge('service_runtime_timestamp', 'Service Runtime Timestamp', ['servicename'], registry=registry)
        if not output:
            return
        for devname, devout in output.items():
            if 'snmp_scan_runtime' not in devout:
                runtimeInfo.labels(**{'servicename': 'SNMPMonitoring', 'hostname': devname}).set(0)
                self.logger.info('SNMP Scan Runtime does not have runtime details. Something wrong with SNMPRuntime Thread')
                # We need runtime timestamp. Anything older than 5mins, ignored. It shows that there is an issue with SNMPMon Thread.
                return
            if int(devout['snmp_scan_runtime']) < int(getUTCnow() - 300):
                runtimeInfo.labels(**{'servicename': 'SNMPMonitoring', 'hostname': devname}).set(devout['snmp_scan_runtime'])
                self.logger.info('SNMP Scan Runtime is older than 5 mins. Something wrong with SNMPRuntime Thread')
                return
            snmpGauge = Gauge('interface_statistics', 'Interface Statistics', ['ifDescr', 'ifType', 'ifAlias', 'hostname', 'Key'], registry=registry)
            for hostname, vals in devout.items():
                if hostname == 'snmp_scan_runtime':
                    runtimeInfo.labels(**{'servicename': 'SNMPMonitoring', 'hostname': hostname}).set(vals)
                    continue
                for _idincr, val in vals.items():
                    keys = {'ifDescr': val.get('ifDescr', ''), 'ifType': val.get('ifType', ''), 'ifAlias': val.get('ifAlias', ''), 'hostname': hostname}
                    for key1, val1 in val.items():
                        if isValFloat(val1):
                            keys['Key'] = key1
                            snmpGauge.labels(**keys).set(val1)
                # TODO Add mac addresses to prometheus output

    def maincall(self, environ, start_response):
        """Main call for WSGI"""
        # Certificate must be valid
        try:
            environ["CERTINFO"] = self.getCertInfo(environ)
            self.validateCertificate(environ)
        except Exception as ex:
            start_response('401 Unauthorized', self.headers)
            return [bytes(f'Unauthorized access. {str(ex)}', "UTF-8")]
        if environ['PATH_INFO'] == '/metrics':
            start_response('200 OK', self.headers)
            return self.metrics()
        start_response('404 Not Found', self.headers)
        return iter([b'Not Found'])
