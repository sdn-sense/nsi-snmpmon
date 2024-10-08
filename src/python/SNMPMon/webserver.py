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
import json
from datetime import datetime
from datetime import timezone
from prometheus_client import generate_latest, CollectorRegistry
from prometheus_client import Gauge
from prometheus_client import Info
from SNMPMon.utilities import getStreamLogger
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import dumpFileContentAsJson
from SNMPMon.utilities import isValFloat
from SNMPMon.utilities import getUTCnow
from SNMPMon.utilities import getConfig


class Authorize():
    """Authorize class for SNMPMon. Authorize users based on certificate."""
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.allowedCerts = []
        self.allowedUrls = {}
        self.loadAuthorized()
        self.generateUrls()

    def generateUrls(self):
        """Generate supported urls"""
        if not self.config.get('snmpMon', {}):
            self.logger.error("No devices to monitor")
            return
        for device in self.config.get('snmpMon', {}).keys():
            self.allowedUrls[f"/{device}/metrics"] = device

    def loadAuthorized(self):
        """Load all authorized users for FE from git."""
        for item in self.config.get('authorize_dns', []):
            self.allowedCerts.append(item)

    def getCertInfo(self, environ):
        """Get certificate info."""
        out = {}
        for key in ['SSL_CLIENT_V_REMAIN', 'SSL_CLIENT_S_DN',
                    'SSL_CLIENT_I_DN', 'SSL_CLIENT_V_START', 'SSL_CLIENT_V_END']:
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
            return True
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
    """Frontend for SNMPMon. Exposes SNMP Data in Prometheus format."""
    def __init__(self):
        self.config = getConfig('/etc/snmp-mon.yaml')
        self.logger = getStreamLogger(**self.config.get('logParams', {}))
        self.headers = [('Cache-Control', 'no-cache, no-store, must-revalidate'),
                        ('Pragma', 'no-cache'), ('Expires', '0'), ('Content-Type', 'text/plain')]
        Authorize.__init__(self, self.config, self.logger)

    def metrics(self, host = None):
        """Return metrics view"""
        registry = self.__cleanRegistry()
        self.__getSNMPData(registry, host)
        data = generate_latest(registry)
        return iter([data])

    def __getinputdata(self, environ):
        """Get input data from request"""
        try:
            data = environ['wsgi.input'].read(int(environ['CONTENT_LENGTH']))
            data = data.decode("utf-8")
            data = json.loads(data)
            return data
        except Exception as ex:
            raise Exception(f"Error: {ex}") from ex

    def __saveRequest(self, data):
        """Save request to httpdir"""
        uuid = data.get('uuid', '')
        fName = os.path.join(self.config['httpdir'], f"snmpmon-{uuid}.json")
        dumpFileContentAsJson(self.config, fName, data, True)

    def submitCheck(self, environ, start_response):
        """Check if request is submitted"""
        try:
            data = self.__getinputdata(environ)
            uuid = data.get('uuid', '')
            fName = os.path.join(self.config['httpdir'], f"snmpmon-{uuid}.json")
            if os.path.exists(fName):
                start_response('200 OK', self.headers)
                return [bytes(f'File {fName} already exists.', "UTF-8")]
            start_response('404 Not Found', self.headers)
            return [bytes(f'File {fName} does not exist.', "UTF-8")]
        except Exception as ex:
            raise Exception(f"Error: {ex}") from ex

    def submitRequest(self, environ):
        """Submit request to SNMPMon and save in httpdir"""
        # Get submitted data and load it as json
        try:
            data = self.__getinputdata(environ)
            self.__saveRequest(data)
            return [bytes(f'Request submitted successfully. UUID: {data.get("uuid", "")}', "UTF-8")]
        except Exception as ex:
            raise Exception(f"Error: {ex}") from ex

    def submitDelete(self, environ, start_response):
        """Delete submitted request"""
        try:
            data = self.__getinputdata(environ)
            uuid = data.get('uuid', '')
            fName = os.path.join(self.config['httpdir'], f"snmpmon-{uuid}.json")
            if os.path.exists(fName):
                data['stopRun'] = True
                self.__saveRequest(data)
                start_response('200 OK', self.headers)
                return [bytes(f'File {fName} deleted successfully.', "UTF-8")]
            start_response('404 Not Found', self.headers)
            return [bytes(f'File {fName} does not exist.', "UTF-8")]
        except Exception as ex:
            raise Exception(f"Error: {ex}") from ex

    def submitGet(self, environ, start_response):
        """Get submitted request"""
        try:
            data = self.__getinputdata(environ)
            uuid = data.get('uuid', '')
            fName = os.path.join(self.config['httpdir'], f"snmpmon-{uuid}.json")
            if os.path.exists(fName):
                start_response('200 OK', self.headers)
                return [bytes(str(getFileContentAsJson(fName)), "UTF-8")]
            start_response('404 Not Found', self.headers)
            return [bytes(f'File {fName} does not exist.', "UTF-8")]
        except Exception as ex:
            raise Exception(f"Error: {ex}") from ex

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

    def __addMacInfo(self, macVals, devname, macState):
        """Add Mac Info to prometheus output"""
        for _cntr, vlandict in macVals.items():
            for vlan, macs in vlandict.items():
                incr = 0
                added = []
                for mac in macs:
                    # Secure from duplicate entries;
                    if mac.lower() in added:
                        continue
                    added.append(mac.lower())
                    macState.labels(**{'vlan': vlan, 'hostname': devname, 'incr': str(incr)}).info({'macaddress': mac.lower()})
                    incr += 1

    def __addGeneralInfo(self, vals, devname, snmpGauge):
        """Add General Info to prometheus output"""
        for _cntr, val in vals.items():
            keys = {'ifDescr': val.get('ifDescr', ''), 'ifType': val.get('ifType', ''),
                    'ifAlias': val.get('ifAlias', ''), 'hostname': devname}
            for key1, val1 in val.items():
                if isValFloat(val1):
                    keys['Key'] = key1
                    snmpGauge.labels(**keys).set(val1)

    def __getSNMPData(self, registry, host = None):
        """Add SNMP Data to prometheus output"""
        # Here get info from DB for switch snmp details
        output = self.__getLatestOutput()
        runtimeInfo = Gauge('service_runtime_timestamp', 'Service Runtime Timestamp', ['servicename', 'hostname'], registry=registry)
        snmpGauge = Gauge('interface_statistics', 'Interface Statistics',
                          ['ifDescr', 'ifType', 'ifAlias', 'hostname', 'Key'], registry=registry)
        macState = Info("mac_table", "Mac Address Table", labelnames=["vlan", "hostname", "incr"], registry=registry)
        if not output:
            return
        for devname, devout in output.items():
            if host and devname != host:
                continue
            if 'snmp_scan_runtime' not in devout:
                runtimeInfo.labels(**{'servicename': 'SNMPMonitoring', 'hostname': devname}).set(0)
                self.logger.info('SNMP Scan Runtime does not have runtime details. Something wrong with SNMPRuntime Thread')
                # We need runtime timestamp. Anything older than 5mins, ignored. It shows that there is an issue with SNMPMon Thread.
                return
            if int(devout['snmp_scan_runtime']) < int(getUTCnow() - 300):
                runtimeInfo.labels(**{'servicename': 'SNMPMonitoring', 'hostname': devname}).set(devout['snmp_scan_runtime'])
                self.logger.info('SNMP Scan Runtime is older than 5 mins. Something wrong with SNMPRuntime Thread')
                return
            for hostname, vals in devout.items():
                if hostname == 'snmp_scan_runtime':
                    runtimeInfo.labels(**{'servicename': 'SNMPMonitoring', 'hostname': devname}).set(vals)
                elif hostname == "macs":
                    self.__addMacInfo(vals, devname, macState)
                else:
                    self.__addGeneralInfo(vals, devname, snmpGauge)

    def _submitRequest(self, environ, start_response):
        """Submit Request check"""
        # Accept post method and save to httpdir config location
        if environ['REQUEST_METHOD'] == 'POST':
            if environ['SCRIPT_URL'] == '/submit':
                start_response('200 OK', self.headers)
                return self.submitRequest(environ)
            # Allow to check if there is a submitted request
            if environ['SCRIPT_URL'] == '/submitcheck':
                return self.submitCheck(environ, start_response)
            # Allow to delete submitted request
            if environ['SCRIPT_URL'] == '/submitdelete':
                return self.submitDelete(environ, start_response)
            # Get content of submitted request
            if environ['SCRIPT_URL'] == '/submitget':
                return self.submitGet(environ, start_response)
        start_response('404 Not Found', self.headers)
        return iter([b'Not Found'])

    def maincall(self, environ, start_response):
        """Main call for WSGI"""
        # Certificate must be valid
        try:
            environ["CERTINFO"] = self.getCertInfo(environ)
            self.validateCertificate(environ)
        except Exception as ex:
            start_response('401 Unauthorized', self.headers)
            return [bytes(f'Unauthorized access. {str(ex)}', "UTF-8")]
        if environ['SCRIPT_URL'] == '/metrics':
            start_response('200 OK', self.headers)
            return self.metrics()
        # Accept post method and save to httpdir config location
        if environ['SCRIPT_URL'].startswith('/submit'):
            return self._submitRequest(environ, start_response)
        if environ['SCRIPT_URL'] in self.allowedUrls:
            start_response('200 OK', self.headers)
            return self.metrics(self.allowedUrls[environ['SCRIPT_URL']])
        start_response('404 Not Found', self.headers)
        return iter([b'Not Found'])
