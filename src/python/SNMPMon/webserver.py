#!/usr/bin/env python3
"""
    WebServer for SNMP Data Exposure in Prometheus format

Authors:
  Justas Balcas jbalcas (at) caltech.edu

Date: 2022/11/21
"""
import os
import time
from prometheus_client import generate_latest, CollectorRegistry
from prometheus_client import Enum, Info, CONTENT_TYPE_LATEST
from prometheus_client import Gauge
import cherrypy
from SNMPMon.utilities import getConfig
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import isValFloat
from SNMPMon.utilities import getUTCnow

class HTTPExpose():
    def __init__(self, config, logger=None):
        super().__init__()
        self.config = config
        self.logger = getTimeRotLogger(**config['logParams'])

    def startwork(self):
        """Start Cherrypy Worker"""
        cherrypy.server.socket_host = '0.0.0.0'
        cherrypy.quickstart(CherryPyThread(self.config, self.logger))


class CherryPyThread():
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    @cherrypy.expose
    def index(self):
        """Index Page"""
        return "Hello world!. Looking for something? :)"

    @staticmethod
    def __cleanRegistry():
        """Get new/clean prometheus registry."""
        registry = CollectorRegistry()
        return registry

    def __getLatestOutput(self):
        fName = os.path.join(self.config['tmpdir'], 'snmp-out-latest.json')
        retryCount = 0
        while retryCount < 5:
            try:
                out = getFileContentAsJson(fName)
                if out:
                    return out
            except Exception as ex:
                self.logger.debug('Got Exception: %s' % ex)
            retryCount += 1
            time.sleep(0.2)
        return {}

    def __includeFilter(self, keys):
        """
        filterRules:
          dellos9_s0:
            operator: 'and'
            filters:
              Key: 'ifAdminStatus'
              ifDescr: ["hundredGigE 1/21", "Vlan 100"]
        where keys:
        {'ifDescr': 'Vlan 100',
         'ifType': '135',
          'ifAlias': 'Kubernetes Multus for SENSE',
          'hostname': 'dellos9_s0',
          'Key': 'ifHCInBroadcastPkts'}
        """
        if 'filterRules' not in self.config:
            return True
        if keys['hostname'] not in self.config['filterRules']:
            return True
        filterChecks = []
        for filterKey, filterVal in self.config['filterRules'][keys['hostname']]['filters'].items():
            if isinstance(filterVal, str):
                if keys[filterKey] == filterVal:
                    filterChecks.append(True)
                else:
                    filterChecks.append(False)
            elif isinstance(filterVal, list):
                if keys[filterKey] in filterVal:
                    filterChecks.append(True)
                else:
                    filterChecks.append(False)
        if self.config['filterRules'][keys['hostname']]['operator'] == 'and' and all(filterChecks):
            return True
        if self.config['filterRules'][keys['hostname']]['operator'] == 'or' and any(filterChecks):
            return True
        return False

    def __getSNMPData(self, registry, **kwargs):
        """Add SNMP Data to prometheus output"""
        # Here get info from DB for switch snmp details
        output = self.__getLatestOutput()
        runtimeInfo = Gauge('service_runtime_timestamp', 'Service Runtime Timestamp', ['servicename'], registry=registry)
        if not output:
            return
        if 'snmp_scan_runtime' not in output:
            runtimeInfo.labels(**{'servicename': 'SNMPMonitoring'}).set(0)
            self.logger.info('SNMP Scan Runtime does not have runtime details. Something wrong with SNMPRuntime Thread')
            # We need runtime timestamp. Anything older than 5mins, ignored. It shows that there is an issue with SNMPMon Thread.
            return
        if int(output['snmp_scan_runtime']) < int(getUTCnow() - 300):
            runtimeInfo.labels(**{'servicename': 'SNMPMonitoring'}).set(output['snmp_scan_runtime'])
            self.logger.info('SNMP Scan Runtime is older than 5 mins. Something wrong with SNMPRuntime Thread')
            return
        snmpGauge = Gauge('interface_statistics', 'Interface Statistics', ['ifDescr', 'ifType', 'ifAlias', 'hostname', 'Key'], registry=registry)
        for hostname, vals in output.items():
            if hostname == 'snmp_scan_runtime':
                runtimeInfo.labels(**{'servicename': 'SNMPMonitoring'}).set(vals)
                continue
            for key, val in vals.items():
                keys = {'ifDescr': val.get('ifDescr', ''), 'ifType': val.get('ifType', ''), 'ifAlias': val.get('ifAlias', ''), 'hostname': hostname}
                for key1 in ['ifMtu', 'ifAdminStatus', 'ifOperStatus', 'ifHighSpeed', 'ifHCInOctets', 'ifHCOutOctets', 'ifInDiscards', 'ifOutDiscards',
                             'ifInErrors', 'ifOutErrors', 'ifHCInUcastPkts', 'ifHCOutUcastPkts', 'ifHCInMulticastPkts', 'ifHCOutMulticastPkts',
                             'ifHCInBroadcastPkts', 'ifHCOutBroadcastPkts']:
                    if key1 in val and isValFloat(val[key1]):
                        keys['Key'] = key1
                        if self.__includeFilter(keys):
                            snmpGauge.labels(**keys).set(val[key1])

    def __metrics(self):
        """Return all available Hosts, where key is IP address."""
        registry = self.__cleanRegistry()
        self.__getSNMPData(registry)
        data = generate_latest(registry)
        return iter([data])

    @cherrypy.expose
    def prometheus(self):
        """Return prometheus stats."""
        return self.__metrics()



if __name__ == '__main__':
    print("WARNING: Use this only for development!")
    config = getConfig('/etc/snmp-mon.yaml')
    cherrypy.server.socket_host = '0.0.0.0'
    httpStart = HTTPExpose(config)
    httpStart.startwork()
