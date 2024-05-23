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
from prometheus_client import generate_latest, CollectorRegistry
from prometheus_client import Gauge
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import isValFloat
from SNMPMon.utilities import getUTCnow
from SNMPMon.utilities import getConfig


class Frontend():

    def __init__(self):
        self.config = getConfig('/etc/snmp-mon.yaml')
        self.logger = getTimeRotLogger(**self.config.get('logParams', {}))

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
