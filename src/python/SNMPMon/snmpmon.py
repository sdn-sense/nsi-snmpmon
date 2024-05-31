#!/usr/bin/env python3
"""
    SNMPMonitoring gets all information from switches using SNMP
    Cloned and modified from SiteRM - to have it separated SNMPMon Process:
    https://github.com/sdn-sense/siterm/blob/master/src/python/SiteFE/SNMPMonitoring/snmpmon.py

Authors:
  Justas Balcas jbalcas (at) caltech.edu

Date: 2022/11/21
"""
import os
import sys
from easysnmp import Session
from easysnmp.exceptions import EasySNMPUnknownObjectIDError
from easysnmp.exceptions import EasySNMPTimeoutError
from SNMPMon.utilities import getConfig
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import dumpFileContentAsJson
from SNMPMon.utilities import getUTCnow
from SNMPMon.utilities import keyMacMappings, overrideMacMappings
from SNMPMon.utilities import moveFile


class Overrides():
    """Overrides Class"""
    def __init__(self):
        pass

    def _ifDescrSonic(self, session, out):
        """Override ifDescr for SONiC"""
        oids = {}
        for key in out.keys():
            val = 1000000000 + (int(key)*100)
            oids["mib-2.47.1.1.1.1.7." + str(val)] = key

        newNames = session.walk('1.3.6.1.2.1.47.1.1.1.1.7.')
        for item in newNames:
            if item.oid in oids:
                out[oids[item.oid]].setdefault('ifAlias', '')
                out[oids[item.oid]].setdefault('ifDescr', '')
                tmpVal = out[oids[item.oid]]['ifDescr']
                out[oids[item.oid]]['ifDescr'] = item.value
                out[oids[item.oid]]['ifAlias'] += tmpVal
        return out

    def callOverrides(self, session, out):
        """Check if override param defined. So far only special case for SONiC"""
        # check if customOverride is defined and call based on name
        if 'customOverride' in self.config['snmpMon'][self.hostname]:
            if self.config['snmpMon'][self.hostname]['customOverride'] == 'ifDescrSonic':
                return self._ifDescrSonic(session, out)
        return out


class SNMPMonitoring(Overrides):
    """SNMP Monitoring Class"""
    def __init__(self, config, hostname, logger=None):
        super().__init__()
        self.config = config
        self.logger = logger if logger else getTimeRotLogger(**config['logParams'])
        self.hostname = hostname

    def _writeOutFile(self, out):
        return dumpFileContentAsJson(self.config, self.hostname, out)

    def __includeFilter(self, key, val):
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
        if self.hostname not in self.config['filterRules']:
            return True
        filterChecks = []
        for filterKey, filterVal in self.config['filterRules'][self.hostname].get('filters', {}).items():
            if filterKey != key:
                continue
            if isinstance(filterVal, str):
                if val == filterVal:
                    filterChecks.append(True)
                else:
                    filterChecks.append(False)
            elif isinstance(filterVal, list):
                if val in filterVal:
                    filterChecks.append(True)
                else:
                    filterChecks.append(False)
        if not filterChecks:
            return True
        if self.config['filterRules'][self.hostname]['operator'] == 'and' and all(filterChecks):
            return True
        if self.config['filterRules'][self.hostname]['operator'] == 'or' and any(filterChecks):
            return True
        return False

    def scanMacAddresses(self, session):
        """Scan all MAC addresses"""
        macs = {'vlans': {}}
        mappings = keyMacMappings(self.config['snmpMon'][self.hostname].get('network_os', 'default'))
        mappings = overrideMacMappings(self.config['snmpMon'][self.hostname].get('macoverride', {}), mappings)
        allvals = session.walk(mappings['oid'])
        for item in allvals:
            splt = item.oid[(len(mappings['mib'])):].split('.')
            vlan = splt.pop(0)
            mac = [format(int(x), '02x') for x in splt]
            macs['vlans'].setdefault(vlan, [])
            macs['vlans'][vlan].append(":".join(mac))
        return macs

    def startwork(self):
        """Scan all switches and get snmp data"""
        err = []
        jsonOut = {}
        if self.hostname not in self.config['snmpMon']:
            self.logger.info(f'Host: {self.hostname} not found in config.')
            return
        if 'snmpParams' not in self.config['snmpMon'][self.hostname]:
            self.logger.info(f'Host: {self.hostname} config does not have snmpParams parameters.')
            return
        session = Session(**self.config['snmpMon'][self.hostname]['snmpParams'])
        out = {}
        for key in ['ifDescr', 'ifType', 'ifMtu', 'ifAdminStatus', 'ifOperStatus',
                    'ifHighSpeed', 'ifAlias', 'ifHCInOctets', 'ifHCOutOctets', 'ifInDiscards',
                    'ifOutDiscards', 'ifInErrors', 'ifOutErrors', 'ifHCInUcastPkts',
                    'ifHCOutUcastPkts', 'ifHCInMulticastPkts', 'ifHCOutMulticastPkts',
                    'ifHCInBroadcastPkts', 'ifHCOutBroadcastPkts']:
            try:
                allvals = session.walk(key)
                for item in allvals:
                    indx = item.oid_index
                    out.setdefault(indx, {})
                    val = item.value.replace('\x00', '')
                    if self.__includeFilter(key, val):
                        out[indx][key] = val
            except EasySNMPUnknownObjectIDError as ex:
                self.logger.warning(f'Got exception for key {key}: {ex}')
                err.append(ex)
                continue
            except EasySNMPTimeoutError as ex:
                self.logger.warning(f'Got SNMP Timeout Exception: {ex}')
                err.append(ex)
                continue
        out = self.callOverrides(session, out)
        jsonOut[self.hostname] = out
        jsonOut['macs'] = self.scanMacAddresses(session)
        jsonOut['snmp_scan_runtime'] = getUTCnow()
        newFName = self._writeOutFile(jsonOut)
        latestFName = os.path.join(self.config['tmpdir'], f'snmp-{self.hostname}-latest.json')
        moveFile(latestFName, newFName)
        if err:
            raise Exception(f'SNMP Monitoring Errors: {err}')

def execute(hostname):
    """Main Execute."""
    config = getConfig('/etc/snmp-mon.yaml')
    snmpmon = SNMPMonitoring(config, hostname)
    snmpmon.startwork()


if __name__ == '__main__':
    print('WARNING: ONLY FOR DEVELOPMENT!!!!. Number of arguments:', len(sys.argv), 'arguments.')
    print(sys.argv)
    execute(sys.argv[1])
