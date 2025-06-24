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
    def __init__(self, config, hostname):
        super().__init__()
        self.config = config
        self.logger = self._getCustomLogger(hostname)
        self.hostname = hostname

    def _getCustomLogger(self, scanfile):
        """Get Custom Logger"""
        if 'logFile' in self.config['logParams']:
            self.config['logParams']['logFile'] = f"{self.config['logParams']['logFile']}.{scanfile}.out"
        else:
            self.config['logParams']['logFile'] = f'{scanfile}.out'
        self.config['logParams']['service'] = f'SNMP-{scanfile}'
        return getTimeRotLogger(**self.config['logParams'])

    def _writeOutFile(self, out):
        return dumpFileContentAsJson(self.config, self.hostname, out)

    def __includeFilter(self, val):
        """
        # Filter rules inside configuration file
        filterRules:
          dellos9_s0:
            operator: 'and'
            filters:
              - Key: 'ifAdminStatus'
                Val: 'up'
                Startswith: False (default is False - if True - will use py startswith call)
                Replacement: '<new_value>' (optional - if defined will replace value with new_value)
              - Key: ifDescr
                Val: ["hundredGigE 1/21", "Vlan 100"]
        where val is dictionary and has:
        {'ifDescr': 'Vlan 100',
         'ifType': '135',
          'ifAlias': 'Kubernetes Multus for SENSE',
          'hostname': 'dellos9_s0',
          'Key': 'ifHCInBroadcastPkts'}
        """
        retVal = True
        if 'filterRules' not in self.config:
            return retVal, val
        if self.hostname not in self.config['filterRules']:
            return retVal, val
        filterChecks = []
        for filterItem in self.config['filterRules'][self.hostname].get('filters', []):
            filterKey = filterItem.get('Key', '')
            filterVal = filterItem.get('Val', '')
            filterStarts = filterItem.get('Startswith', False)
            filterReplace = filterItem.get('Replacement', '')
            if not filterKey or not filterVal:
                # That is wrong filter. We raise error and continue to include it
                self.logger.warning('Filter rule missing either Key or Val defined. Will not check based on this Key/Val')
                filterChecks.append(True)
                continue
            if isinstance(filterVal, str):
                if not filterStarts and filterKey in val and val[filterKey] == filterVal:
                    filterChecks.append(True)
                    val[filterKey] = filterReplace if filterReplace else val[filterKey]
                elif filterStarts and filterKey in val and val[filterKey].startswith(filterVal):
                    filterChecks.append(True)
                    val[filterKey] = val[filterKey].replace(filterVal, filterReplace) if filterReplace else val[filterKey]
                else:
                    filterChecks.append(False)
            elif isinstance(filterVal, list):
                if val in filterVal:
                    filterChecks.append(True)
                else:
                    filterChecks.append(False)
        if not filterChecks:
            retVal = True
        elif self.config['filterRules'][self.hostname]['operator'] == 'and' and all(filterChecks):
            retVal = True
        elif self.config['filterRules'][self.hostname]['operator'] == 'or' and any(filterChecks):
            retVal = True
        else:
            retVal = False
        return retVal, val

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
        try:
            session = Session(**self.config['snmpMon'][self.hostname]['snmpParams'])
        except ValueError:
            conf = self.config['snmpMon'][self.hostname]['snmpParams']
            hostname = conf.pop('hostname')
            session = Session(**conf)
            session.update_session(hostname=hostname)
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
                    out[indx][key] = item.value.replace('\x00', '')
            except EasySNMPUnknownObjectIDError as ex:
                self.logger.warning(f'Got exception for key {key}: {ex}')
                err.append(ex)
                continue
            except EasySNMPTimeoutError as ex:
                self.logger.warning(f'Got SNMP Timeout Exception: {ex}')
                err.append(ex)
                continue
        # Filter items out
        filteredOut = {}
        for indx, vals in out.items():
            inclFlag, vals = self.__includeFilter(vals)
            if inclFlag:
                filteredOut[indx] = vals
        filteredOut = self.callOverrides(session, filteredOut)
        jsonOut[self.hostname] = filteredOut
        jsonOut['macs'] = self.scanMacAddresses(session)
        jsonOut['snmp_scan_runtime'] = getUTCnow()
        newFName = self._writeOutFile(jsonOut)
        latestFName = os.path.join(self.config['tmpdir'], f'snmp-{self.hostname}-latest.json')
        moveFile(latestFName, newFName)
        if err:
            raise Exception(f'SNMP Monitoring Errors: {err}')

def execute(hostname):
    """Main Execute."""
    config = getConfig('/etc/snmp-mon-cenic.yaml')
    snmpmon = SNMPMonitoring(config, hostname)
    snmpmon.startwork()


if __name__ == '__main__':
    print('WARNING: ONLY FOR DEVELOPMENT!!!!. Number of arguments:', len(sys.argv), 'arguments.')
    print(sys.argv)
    execute(sys.argv[1])
