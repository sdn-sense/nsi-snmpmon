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

class SNMPMonitoring():
    """SNMP Monitoring Class"""
    def __init__(self, config, logger=None):
        super().__init__()
        self.config = config
        self.logger = getTimeRotLogger(**config['logParams'])

    def _cleanOldCopies(self, ignoreList=[]):
        self.logger.info('Start check of old files')
        allfiles = os.listdir(self.config['tmpdir'])
        if len(allfiles) <= self.config.get('outcopies', 10):
            return
        while len(allfiles) >= self.config.get('outcopies', 10):
            fName = allfiles.pop(0)
            fileRemove = os.path.join(self.config['tmpdir'], fName)
            if fileRemove in ignoreList:
                continue
            os.remove(fileRemove)
            self.logger.info(f'File {fileRemove} removed. Old.')

    def _writeOutFile(self, out):
        return dumpFileContentAsJson(self.config, out)

    def _linkNewFile(self, dstFile, srcFile):
        if os.path.isfile(dstFile):
            os.unlink(dstFile)
        os.symlink(srcFile, dstFile)


    def startwork(self):
        """Scan all switches and get snmp data"""
        err = []
        jsonOut = {}
        for host in self.config['snmpMon']:
            if 'snmpParams' not in self.config['snmpMon'][host]:
                self.logger.info(f'Host: {host} config does not have snmpParams parameters.')
                continue
            session = Session(**self.config['snmpMon'][host]['snmpParams'])
            out = {}
            for key in ['ifDescr', 'ifType', 'ifMtu', 'ifAdminStatus', 'ifOperStatus',
                        'ifHighSpeed', 'ifAlias', 'ifHCInOctets', 'ifHCOutOctets', 'ifInDiscards',
                        'ifOutDiscards', 'ifInErrors', 'ifOutErrors', 'ifHCInUcastPkts',
                        'ifHCOutUcastPkts', 'ifHCInMulticastPkts', 'ifHCOutMulticastPkts',
                        'ifHCInBroadcastPkts', 'ifHCOutBroadcastPkts']:
                try:
                    allvals = session.walk(key)
                except EasySNMPUnknownObjectIDError as ex:
                    self.logger.warning(f'Got exception for key {key}: {ex}')
                    err.append(ex)
                    continue
                except EasySNMPTimeoutError as ex:
                    self.logger.warning(f'Got SNMP Timeout Exception: {ex}')
                    err.append(ex)
                    continue
                for item in allvals:
                    indx = item.oid_index
                    out.setdefault(indx, {})
                    out[indx][key] = item.value.replace('\x00', '')
            jsonOut[host] = out
        jsonOut['snmp_scan_runtime'] = getUTCnow()
        newFName = self._writeOutFile(jsonOut)
        latestFName = os.path.join(self.config['tmpdir'], 'snmp-out-latest.json')
        ignoreList = [newFName, latestFName]
        self._linkNewFile(latestFName, newFName)
        self._cleanOldCopies(ignoreList=ignoreList)
        if err:
            raise Exception(f'SNMP Monitoring Errors: {err}')


def execute(config=None):
    """Main Execute."""
    if not config:
        config = getConfig('/etc/snmp-mon.yaml')
    snmpmon = SNMPMonitoring(config)
    snmpmon.startwork()


if __name__ == '__main__':
    print('WARNING: ONLY FOR DEVELOPMENT!!!!. Number of arguments:', len(sys.argv), 'arguments.')
    print(sys.argv)
    execute()
