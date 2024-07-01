#!/usr/bin/env python3
"""
    SNMPMonitoring multiworker, gets config file and launches SNMPMonitoring
    thread for each device.

Authors:
  Justas Balcas juztas at gmail dot com

Date: 2024/05/23
"""
import os
import time
import subprocess
import shlex
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import dumpFileContentAsJson
from SNMPMon.utilities import moveFile
from SNMPMon.utilities import updatedict


def externalCommand(command, communicate=True):
    """Execute External Commands and return stdout and stderr."""
    command = shlex.split(str(command))
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if communicate:
        return proc.communicate()
    return proc

class MultiWorker():
    """SNMP Monitoring Class"""
    def __init__(self, config, logger=None):
        super().__init__()
        self.config = config
        self.logger = logger if logger else getTimeRotLogger(**config['logParams'])
        self.firstRun = True

    def _runCmd(self, cmd, action, device, foreground=False):
        """Start execution of new requests"""
        retOut = {'stdout': [], 'stderr': [], 'exitCode': -1}
        command = f"{cmd} --action {action} --devicename {device}"
        if foreground:
            command += " --foreground"
        cmdOut = externalCommand(command, False)
        out, err = cmdOut.communicate()
        retOut['stdout'] += out.decode("utf-8").split('\n')
        retOut['stderr'] += err.decode("utf-8").split('\n')
        retOut['exitCode'] = cmdOut.returncode
        return retOut

    def __getLatestOutput(self, fName):
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

    def _latestOutputESnet(self):
        """Get latest output from all ESnet monitored devices."""
        out = {}
        # First identify oscarsid (if we have it)
        oscarIds = []
        for file in os.listdir(self.config['httpdir']):
            if not file.endswith('.json'):
                continue
            fName = os.path.join(self.config['httpdir'], file)
            try:
                tmpOut = getFileContentAsJson(fName)
                if tmpOut and tmpOut.get('runinfo', {}).get('oscarsid', ''):
                    if tmpOut['runinfo']['oscarsid'] not in oscarIds:
                        oscarIds.append(tmpOut['runinfo']['oscarsid'])
            except Exception as ex:
                self.logger.debug(f'Got Exception: {ex}')
        # Now here we loop via all OscarIds and get latest output
        for oscarId in oscarIds:
            fName = os.path.join(self.config['tmpdir'], f"snmp-{oscarId}.json")
            try:
                tmpOut = self.__getLatestOutput(fName)
                if tmpOut:
                    out = updatedict(out, tmpOut)
            except Exception as ex:
                self.logger.debug(f'Got Exception: {ex}')
        return out

    def _latestOutput(self):
        """Get latest output from all devices and write it to a single file."""
        out = {}
        for device in self.config.get('snmpMon', {}).keys():
            fName = os.path.join(self.config['tmpdir'], f"snmp-{device}-latest.json")
            try:
                tmpOut = self.__getLatestOutput(fName)
                if tmpOut:
                    out[device] = tmpOut
            except Exception as ex:
                self.logger.debug(f'Got Exception: {ex}')
        esnetout = self._latestOutputESnet()
        if esnetout:
            out = updatedict(out, esnetout)
        return dumpFileContentAsJson(self.config, 'multiworker', out)

    def _startSNMPMonitoring(self):
        """Start SNMP Monitoring processes for each device."""
        # Read config and for each device start SNMPMonitoring supervisord process
        # which should check if it is status ok and if not - restart it.
        if not self.config.get('snmpMon', {}):
            self.logger.error("No devices to monitor")
            return
        for device in self.config.get('snmpMon', {}).keys():
            # Check status
            retOut = self._runCmd('SNMPMonitoring', 'status', device)
            if retOut['exitCode'] != 0 and self.firstRun:
                self.logger.info(f"Starting SNMPMonitoring for {device}")
                retOut = self._runCmd('SNMPMonitoring', 'start', device, True)
                self.logger.info(f"Starting SNMPMonitoring for {device} - {retOut}")
                continue
            if retOut['exitCode'] != 0 and not self.firstRun:
                self.logger.error(f"SNMPMonitoring for {device} failed: {retOut}")
                retOut = self._runCmd('SNMPMonitoring', 'restart', device, True)
                self.logger.info(f"Restarting SNMPMonitoring for {device} - {retOut}")
                continue

    def _startESnetMonitoring(self):
        """Read httpdir config and start ESnet monitoring processes"""
        if not self.config.get('ESnetConfig', {}):
            self.logger.error("No ESnet devices to monitor")
            return
        for file in os.listdir(self.config['httpdir']):
            if not file.endswith('.json'):
                continue
            fName = os.path.join(self.config['httpdir'], file)
            config = getFileContentAsJson(fName)
            uuid, orchestrator = config.get('uuid', ''), config.get('orchestrator', '')
            firstRun, stopRun = bool(config.get('firstRun', True)), bool(config.get('stopRun', False))
            if not uuid or not orchestrator:
                self.logger.error(f"UUID or Orchestrator is missing in {fName}")
                continue
            if stopRun:
                self.logger.info(f"Stopping ESnetMonitoring for {uuid}")
                retOut = self._runCmd('ESnetMonitoring', 'stop', uuid, True)
                self.logger.info(f"Stopping ESnetMonitoring for {uuid} - {retOut}")
                os.remove(fName)
                continue
            # Write back the file with firstRun set to False
            retOut = self._runCmd('ESnetMonitoring', 'status', uuid)
            if retOut['exitCode'] != 0 and firstRun:
                self.logger.info(f"Starting ESnetMonitoring for {uuid}")
                retOut = self._runCmd('ESnetMonitoring', 'start', uuid, True)
                self.logger.info(f"Starting ESnetMonitoring for {uuid} - {retOut}")
                continue
            if retOut['exitCode'] != 0 and not firstRun:
                self.logger.error(f"ESnetMonitoring for {uuid} failed: {retOut}")
                retOut = self._runCmd('ESnetMonitoring', 'restart', uuid, True)
                self.logger.info(f"Restarting ESnetMonitoring for {uuid} - {retOut}")
                continue

    def startwork(self):
        """Multiworker main process"""
        # Start all SNMPMonitoring processes
        self._startSNMPMonitoring()
        # Start all ESnet monitoring processes
        self._startESnetMonitoring()
        # join all output files to a single file
        newFName = self._latestOutput()
        latestFName = os.path.join(self.config['tmpdir'], 'snmp-multiworker-latest.json')
        moveFile(latestFName, newFName)
        # Mark as not first run, so if service stops, it uses restart
        self.firstRun = False
