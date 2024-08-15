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
from datetime import datetime, timedelta
import shlex
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import dumpFileContentAsJson
from SNMPMon.utilities import moveFile
from SNMPMon.utilities import updatedict
from SNMPMon.utilities import getConfig

def fileUpdatedLastNMin(filename, minutes=5):
    """Check if file was updated with-in last N minutes."""
    try:
        fileMtime = os.path.getmtime(filename)
        fileMtimeDt = datetime.fromtimestamp(fileMtime)
        currentTime = datetime.now()
        if currentTime - fileMtimeDt <= timedelta(minutes=minutes):
            return True
    except FileNotFoundError:
        return False
    return False


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
        self.scannedfiles = []

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
                self.logger.debug(f'Got Exception3: {ex}')
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
                self.scannedfiles.append(fName)
                tmpOut = getFileContentAsJson(fName)
                if tmpOut and tmpOut.get('runinfo', {}).get('oscarsid', ''):
                    if tmpOut['runinfo']['oscarsid'] not in oscarIds:
                        oscarIds.append(tmpOut['runinfo']['oscarsid'])
            except Exception as ex:
                self.logger.debug(f'Got Exception4: {ex}')
        # Now here we loop via all OscarIds and get latest output
        for oscarId in oscarIds:
            fName = os.path.join(self.config['tmpdir'], f"snmp-{oscarId}.json")
            try:
                tmpOut = self.__getLatestOutput(fName)
                if tmpOut:
                    out = updatedict(out, tmpOut)
            except Exception as ex:
                self.logger.debug(f'Got Exception1: {ex}')
        return out

    def _latestOutputOther(self):
        """Get all the rest files and merge them."""
        # Get all the rest files
        out = {}
        for dirname, _dirs, files in os.walk(self.config['tmpdir']):
            for filename in files:
                fName = os.path.join(dirname, filename)
                if fName in self.scannedfiles:
                    continue
                if filename == 'snmp-multiworker-latest.json':
                    continue
                if not fileUpdatedLastNMin(fName, 5):
                    continue
                try:
                    tmpOut = getFileContentAsJson(fName)
                    if tmpOut:
                        out = updatedict(out, tmpOut)
                except Exception as ex:
                    self.logger.debug(f'Got Exception2: {ex}')
        return out

    def _latestOutput(self):
        """Get latest output from all devices and write it to a single file."""
        out = {}
        for device in self.config.get('snmpMon', {}).keys():
            fName = os.path.join(self.config['tmpdir'], f"snmp-{device}-latest.json")
            try:
                self.scannedfiles.append(fName)
                tmpOut = self.__getLatestOutput(fName)
                if tmpOut:
                    out[device] = tmpOut
            except Exception as ex:
                self.logger.debug(f'Got Exception5: {ex}')
        esnetout = self._latestOutputESnet()
        if esnetout:
            out = updatedict(out, esnetout)
        out = updatedict(out, self._latestOutputOther())
        return dumpFileContentAsJson(self.config, 'multiworker', out)

    def _startSNMPMonitoring(self):
        """Start SNMP Monitoring processes for each device."""
        # Read config and for each device start SNMPMonitoring supervisord process
        # which should check if it is status ok and if not - restart it.
        if not self.config.get('snmpMon', {}):
            self.logger.error("No devices to monitor configured for SNMP.")
            return False
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
        return True

    def _startTSDSMonitoring(self):
        """Read hhtpdir config and start TSDS monitoring processes"""
        if not self.config.get('tsds_uri', ''):
            self.logger.error("No TSDS devices to monitor configured.")
            return False
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
                self.logger.info(f"Stopping TSDSMonitoring for {uuid}")
                retOut = self._runCmd('TSDSMonitoring', 'stop', uuid, True)
                self.logger.info(f"Stopping TSDSMonitoring for {uuid} - {retOut}")
                os.remove(fName)
                continue
            # Write back the file with firstRun set to False
            retOut = self._runCmd('TSDSMonitoring', 'status', uuid)
            if retOut['exitCode'] != 0 and firstRun:
                self.logger.info(f"Starting TSDSMonitoring for {uuid}")
                retOut = self._runCmd('TSDSMonitoring', 'start', uuid, True)
                self.logger.info(f"Starting TSDSMonitoring for {uuid} - {retOut}")
                continue
            if retOut['exitCode'] != 0 and not firstRun:
                self.logger.error(f"TSDSMonitoring for {uuid} failed: {retOut}")
                retOut = self._runCmd('TSDSMonitoring', 'restart', uuid, True)
                self.logger.info(f"Restarting TSDSMonitoring for {uuid} - {retOut}")
                continue
        return True

    def _startESnetMonitoring(self):
        """Read httpdir config and start ESnet monitoring processes"""
        if not self.config.get('es_host', '') and not self.config.get('es_index', ''):
            self.logger.error("No ESnet devices to monitor configured.")
            return False
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
        return True

    def startwork(self):
        """Multiworker main process"""
        # Start all SNMPMonitoring processes
        self.scannedfiles = []
        for service, servclass in {'SNMPMonitoring': self._startSNMPMonitoring,
                                   'ESnetMonitoring': self._startESnetMonitoring,
                                   'TSDSMonitoring': self._startTSDSMonitoring}.items():
            started = servclass()
            if started:
                self.logger.info(f"{service} started successfully. Will not start any other monitoring (Only one allowed).")
                break
            self.logger.error(f"{service} not started. Either not configured or already running.")
        # join all output files to a single file
        newFName = self._latestOutput()
        latestFName = os.path.join(self.config['tmpdir'], 'snmp-multiworker-latest.json')
        moveFile(latestFName, newFName)
        # Mark as not first run, so if service stops, it uses restart
        self.firstRun = False

if __name__ == '__main__':
    CONFIG = getConfig('/etc/snmp-mon.yaml')
    MULTIWORKER = MultiWorker(CONFIG)
    MULTIWORKER.startwork()
