#!/usr/bin/env python3
"""
    SNMPMonitoring multiworker, gets config file and launches SNMPMonitoring
    thread for each device.

Authors:
  Justas Balcas juztas at gmail dot com

Date: 2024/05/23
"""

import subprocess
import shlex
from SNMPMon.utilities import getTimeRotLogger


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

    def _runCmd(self, action, device):
        """Start execution of new requests"""
        retOut = {}
        command = f"SNMPMonitoring --action {action} --devicename {device}"
        cmdOut = externalCommand(command, False)
        out, err = cmdOut.communicate()
        retOut['stdout'] += out.decode("utf-8").split('\n')
        retOut['stderr'] += err.decode("utf-8").split('\n')
        retOut['exitCode'] = cmdOut.returncode
        return retOut

    def startwork(self):
        """Multiworker main process"""
        # Read config and for each device start SNMPMonitoring supervisord process
        # which should check if it is status ok and if not - restart it.
        if not self.config.get('snmpMon', {}):
            self.logger.error("No devices to monitor")
            return
        for device in self.config.get('snmpMon', {}).keys():
            # Check status
            retOut = self._runCmd('status', device)
            if retOut['exitCode'] != 0 and self.firstRun:
                self.logger.info(f"Starting SNMPMonitoring for {device}")
                retOut = self._runCmd('start', device)
                self.logger.info(f"Starting SNMPMonitoring for {device} - {retOut}")
                continue
            if retOut['exitCode'] != 0 and not self.firstRun:
                self.logger.error(f"SNMPMonitoring for {device} failed: {retOut}")
                retOut = self._runCmd('restart', device)
                self.logger.info(f"Restarting SNMPMonitoring for {device} - {retOut}")
                continue
        self.firstRun = False
