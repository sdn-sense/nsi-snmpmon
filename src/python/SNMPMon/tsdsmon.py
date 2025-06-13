#!/usr/bin/env python3
""" TSDS Sense Real Time Monitoring Exporter"""
import sys
import pprint
import os.path
import requests
from SNMPMon.utilities import getConfig
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import dumpFileContentAsJson
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import getUTCnow


def sum_and_average(data):
    """Sum and average input data"""
    secondvals = [item[1] for item in data]
    total_sum = 0
    for val in secondvals:
        if val:
            try:
                total_sum += float(val)
            except ValueError:
                continue
    average = total_sum / len(secondvals) if secondvals else 0
    return average

class TSDS():
    """ TSDS class. """
    def __init__(self, config, scanfile):
        self.config = config
        self.logger = self._getCustomLogger(scanfile)
        self.scanfile = os.path.join(config['httpdir'], f"snmpmon-{scanfile}.json")
        self.tsdsuri = config.get('tsds_uri', 'http://localhost:8086/query')
        self.outdata = {}
        self.mapkeys = {}
        self.config['overwrite'] = {'hostname': '.net.internet2.edu'}

    def _getCustomLogger(self, scanfile):
        """Get Custom Logger"""
        if 'logFile' in self.config['logParams']:
            self.config['logParams']['logFile'] = f"{self.config['logParams']['logFile']}.{scanfile}.out"
        else:
            self.config['logParams']['logFile'] = f'{scanfile}.out'
        self.config['logParams']['service'] = f'TSDS-{scanfile}'
        return getTimeRotLogger(**self.config['logParams'])

    def _clean(self):
        """Clean up"""
        self.outdata = {}

    def overwrite(self, **kwargs):
        """Overwrite the config"""
        if self.config.get('overwrite', {}):
            for key, val in self.config['overwrite'].items():
                if key in kwargs:
                    splth =kwargs[key].split("+")
                    out = splth[1] + val
                    return out
        return kwargs.get('hostname', '')


    def _writeOutFile(self):
        """Write out file in an expected output format"""
        snmpout = {}
        incr = 0
        mapkeys = {"input": "ifHCInOctets", "output": "ifHCOutOctets", "inerror": "ifInErrors",
                   "outerror": "ifOutErrors", "indiscard": "ifInDiscards", "outdiscard": "ifOutDiscards"}
        for device, portdata in self.outdata.items():
            devout = snmpout.setdefault(device, {})
            for res in portdata.get('results', []):
                port = res.get('intf', '')
                if not port:
                    continue
                incr += 1
                # ifDescr=~"node+core1.star.*port+HundredGigE0/0/0/20-3600"
                # Special replacement of dot to dash and also custom for Internet2
                ifDescr = device + "-port+" + port.replace('.', '-')
                tmpd = {"ifDescr": ifDescr, "ifType": "6", "ifAlias": port, "hostname": device}
                for key, mapkey in self.mapkeys.items():
                    if key in res:
                        tmpd[mapkeys[mapkey]] = sum_and_average(res[key])
                devout.setdefault(device, {}).setdefault(str(incr), tmpd)
            # Set the runtime
            snmpout.setdefault(device, {}).setdefault('snmp_scan_runtime', getUTCnow())
        pprint.pprint(snmpout)
        return dumpFileContentAsJson(self.config, device, snmpout)

    def _callTSDS(self, host, fields):
        """Call TSDS and Get data"""
        # Define the parameters
        query = ""
        for field in fields:
            query += f"aggregate(values.{field}, 60, average), "
            self.mapkeys[f"aggregate(values.{field}, 60, average)"] = field
        # Need to remove last 2 characters
        query = query[:-2]
        params = {
            'method': 'query',
            'measurement_type': 'interface',
            'query': f'get intf, node, units, {query} between(now-5m, now) by intf, node from interface where ( node = "{host}" )'
        }
        response = requests.get(self.tsdsuri, params=params, timeout=60)
        if response.status_code != 200:
            self.logger.error(f"Error: {response.status_code}")
            return {}
        data = response.json()
        return data


    def startwork(self):
        """Main run"""
        self.logger.info("Starting TSDS monitoring")
        self._clean()
        # Load file
        devinput = getFileContentAsJson(self.scanfile)
        if not devinput:
            self.logger.error("No devices to monitor")
            return
        if not devinput.get('devices', []):
            self.logger.error("No devices to monitor")
            return

        for device in devinput.get('devices', []):
            hostname = self.overwrite(hostname=device['device'])
            self.logger.info(f"Working on device: {hostname}")
            self.outdata[device['device']] = self._callTSDS(hostname, ["input", "output", "inerror", "outerror", "indiscard", "outdiscard"])
        pprint.pprint(self.outdata)
        self._writeOutFile()

if __name__ == "__main__":
    conf = getConfig('/etc/snmp-mon.yaml')
    ts = TSDS(conf, sys.argv[1])
    ts.startwork()
