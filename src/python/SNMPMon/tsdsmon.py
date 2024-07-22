#!/usr/bin/env python3
""" TSDS Sense Real Time Monitoring Exporter"""
import pprint
from os import walk
import os.path
import requests
from SNMPMon.utilities import getConfig
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import dumpFileContentAsJson
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import getUTCnow


def sum_and_average(data):
    """Sum and average input data"""
    second_values = [item[1] for item in data]
    total_sum = sum(second_values)
    average = total_sum / len(second_values) if second_values else 0
    return average

class TSDS():
    """ TSDS class. """
    def __init__(self, config, scanfile, logger=None):
        self.config = config
        self.logger = logger if logger else getTimeRotLogger(**config['logParams'])
        self.scanfile = os.path.join(config['httpdir'], f"snmpmon-{scanfile}.json")
        self.tsdsuri = config.get('tsdsuri', 'http://localhost:8086/query')
        self.outdata = {}
        self.mapkeys = {}

    def _clean(self):
        """Clean up"""
        self.outdata = {}

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
                tmpd = {"ifDescr": port, "ifType": "6", "ifAlias": port, "hostname": device}
                for key, mapkey in self.mapkeys.items():
                    if key in res:
                        tmpd[mapkeys[mapkey]] = sum_and_average(res[key])
                devout.setdefault(device, {}).setdefault(str(incr), tmpd)
            # Set the runtime
            snmpout.setdefault(device, {}).setdefault('snmp_scan_runtime', getUTCnow())
        pprint.pprint(snmpout)
        return dumpFileContentAsJson(self.config, 'tsds', snmpout)

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
            self.logger.info(f"Working on device: {device['device']}")
            self.outdata[device['device']] = self._callTSDS(device['device'], ["input", "output", "inerror", "outerror", "indiscard", "outdiscard"])
        pprint.pprint(self.outdata)
        self._writeOutFile()

if __name__ == "__main__":
    conf = getConfig('/etc/snmp-mon.yaml')
    for (dirpath, dirnames, filenames) in walk(conf['httpdir']):
        for filename in filenames:
            if not filename.endswith('.json'):
                continue
            ts = TSDS(conf, os.path.join(conf['httpdir'], filename))
            ts.startwork()
