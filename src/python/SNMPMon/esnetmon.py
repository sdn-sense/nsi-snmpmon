#!/usr/bin/env python3
"""ESnet SDN Sense Real Time Monitoring Exporter"""
import pprint
from os import walk
import os.path
import copy
from elasticsearch import Elasticsearch
from SNMPMon.utilities import getConfig
from SNMPMon.utilities import getFileContentAsJson
from SNMPMon.utilities import dumpFileContentAsJson
from SNMPMon.utilities import getTimeRotLogger
from SNMPMon.utilities import getUTCnow

class ESnetES():
    """ESnet ElasticSearch Class"""
    def __init__(self, config, scanfile, logger=None):
        self.config = config
        self.logger = logger if logger else getTimeRotLogger(**config['logParams'])
        self.scanfile = os.path.join(config['httpdir'], f"snmpmon-{scanfile}.json")
        self.client = Elasticsearch([config['es_host']], request_timeout=60)
        self.ind = config['es_index']
        self.monports = {'oscarsid': "", "ports": {}}
        self.outdata = {}

    def _clean(self):
        """Clean up"""
        self.monports = {'oscarsid': "", "ports": {}}
        self.outdata = {}

    def get_dev_data(self, **kwargs):
        """Get device data"""
        mquery = {
           "size":0,
           "_source":False,
           "aggs":{"volume_per_interval": {
                        "date_histogram": {"field": "start","fixed_interval": "1m"},
                        "aggs": {"volume_in":{"sum":{"field":"values.in_bits.delta"}},
                                 "volume_out":{"sum":{"field":"values.out_bits.delta"}},
                                 "volume_inerr":{"sum":{"field":"values.in_errors.delta"}},
                                 "volume_outerr":{"sum":{"field":"values.out_errors.delta"}},
                                 "volume_indisc":{"sum":{"field":"values.in_discards.delta"}},
                                 "volume_outdisc":{"sum":{"field":"values.out_discards.delta"}},
                                 "mac_addresses":{"terms":{"field": "meta.fdb_mac_addrs"}},
                                 "rate_in":{"bucket_script":{"buckets_path":{"volume": "volume_in"},"script": "params.volume / 300"}},
                                 "rate_out":{"bucket_script":{"buckets_path":{"volume": "volume_out"},"script": "params.volume / 300"}},
                                 "err_in":{"bucket_script":{"buckets_path":{"volume": "volume_inerr"},"script": "params.volume / 300"}},
                                 "err_out":{"bucket_script":{"buckets_path":{"volume": "volume_outerr"},"script": "params.volume / 300"}},
                                 "disc_in":{"bucket_script":{"buckets_path":{"volume": "volume_indisc"},"script": "params.volume / 300"}},
                                 "disc_out":{"bucket_script":{"buckets_path":{"volume": "volume_outdisc"},"script": "params.volume / 300"}}
                        }}},
            "query":{"bool":{"filter":[{"range":{"start":{"gte":"now-5m","lte":"now"}}}]}}}

        for device, ports in self.monports['ports'].items():
            # Get all oscars_ids for the device abd port
            for port in ports:
                query = copy.deepcopy(mquery)
                # Add filter for device and port
                query["query"]["bool"]["filter"].append({"query_string": {"analyze_wildcard": True, "query": f"meta.id: \"{port}\""}})
                #query["query"]["bool"]["filter"].append({"query_string": {"analyze_wildcard": True, "query": f"meta.device: \"{device}\""}})
                res = self.client.search(body=query, index=self.ind, preference="primary")
                # Do an aggregation of results and log everything
                self.outdata.setdefault(device, {}).setdefault(port, {})
                for bucket in res["aggregations"]["volume_per_interval"]["buckets"]:
                    for key in ["volume_in", "volume_out", "rate_in", "rate_out", "err_in", "err_out", "disc_in", "disc_out"]:
                        self.outdata[device][port].setdefault(key, []).append(bucket[key]["value"])
                    if "mac_addresses" in bucket:
                        for macaddr in bucket["mac_addresses"]["buckets"]:
                            if macaddr['key'] not in self.outdata[device][port].get("mac_addresses", []):
                                self.outdata[device][port].setdefault("mac_addresses", []).append(macaddr['key'])


    def get_all(self, **kwargs):
        """Get all interfaces"""
        aggregations = {"ifaces": {"ifaces": {"terms": {"field": "meta.id","size": 25000}}},
                        "oscars_ids": {"oscars_ids": {"terms": {"field": "meta.oscars_id","size": 25000}}}}
        query = {"size": 0,
                    "_source": False,
                    "aggs": {}, # aggs will be overwritten by query check
                    "query": {"bool": {"filter": [{"range": {"start": {"gte": "now-15m/m","lte": "now"}}}]}}}
        # Add specific aggregator if any
        if 'query' in kwargs and kwargs['query'] in aggregations:
            query["aggs"] = aggregations[kwargs['query']]
        else:
            raise Exception(f"Invalid query: {kwargs}")
        # Add filters if any
        if 'device' in kwargs:
            query["query"]["bool"]["filter"].append({"query_string": {"analyze_wildcard": True, "query": f"meta.device: \"{kwargs['device']}\""}})
        if 'oscars_id' in kwargs:
            query["query"]["bool"]["filter"].append({"query_string": {"analyze_wildcard": True, "query": f"meta.oscars_id: \"{kwargs['oscars_id']}\""}})
        if 'port' in kwargs:
            query["query"]["bool"]["filter"].append({"query_string": {"analyze_wildcard": True, "query": f"meta.id: \"{kwargs['port']}\""}})
        res = self.client.search(body=query, index=self.ind)
        return res

    def filterPorts(self, allports, device):
        """Filter ports we are looking for monitoring"""
        for iface in allports["aggregations"]["ifaces"]["buckets"]:
            if iface["key"] == f"{device['device']}::{device['port']}":
                self.monports['ports'].setdefault(device['device'], {}).setdefault(iface["key"], -1)
            elif iface["key"].startswith(f"{device['device']}::") and \
                 device['port'] in iface["key"] and \
                 iface["key"].endswith(f"-{device['vlan']}"):
                self.monports['ports'].setdefault(device['device'], {}).setdefault(iface["key"], int(device.get('vlan', -1)))

    def identifyOscarId(self):
        """Identify OscarId for the device and port"""
        for device, ports in self.monports['ports'].items():
            # Get all oscars_ids for the device abd port
            for port in ports:
                oscarids = self.get_all(query="oscars_ids", device=device, port=port)
                for oscarsout in oscarids["aggregations"]["oscars_ids"]["buckets"]:
                    if oscarsout.get("key"):
                        self.monports['oscarsid'] = oscarsout["key"]
                        return

    def _writeOutFile(self):
        """Write out file in an expected output format"""
        snmpout = {}
        incr = 0
        mapkeys = {"rate_in": "ifHCInOctets", "rate_out": "ifHCOutOctets", "err_in": "ifInErrors",
                   "err_out": "ifOutErrors", "disc_in": "ifInDiscards", "disc_out": "ifOutDiscards"}
        for device, portdata in self.outdata.items():
            devout = snmpout.setdefault(device, {})
            for port, data in portdata.items():
                incr += 1
                tmpd = {"ifDescr": port, "ifType": "6", "ifAlias": port, "hostname": device}
                for key, mapkey in mapkeys.items():
                    if key in data:
                        sumdata = sum(data[key])
                        countdata = len(data[key])
                        tmpd[mapkey] = str(int(sumdata/countdata))
                devout.setdefault(device, {}).setdefault(str(incr), tmpd)
                # Add mac addresses
                if 'mac_addresses' in data:
                    vlan = self.monports.get('ports', {}).get(device, {}).get(port, -1)
                    if vlan == -1:
                        continue
                    outdm = devout.setdefault('macs', {}).setdefault("vlans", {}).setdefault(str(vlan), [])
                    for mac in data['mac_addresses']:
                        if mac not in outdm:
                            outdm.append(mac)
            # Set the runtime
            snmpout.setdefault(device, {}).setdefault('snmp_scan_runtime', getUTCnow())
        pprint.pprint(snmpout)
        return dumpFileContentAsJson(self.config, self.monports['oscarsid'], snmpout)

    def startwork(self):
        """Main run"""
        self.logger.info("Starting ESnet monitoring")
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
            allports = self.get_all(query="ifaces", device=device["device"])
            self.filterPorts(allports, device)
        # Now we have all ports we want to monitor
        self.identifyOscarId()
        self.get_dev_data()
        self._writeOutFile()
        if not devinput.get('runinfo', {}):
            self.logger.info(f"First run finished. dumping data. {devinput}")
            devinput['runinfo'] = self.monports
            devinput['firstRun'] = False
            dumpFileContentAsJson(self.config, self.scanfile, devinput, True)

if __name__ == "__main__":
    conf = getConfig('/etc/snmp-mon.yaml')
    for (dirpath, dirnames, filenames) in walk(conf['httpdir']):
        for filename in filenames:
            if not filename.endswith('.json'):
                continue
            es = ESnetES(conf, os.path.join(conf['httpdir'], filename))
            es.startwork()
