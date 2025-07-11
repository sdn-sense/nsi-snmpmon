#!/usr/bin/env python3
"""
    SNMP Monitoring utilities
Authors:
  Justas Balcas jbalcas (at) caltech.edu

Date: 2023/01/10
"""
import os
import ast
import time
import shutil
import datetime
import logging
import logging.handlers
import simplejson as json
from yaml import safe_load as yload

# Logging levels.
LEVELS = {'FATAL': logging.FATAL,
          'ERROR': logging.ERROR,
          'WARNING': logging.WARNING,
          'INFO': logging.INFO,
          'DEBUG': logging.DEBUG}

def isValFloat(inVal):
    """Check if inVal is float"""
    try:
        float(inVal)
    except ValueError:
        return False
    except TypeError:
        return False
    return True

def parseEsTime(timestr):
    """Parse ES Time to datetime object"""
    return datetime.datetime.strptime(timestr, "%Y-%m-%dT%H:%M:%SZ")

def evaldict(inputDict):
    """Output from the server needs to be evaluated."""
    if not inputDict:
        return {}
    if isinstance(inputDict, (list, dict)):
        return inputDict
    out = {}
    try:
        out = ast.literal_eval(inputDict)
    except ValueError:
        out = json.loads(inputDict)
    except SyntaxError as ex:
        raise Exception(f'Got Syntax Error: {ex}') from ex
    return out

def getFileContentAsJson(inputFile):
    """Get file content as json."""
    out = {}
    if os.path.isfile(inputFile):
        with open(inputFile, 'r', encoding='utf-8') as fd:
            try:
                out = json.load(fd)
            except ValueError:
                print(fd.seek(0))
                out = evaldict(fd.read())
    return out

def dumpFileContentAsJson(config, name, content, fullpath=False):
    """Dump File content with locks."""
    if fullpath:
        filename = name
    else:
        if not os.path.isdir(config['tmpdir']):
            os.makedirs(config['tmpdir'])
        filename = os.path.join(config['tmpdir'], f'snmp-{name}.json')
    tmpoutFile = filename + '.tmp'
    with open(tmpoutFile, 'w+', encoding='utf-8') as fd:
        json.dump(content, fd)
    shutil.move(tmpoutFile, filename)
    return filename

def moveFile(dstFile, srcFile):
    """Move file from src to dst."""
    shutil.move(srcFile, dstFile)

def getConfig(filename):
    """Get Config file"""
    if os.path.isfile(filename):
        with open(filename, 'r', encoding='utf-8') as fd:
            output = yload(fd.read())
    else:
        raise Exception(f'Config file {filename} does not exist.')
    return output

def getUTCnow():
    """Get UTC Time."""
    now = datetime.datetime.utcnow()
    timestamp = int(time.mktime(now.timetuple()))
    return timestamp

def checkLoggingHandler(**kwargs):
    """Check if logging handler is present and return True/False"""
    if logging.getLogger(kwargs.get('service', __name__)).hasHandlers():
        for handler in logging.getLogger(kwargs.get('service', __name__)).handlers:
            if isinstance(handler, kwargs['handler']):
                return handler
    return None

def getStreamLogger(**kwargs):
    """Get Stream Logger."""
    kwargs["handler"] = logging.StreamHandler
    handler = checkLoggingHandler(**kwargs)
    logger = logging.getLogger(kwargs.get("service", __name__))
    if not handler:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
            datefmt="%a, %d %b %Y %H:%M:%S",
        )
        handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(LEVELS[kwargs.get("logLevel", "DEBUG")])
    return logger

def getTimeRotLogger(**kwargs):
    """Get new Logger for logging."""
    kwargs['handler'] = logging.handlers.TimedRotatingFileHandler
    handler = checkLoggingHandler(**kwargs)
    logFile = kwargs.get('logFile', '')
    logger = logging.getLogger(kwargs.get('service', __name__))
    if not handler:
        handler = logging.handlers.TimedRotatingFileHandler(logFile,
                                                            when=kwargs.get('rotateTime', 'midnight'),
                                                            backupCount=kwargs.get('backupCount', 5))
        formatter = logging.Formatter("%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s",
                                      datefmt="%a, %d %b %Y %H:%M:%S")
        handler.setFormatter(formatter)
        handler.setLevel(LEVELS[kwargs.get('logLevel', 'DEBUG')])
        logger.addHandler(handler)
    logger.setLevel(LEVELS[kwargs.get('logLevel', 'DEBUG')])
    return logger

def keyMacMappings(network_os):
    """Key/Mac mapping for MAC monitoring"""
    default = {"oid": "1.3.6.1.2.1.17.7.1.2.2.1.3", "mib": "mib-2.17.7.1.2.2.1.3."}
    mappings = {
        "sonic": {
            "oid": "1.3.6.1.2.1.17.7.1.2.2.1.2",
            "mib": "mib-2.17.7.1.2.2.1.2.",
        }
    }
    if network_os in mappings:
        return mappings[network_os]
    return default

def overrideMacMappings(config, mappings):
    """Override Mac mappings"""
    if 'oid' in config:
        mappings['oid'] = config['oid']
    if 'mib' in config:
        mappings['mib'] = config['mib']
    return mappings

def findMaxInteger(strlist):
    """Find the maximum integer in a list of strings."""
    intlist = list(map(int, strlist))
    return max(intlist)

def updatedict(orig, new):
    """Update dictionary."""
    for key, val in new.items():
        for key1, val1 in val.items():
            if not isinstance(val1, dict):
                orig.setdefault(key, {}).setdefault(key1, "")
                orig[key][key1] = val1
                continue
            for _mkey, mval in val1.items():
                allitems = list(orig.get(key, {}).get(key1, {}).keys())
                nextint = findMaxInteger(allitems) + 1 if allitems else 0
                orig.setdefault(key, {}).setdefault(key1, {})[str(nextint)] = mval
    return orig
