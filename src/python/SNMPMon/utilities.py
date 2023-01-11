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
import datetime
import logging
import logging.handlers
import shutil
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
    return True

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
        raise Exception(f'Got Syntax Error: {ex}')
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

def dumpFileContentAsJson(config, content):
    """Dump File content with locks."""
    filename = os.path.join(config['tmpdir'], 'snmp-out-%s.json' % getUTCnow())
    tmpoutFile = filename + '.tmp'
    with open(tmpoutFile, 'w+', encoding='utf-8') as fd:
        json.dump(content, fd)
    shutil.move(tmpoutFile, filename)
    return filename

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