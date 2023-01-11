#!/usr/bin/env python3
"""
Setup tools script for SNMPMon.
Authors:
  Justas Balcas jbalcas (at) caltech.edu
Date: 2023/01/10
"""
from setuptools import setup
from setupUtilities import get_py_modules, VERSION

# Cronjobs which are running also have to be prepared with correct timing.
# Also another cronjob, which monitors config file and modifies cronjobs if needed.
# Currently it is allowed to specify only minutes and up to 30 minutes.
# This is how CRONJOBS are handled and division is done only for the current hour.
SCRIPTS = ["packaging/SNMPMonitoring", "packaging/WebServer"]

setup(
    name='SNMPMon',
    version=f"{VERSION}",
    long_description="SNMPMon installation",
    author="Justas Balcas",
    author_email="juztas@gmail.com",
    url="https://sdn-sense.github.io",
    download_url=f"https://github.com/sdn-sense/siterm/archive/refs/tags/{VERSION}.tar.gz",
    keywords=['SNMPMon', 'system', 'monitor', 'SDN', 'end-to-end'],
    package_dir={'': 'src/python/'},
    packages=['SNMPMon'],
    install_requires=[],
    data_files=[],
    py_modules=get_py_modules(['src/python/SNMPMon/']),
    scripts=SCRIPTS
)
