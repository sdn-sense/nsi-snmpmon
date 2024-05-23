#!/bin/bash
docker buildx build --no-cache --platform=linux/amd64 -t nsi-snmpmon .
