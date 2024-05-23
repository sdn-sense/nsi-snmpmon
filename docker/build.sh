#!/bin/bash
docker buildx build --platform=linux/amd64 --no-cache -t nsi-snmpmon .
