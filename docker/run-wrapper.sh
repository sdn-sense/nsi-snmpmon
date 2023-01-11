#!/bin/bash

SNMPMonitoring --action start --foreground
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start SNMPMonitoring service: $status"
fi
sleep 5

# Webserver continues to run, no exit.
WebServer --action start --foreground
status=$?
if [ $status -ne 0 ]; then
  echo "Failed to start WebServer service: $status"
fi

while true; do sleep 1; done

