#!/bin/bash

# Kiểm tra trạng thái của Splunk
timestamp=$(date '+%Y-%m-%d %H:%M:%S')
status=$(sudo /opt/splunk/bin/splunk status)
echo "Splunk status: $status" >> /tmp/splunk_check.log

if [[ $status == *"splunkd is running"* ]]; then
    echo "[$timestamp] Splunk is running" >> /tmp/splunk_check.log
    exit 0
else
    echo "[$timestamp] Splunk is not running" >> /tmp/splunk_check.log
    exit 1
fi