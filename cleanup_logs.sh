#!/bin/bash
sudo find /var/log/DLA/ -type f -name "*.log" -mtime +7 -exec rm {} \; > /var/log/DLA/cron_log_cleanup.log 2>&1