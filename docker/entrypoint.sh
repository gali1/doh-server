#!/usr/bin/env bash
LOG_FILE=/var/log/doh-proxy/doh-proxy.log

/doh-proxy.sh 2>&1 | tee $LOG_FILE
