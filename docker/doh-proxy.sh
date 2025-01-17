#!/usr/bin/env bash

LOG_FILE=/var/log/doh-proxy/doh-proxy.log
LOG_SIZE=10M
LOG_NUM=10

# logrotate
if [ $LOGROTATE_NUM ]; then
  LOG_NUM=${LOGROTATE_NUM}
fi
if [ $LOGROTATE_SIZE ]; then
  LOG_SIZE=${LOGROTATE_SIZE}
fi

cat > /etc/logrotate.conf << EOF
# see "man logrotate" for details
# rotate log files weekly
weekly
# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm
# keep 4 weeks worth of backlogs
rotate 4
# create new (empty) log files after rotating old ones
create
# use date as a suffix of the rotated file
#dateext
# uncomment this if you want your log files compressed
#compress
# packages drop log rotation information into this directory
include /etc/logrotate.d
# system-specific logs may be also be configured here.
EOF

cat > /etc/logrotate.d/doh-proxy << EOF
${LOG_FILE} {
    dateext
    daily
    missingok
    rotate ${LOG_NUM}
    notifempty
    compress
    delaycompress
    dateformat -%Y-%m-%d-%s
    size ${LOG_SIZE}
    copytruncate
}
EOF

cp -p /etc/cron.daily/logrotate /etc/cron.hourly/
service cron start

# debug level logging
LOG_LEVEL=info
if [ ${DEBUG} ]; then
  echo "Logging in debug mode"
  LOG_LEVEL=debug
fi

echo "start DoH proxy"

# read custom configuration
source /opt/doh-proxy/etc/.env

echo "doh-proxy: upstream dns server address: ${UPSTREAM_ADDR}:${UPSTREAM_PORT}"

RUST_LOG=${LOG_LEVEL} /opt/doh-proxy/sbin/doh-proxy \
  --hostname=${HOSTNAME} \
  --server-address=${UPSTREAM_ADDR}:${UPSTREAM_PORT} \
  --listen-address=0.0.0.0:3000 \
  --path=/dns-query \
  --validation-algorithm-target=${VALIDATION_ALGORITHM} \
  --validation-key-target=/opt/doh-proxy/etc/public_key.pem \
  --token-issuer-target=${TOKEN_ISSUER} \
  --client-ids-target=${CLIENT_IDS} \
  --validation-algorithm-proxy=${VALIDATION_ALGORITHM} \
  --validation-key-proxy=/opt/doh-proxy/etc/public_key.pem \
  --token-issuer-proxy=${TOKEN_ISSUER} \
  --client-ids-proxy=${CLIENT_IDS} \
  --odoh-allowed-target-domains=${ODOH_ALLOWED_TARGET_DOMAINS} \
  --odoh-allowed-proxy-ips=${ODOH_ALLOWED_PROXY_IPS} \
  --domain-block-rule=/opt/doh-proxy/etc/block.txt \
  --domain-override-rule=/opt/doh-proxy/etc/override.txt
