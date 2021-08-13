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

echo "start DoH proxy"

# read custom configuration
source /opt/doh-proxy/etc/.env

echo "doh-proxy: upstream dns server address: ${UPSTREAM_ADDR}:${UPSTREAM_PORT}"

/opt/doh-proxy/sbin/doh-proxy \
  --hostname=${HOSTNAME} \
  --server-address=${UPSTREAM_ADDR}:${UPSTREAM_PORT} \
  --listen-address=0.0.0.0:3000 \
  --path=/dns-query \
  --validation-algorithm=${VALIDATION_ALGORITHM} \
  --validation-key-path=/opt/doh-proxy/etc/public_key.pem \
  --token-issuer=${TOKEN_ISSUER} \
  --client-ids=${CLIENT_IDS} \
  --domain-block-rule=/opt/doh-proxy/etc/block.txt \
  --domain-override-rule=/opt/doh-proxy/etc/override.txt
