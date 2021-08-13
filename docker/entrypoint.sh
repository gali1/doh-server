| \
  #!/usr/bin/env bash
  LOG_FILE=/var/log/doh-proxy/doh-proxy.log

  bash /doh-proxy.sh | tee $LOG_FILE
