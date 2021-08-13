| #!/usr/bin/env bash
  LOG_FILE=/var/log/doh-proxy/doh-proxy.log

  /doh-proxy.sh | tee $LOG_FILE
