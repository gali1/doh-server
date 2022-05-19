pub const DNS_QUERY_PARAM: &str = "dns";
#[cfg(feature = "odoh-proxy")]
pub const ODOH_TARGET_HOST_QUERY_PARAM: &str = "targethost";
#[cfg(feature = "odoh-proxy")]
pub const ODOH_TARGET_PATH_QUERY_PARAM: &str = "targetpath";
#[cfg(feature = "odoh-proxy")]
pub const MODOH_PROXY_HOST_QUERY_PARAM: &str = "relayhost";
#[cfg(feature = "odoh-proxy")]
pub const MODOH_PROXY_PATH_QUERY_PARAM: &str = "relaypath";
pub const MAX_DNS_QUESTION_LEN: usize = 512;
pub const MAX_DNS_RESPONSE_LEN: usize = 4096;
pub const MIN_DNS_PACKET_LEN: usize = 17;
pub const STALE_IF_ERROR_SECS: u32 = 86400;
pub const STALE_WHILE_REVALIDATE_SECS: u32 = 60;
#[cfg(feature = "tls")]
pub const CERTS_WATCH_DELAY_SECS: u32 = 10;
pub const ODOH_KEY_ROTATION_SECS: u32 = 86400;
pub const UDP_TCP_RATIO: usize = 8;
pub const REGEXP_DOMAIN: &str = r"([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+([a-zA-Z]{2,})";
pub const REGEXP_DOMAIN_OR_PREFIX: &str =
  r"^([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.)+([a-zA-Z]{2,}|\*)";
pub const REGEXP_IPV4: &str = r"((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
pub const REGEXP_IPV6: &str = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
pub const HEADER_IP_KEYS: &[&str] = &[
  "x-client-ip",
  "x-forwarded-for",
  "cf-connecting-ip",
  "fastly-client-ip",
  "true-client-ip",
  "x-real-ip",
  "x-cluster-client-ip",
];
