pub const LISTEN_ADDRESS: &str = "127.0.0.1:3000";
pub const MAX_CLIENTS: usize = 512;
pub const MAX_CONCURRENT_STREAMS: u32 = 16;
pub const PATH: &str = "/dns-query";
#[cfg(feature = "odoh-proxy")]
pub const ODOH_PROXY_PATH: &str = "/proxy";
pub const ODOH_CONFIGS_PATH: &str = "/.well-known/odohconfigs";
pub const SERVER_ADDRESS: &str = "9.9.9.9:53";
pub const TIMEOUT_SEC: u64 = 10;
pub const MAX_TTL: u32 = 86400 * 7;
pub const MIN_TTL: u32 = 10;
pub const ERR_TTL: u32 = 2;

pub const VALIDATION_ALGORITHM: &str = "ES256";
