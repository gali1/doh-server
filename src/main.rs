#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate clap;

mod config;
mod constants;
mod utils;

use libdoh::*;

use crate::config::*;
use crate::constants::*;

use libdoh::odoh::ODoHRotator;
use libdoh::odoh_proxy::ODoHProxy;
use libdoh::reexports::tokio;
// use std::env;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    // env::set_var("RUST_LOG", "info");
    // env_logger::init();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let ts = buf.timestamp();
            writeln!(
                buf,
                "{} [{}] {}",
                ts,
                record.level(),
                // record.target(),
                record.args(),
                // record.file().unwrap_or("unknown"),
                // record.line().unwrap_or(0),
            )
        })
        .init();
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();
    runtime_builder.thread_name("doh-proxy");
    let runtime = runtime_builder.build().unwrap();

    let rotator = match ODoHRotator::new(runtime.handle().clone()) {
        Ok(r) => r,
        Err(_) => panic!("Failed to create ODoHRotator"),
    };

    let mut globals = Globals {
        #[cfg(feature = "tls")]
        tls_cert_path: None,
        #[cfg(feature = "tls")]
        tls_cert_key_path: None,

        listen_address: LISTEN_ADDRESS.parse().unwrap(),
        local_bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        server_address: SERVER_ADDRESS.parse().unwrap(),
        path: PATH.to_string(),
        odoh_proxy_path: ODOH_PROXY_PATH.to_string(),
        max_clients: MAX_CLIENTS,
        timeout: Duration::from_secs(TIMEOUT_SEC),
        clients_count: Default::default(),
        max_concurrent_streams: MAX_CONCURRENT_STREAMS,
        min_ttl: MIN_TTL,
        max_ttl: MAX_TTL,
        err_ttl: ERR_TTL,
        keepalive: true,
        disable_post: false,
        allow_odoh_post: false,
        enable_auth_target: false,
        enable_auth_proxy: false,

        validation_key_target: None,
        validation_algorithm_target: None,
        validation_options_target: None,

        validation_key_proxy: None,
        validation_algorithm_proxy: None,
        validation_options_proxy: None,

        domain_block: None,
        domain_override: None,
        query_plugins: None,
        requires_dns_message_parsing: false,
        odoh_configs_path: ODOH_CONFIGS_PATH.to_string(),
        odoh_rotator: Arc::new(rotator),
        odoh_proxy: ODoHProxy::new(Duration::from_secs(TIMEOUT_SEC)).unwrap(),

        runtime_handle: runtime.handle().clone(),
    };
    parse_opts(&mut globals);
    let doh = DoH {
        globals: Arc::new(globals),
    };
    runtime.block_on(doh.entrypoint()).unwrap();
}
