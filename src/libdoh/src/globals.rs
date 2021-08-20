use crate::algorithm::*;
use crate::odoh::ODoHRotator;
use crate::odoh_proxy::ODoHProxy;
use crate::plugin::AppliedQueryPlugins;
use crate::plugin_block_domains::DomainBlockRule;
use crate::plugin_override_domains::DomainOverrideRule;
use jwt_simple::prelude::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime;

use std::str::FromStr;

#[cfg(feature = "tls")]
use std::path::PathBuf;

#[derive(Debug)]
pub enum ValidationLocation {
    Target,
    Proxy,
}

#[derive(Debug)]
pub struct Globals {
    #[cfg(feature = "tls")]
    pub tls_cert_path: Option<PathBuf>,

    #[cfg(feature = "tls")]
    pub tls_cert_key_path: Option<PathBuf>,

    pub listen_address: SocketAddr,
    pub local_bind_address: SocketAddr,
    pub server_address: SocketAddr,
    pub path: String,
    pub odoh_proxy_path: String,
    pub max_clients: usize,
    pub timeout: Duration,
    pub clients_count: ClientsCount,
    pub max_concurrent_streams: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub err_ttl: u32,
    pub keepalive: bool,
    pub disable_post: bool,
    pub allow_odoh_post: bool,

    // auth at target
    pub enable_auth_target: bool,
    pub validation_key_target: Option<JwtValidationKey>,
    pub validation_algorithm_target: Option<Algorithm>,
    pub validation_options_target: Option<VerificationOptions>,

    // auth at proxy
    pub enable_auth_proxy: bool,
    pub validation_key_proxy: Option<JwtValidationKey>,
    pub validation_algorithm_proxy: Option<Algorithm>,
    pub validation_options_proxy: Option<VerificationOptions>,

    pub domain_block: Option<DomainBlockRule>,
    pub domain_override: Option<DomainOverrideRule>,
    pub query_plugins: Option<AppliedQueryPlugins>,
    pub requires_dns_message_parsing: bool,
    pub odoh_configs_path: String,
    pub odoh_rotator: Arc<ODoHRotator>,
    pub odoh_proxy: ODoHProxy,

    pub runtime_handle: runtime::Handle,
}

impl Globals {
    pub fn set_validation_algorithm(&mut self, algorithm_str: &str, loc: ValidationLocation) {
        if let Ok(a) = Algorithm::from_str(algorithm_str) {
            match loc {
                ValidationLocation::Target => self.validation_algorithm_target = Some(a),
                ValidationLocation::Proxy => self.validation_algorithm_proxy = Some(a),
            }
        } else {
            panic!("Invalid algorithm")
        }
    }
    pub fn set_validation_key(&mut self, key_str: &str, loc: ValidationLocation) {
        let alg = match loc {
            ValidationLocation::Target => &self.validation_algorithm_target,
            ValidationLocation::Proxy => &self.validation_algorithm_proxy,
        };
        match &alg {
            Some(va) => match JwtValidationKey::new(va, key_str) {
                Ok(vk) => match loc {
                    ValidationLocation::Target => self.validation_key_target = Some(vk),
                    ValidationLocation::Proxy => self.validation_key_proxy = Some(vk),
                },
                Err(e) => {
                    panic!("Invalid key for specified algorithm: {:?}", e);
                }
            },
            None => {
                panic!("Algorithm not specified");
            }
        }
    }

    pub fn is_hmac(&self, loc: ValidationLocation) -> bool {
        let alg = match loc {
            ValidationLocation::Target => &self.validation_algorithm_target,
            ValidationLocation::Proxy => &self.validation_algorithm_proxy,
        };
        match alg {
            Some(Algorithm::HS256) | Some(Algorithm::HS384) | Some(Algorithm::HS512) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientsCount(Arc<AtomicUsize>);

impl ClientsCount {
    pub fn current(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    pub fn increment(&self) -> usize {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn decrement(&self) -> usize {
        let mut count;
        while {
            count = self.0.load(Ordering::Relaxed);
            count > 0
                && self
                    .0
                    .compare_exchange(count, count - 1, Ordering::Relaxed, Ordering::Relaxed)
                    != Ok(count)
        } {}
        count
    }
}
