use crate::algorithm::*;
use crate::constants::*;
use crate::odoh::ODoHRotator;
use crate::plugin::AppliedQueryPlugins;
use crate::plugin_block_domains::DomainBlockRule;
use crate::plugin_override_domains::{DomainOverrideRule, MapsTo};
use log::{debug, error, info, warn};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime;

use std::str::FromStr;

#[cfg(feature = "tls")]
use std::path::PathBuf;

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
    pub disable_auth: bool,
    pub validation_key: Option<JwtValidationKey>,
    pub validation_algorithm: Option<Algorithm>,
    pub domain_block: Option<DomainBlockRule>,
    pub domain_override: Option<DomainOverrideRule>,
    pub query_plugins: Option<AppliedQueryPlugins>,
    pub requires_dns_message_parsing: bool,
    pub odoh_configs_path: String,
    pub odoh_rotator: Arc<ODoHRotator>,

    pub runtime_handle: runtime::Handle,
}

impl Globals {
    pub fn set_validation_algorithm(&mut self, algorithm_str: &str) {
        if let Ok(a) = Algorithm::from_str(algorithm_str) {
            self.validation_algorithm = Some(a);
        } else {
            panic!("Invalid algorithm")
        }
    }
    pub fn set_validation_key(&mut self, key_str: &str) {
        // self.validation_key = Some(key_str.to_string());
        match &self.validation_algorithm {
            Some(va) => match JwtValidationKey::new(va, key_str) {
                Ok(vk) => {
                    self.validation_key = Some(vk);
                }
                Err(e) => {
                    panic!("Invalid key for specified algorithm: {:?}", e);
                }
            },
            None => {
                panic!("Algorithm not specified");
            }
        }
    }

    pub fn is_hmac(&self) -> bool {
        match self.validation_algorithm {
            Some(Algorithm::HS256) | Some(Algorithm::HS384) | Some(Algorithm::HS512) => true,
            _ => false,
        }
    }

    // pub fn set_domain_block(&mut self, vec_domain_str: Vec<&str>) {
    //     // TODO: currently only prefix match with '*' is supported
    //     let re = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN_OR_PREFIX, r"$")).unwrap();
    //     let hs: HashSet<String> = vec_domain_str
    //         .iter()
    //         .filter(|x| re.is_match(x))
    //         .map(|y| y.to_string())
    //         .collect();
    //     self.domain_block = Some(DomainBlockRule { domains: hs });
    // }
    // pub fn set_domain_override(&mut self, vec_domain_map_str: Vec<&str>) {
    //     let redomain_split_space =
    //         Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN, r"\s+\S+$")).unwrap();
    //     let hm: HashMap<String, Vec<MapsTo>> = vec_domain_map_str
    //         .iter()
    //         .filter(|x| redomain_split_space.is_match(x)) // filter by primary key (domain)
    //         .filter_map(|x| {
    //             let split: Vec<&str> = x.split_whitespace().collect();
    //             if split.len() != 2 {
    //                 warn!("Invalid override rule: {}", split[0]);
    //                 None
    //             } else {
    //                 let targets: Vec<MapsTo> =
    //                     split[1].split(',').filter_map(|x| MapsTo::new(x)).collect();
    //                 let original_len = split[1].split(',').collect::<Vec<&str>>().len();
    //                 let res = match original_len == targets.len() {
    //                     true => Some((split[0].to_string(), targets)),
    //                     false => {
    //                         warn!("Invalid override rule: {}", split[0]);
    //                         None
    //                     }
    //                 };
    //                 res
    //             }
    //         })
    //         .collect();
    //     self.domain_override = Some(DomainOverrideRule { domain_maps: hm });
    // }
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
