use crate::constants::*;
use clap::Arg;
use libdoh::log::*;
use libdoh::plugin::{AppliedQueryPlugins, QueryPlugin};
use libdoh::plugin_block_domains::DomainBlockRule;
use libdoh::plugin_override_domains::DomainOverrideRule;
use libdoh::reexports::jwt_simple::prelude::*;
use libdoh::*;
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::time::Duration;

#[cfg(feature = "tls")]
use std::path::PathBuf;

pub fn parse_opts(globals: &mut Globals) {
    use crate::utils::{verify_remote_server, verify_sock_addr, verify_url};

    let max_clients = MAX_CLIENTS.to_string();
    let timeout_sec = TIMEOUT_SEC.to_string();
    let max_concurrent_streams = MAX_CONCURRENT_STREAMS.to_string();
    let min_ttl = MIN_TTL.to_string();
    let max_ttl = MAX_TTL.to_string();
    let err_ttl = ERR_TTL.to_string();

    let _ = include_str!("../Cargo.toml");
    let options = command!()
        .arg(
            Arg::new("hostname")
                .short('H')
                .long("hostname")
                .takes_value(true)
                .help("Host name (not IP address) DoH clients will use to connect"),
        )
        .arg(
            Arg::new("public_address")
                .short('g')
                .long("public-address")
                .takes_value(true)
                .help("External IP address DoH clients will connect to"),
        )
        .arg(
            Arg::new("public_port")
                .short('j')
                .long("public-port")
                .takes_value(true)
                .help("External port DoH clients will connect to, if not 443"),
        )
        .arg(
            Arg::new("listen_address")
                .short('l')
                .long("listen-address")
                .takes_value(true)
                .default_value(LISTEN_ADDRESS)
                .validator(verify_sock_addr)
                .help("Address to listen to"),
        )
        .arg(
            Arg::new("server_address")
                .short('u')
                .long("server-address")
                .takes_value(true)
                .default_value(SERVER_ADDRESS)
                .validator(verify_remote_server)
                .help("Address to connect to"),
        )
        .arg(
            Arg::new("local_bind_address")
                .short('b')
                .long("local-bind-address")
                .takes_value(true)
                .validator(verify_sock_addr)
                .help("Address to connect from"),
        )
        .arg(
            Arg::new("path")
                .short('p')
                .long("path")
                .takes_value(true)
                .default_value(PATH)
                .help("URI path"),
        )
        .arg(
            Arg::new("max_clients")
                .short('c')
                .long("max-clients")
                .takes_value(true)
                .default_value(&max_clients)
                .help("Maximum number of simultaneous clients"),
        )
        .arg(
            Arg::new("max_concurrent")
                .short('C')
                .long("max-concurrent")
                .takes_value(true)
                .default_value(&max_concurrent_streams)
                .help("Maximum number of concurrent requests per client"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .takes_value(true)
                .default_value(&timeout_sec)
                .help("Timeout, in seconds"),
        )
        .arg(
            Arg::new("min_ttl")
                .short('T')
                .long("min-ttl")
                .takes_value(true)
                .default_value(&min_ttl)
                .help("Minimum TTL, in seconds"),
        )
        .arg(
            Arg::new("max_ttl")
                .short('X')
                .long("max-ttl")
                .takes_value(true)
                .default_value(&max_ttl)
                .help("Maximum TTL, in seconds"),
        )
        .arg(
            Arg::new("err_ttl")
                .short('E')
                .long("err-ttl")
                .takes_value(true)
                .default_value(&err_ttl)
                .help("TTL for errors, in seconds"),
        )
        .arg(
            Arg::new("disable_keepalive")
                .short('K')
                .long("disable-keepalive")
                .help("Disable keepalive"),
        )
        .arg(
            Arg::new("disable_post")
                .short('P')
                .long("disable-post")
                .help("Disable POST queries"),
        )
        .arg(
            Arg::new("allow_odoh_post")
                .short('O')
                .long("allow-odoh-post")
                .help("Allow POST queries over ODoH even if they have been disabled for DoH"),
        )
        .arg(
            Arg::new("validation_key_target")
                .short('W')
                .long("validation-key-target")
                .takes_value(true)
                .help("Target validation key file path like \"./public_key.pem\""),
        )
        .arg(
            Arg::new("validation_algorithm_target")
                .short('A')
                .long("validation-algorithm-target")
                .takes_value(true)
                .default_value(VALIDATION_ALGORITHM)
                .help("Target validation algorithm"),
        )
        .arg(
            Arg::new("token_issuer_target")
                .short('M')
                .long("token-issuer-target")
                .validator(verify_url)
                .takes_value(true)
                .help(
                    "Target allowed issuer of Id token specified as URL like \"https://example.com/issue\"",
                ),
        )
        .arg(
            Arg::new("client_ids_target")
                .short('S')
                .long("client-ids-target")
                .takes_value(true)
                .help(
                    "Target allowed client ids of Id token, separated with comma like \"id_a,id_b\"",
                ),
        )
        .arg(
            Arg::new("odoh_allowed_proxy_ips")
                .short('d')
                .long("odoh-allowed-proxy-ips")
                .takes_value(true)
                .help(
                    "Allowed ODoH proxies' IP addresses/DoH client addresses from which this node (as (O)DoH target) can accept requests, separated with comma. If some ips are given, requests from them are accepted when authorization header is missing (of course rejected the when invalid token is given). If none is given and no authorization is configured, it can accept anywhere."
                )
        )
        .arg(
            Arg::new("domain_block")
                .short('B')
                .long("domain-block-rule")
                .takes_value(true)
                .help("Domains block rule file path like \"./domains_block.txt\""),
        )
        .arg(
            Arg::new("domain_override")
                .short('R')
                .long("domain-override-rule")
                .takes_value(true)
                .help("Domains override rule file path like \"./domains_override.txt\""),
        );

    #[cfg(feature = "tls")]
    let options = options
        .arg(
            Arg::new("tls_cert_path")
                .short('i')
                .long("tls-cert-path")
                .takes_value(true)
                .help(
                    "Path to the PEM/PKCS#8-encoded certificates (only required for built-in TLS)",
                ),
        )
        .arg(
            Arg::new("tls_cert_key_path")
                .short('I')
                .long("tls-cert-key-path")
                .takes_value(true)
                .help("Path to the PEM-encoded secret keys (only required for built-in TLS)"),
        );

    #[cfg(feature = "odoh-proxy")]
    let options = options.arg(
        Arg::new("odoh_proxy_path")
            .short('q')
            .long("odoh-proxy-path")
            .takes_value(true)
            .default_value(ODOH_PROXY_PATH)
            .help("ODoH proxy URI path"),
    )
    .arg(
        Arg::new("validation_key_proxy")
            .short('w')
            .long("validation-key-proxy")
            .takes_value(true)
            .help("Proxy validation key file path like \"./public_key.pem\""),
    )
    .arg(
        Arg::new("validation_algorithm_proxy")
            .short('a')
            .long("validation-algorithm-proxy")
            .takes_value(true)
            .default_value(VALIDATION_ALGORITHM)
            .help("Proxy validation algorithm"),
    )
    .arg(
        Arg::new("token_issuer_proxy")
            .short('m')
            .long("token-issuer-proxy")
            .validator(verify_url)
            .takes_value(true)
            .help(
                "Proxy allowed issuer of Id token specified as URL like \"https://example.com/issue\"",
            ),
    )
    .arg(
        Arg::new("client_ids_proxy")
            .short('s')
            .long("client-ids-proxy")
            .takes_value(true)
            .help(
                "Proxy allowed client ids of Id token, separated with comma like \"id_a,id_b\"",
            ),
    )
    .arg(
        Arg::new("odoh_allowed_target_domains")
            .short('D')
            .long("odoh-allowed-target-domains")
            .takes_value(true)
            .help(
                "Allowed domains to which this node (as ODoH proxy) can forward ODoH request, separated with comma. If none is given, it can forward anywhere.",
            )
    );

    let matches = options.get_matches();
    globals.listen_address = matches.value_of("listen_address").unwrap().parse().unwrap();

    globals.server_address = matches
        .value_of("server_address")
        .unwrap()
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    globals.local_bind_address = match matches.value_of("local_bind_address") {
        Some(address) => address.parse().unwrap(),
        None => match globals.server_address {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(s) => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                s.flowinfo(),
                s.scope_id(),
            )),
        },
    };
    globals.path = matches.value_of("path").unwrap().to_string();
    if !globals.path.starts_with('/') {
        globals.path = format!("/{}", globals.path);
    }
    globals.max_clients = matches.value_of("max_clients").unwrap().parse().unwrap();
    globals.timeout = Duration::from_secs(matches.value_of("timeout").unwrap().parse().unwrap());
    globals.max_concurrent_streams = matches.value_of("max_concurrent").unwrap().parse().unwrap();
    globals.min_ttl = matches.value_of("min_ttl").unwrap().parse().unwrap();
    globals.max_ttl = matches.value_of("max_ttl").unwrap().parse().unwrap();
    globals.err_ttl = matches.value_of("err_ttl").unwrap().parse().unwrap();
    globals.keepalive = !matches.is_present("disable_keepalive");
    globals.disable_post = matches.is_present("disable_post");
    globals.allow_odoh_post = matches.is_present("allow_odoh_post");

    if let Some(p) = matches.value_of("validation_key_target") {
        if let Some(a) = matches.value_of("validation_algorithm_target") {
            info!("[Auth (O)DoH target] Validation algorithm is {:?}", &a);
            globals.set_validation_algorithm(a, ValidationLocation::Target);
        }

        if let Ok(content) = fs::read_to_string(p) {
            if globals.is_hmac(ValidationLocation::Target) {
                let truncate_vec: Vec<&str> = content.split('\n').collect();
                assert!(!truncate_vec.is_empty());
                globals.set_validation_key(truncate_vec[0], ValidationLocation::Target);
            } else {
                globals.set_validation_key(&content, ValidationLocation::Target);
            }
        }
        globals.enable_auth_target = true;
        info!("[Auth (O)DoH target] Validation key is successfully set.");

        // Treat a given token as ID token
        // Check audience and issuer if they are set when start
        let mut options = VerificationOptions::default();
        if let Some(iss) = matches.value_of("token_issuer_target") {
            options.allowed_issuers = Some(HashSet::from_strings(&[iss]));
            info!("[Auth (O)DoH target] Allowed issuer: {}", iss);
        }
        if let Some(cids) = matches.value_of("client_ids_target") {
            let cids_vec: Vec<String> = cids.split(',').map(|x| x.to_string()).collect();
            options.allowed_audiences = Some(HashSet::from_strings(&cids_vec));
            info!("[Auth (O)DoH target] Allowed client ids: {:?}", cids_vec);
        }
        globals.validation_options_target = Some(options);
    }

    if let Some(allowed) = matches.value_of("odoh_allowed_proxy_ips") {
        let allowed_proxy: HashSet<IpAddr> = allowed
            .split(',')
            .filter(|c| !c.is_empty())
            .map(|c| c.parse().unwrap())
            .collect();
        globals.odoh_allowed_proxy_ips = Some(allowed_proxy);
    };

    #[cfg(feature = "odoh-proxy")]
    {
        if let Some(p) = matches.value_of("validation_key_proxy") {
            if let Some(a) = matches.value_of("validation_algorithm_proxy") {
                info!("[Auth (O)DoH proxy] Validation algorithm is {:?}", &a);
                globals.set_validation_algorithm(a, ValidationLocation::Proxy);
            }

            if let Ok(content) = fs::read_to_string(p) {
                if globals.is_hmac(ValidationLocation::Proxy) {
                    let truncate_vec: Vec<&str> = content.split('\n').collect();
                    assert!(!truncate_vec.is_empty());
                    globals.set_validation_key(truncate_vec[0], ValidationLocation::Proxy);
                } else {
                    globals.set_validation_key(&content, ValidationLocation::Proxy);
                }
            }
            globals.enable_auth_proxy = true;
            info!("[Auth (O)DoH proxy] Validation key is successfully set.");

            // Treat a given token as ID token
            // Check audience and issuer if they are set when start
            let mut options = VerificationOptions::default();
            if let Some(iss) = matches.value_of("token_issuer_proxy") {
                options.allowed_issuers = Some(HashSet::from_strings(&[iss]));
                info!("[Auth (O)DoH proxy] Allowed issuer: {}", iss);
            }
            if let Some(cids) = matches.value_of("client_ids_proxy") {
                let cids_vec: Vec<String> = cids.split(',').map(|x| x.to_string()).collect();
                options.allowed_audiences = Some(HashSet::from_strings(&cids_vec));
                info!("[Auth (O)DoH proxy] Allowed client ids: {:?}", cids_vec);
            }
            globals.validation_options_proxy = Some(options);
        }

        if let Some(allowed) = matches.value_of("odoh_allowed_target_domains") {
            let allowed_target: HashSet<String> = allowed
                .split(',')
                .filter(|c| !c.is_empty())
                .map(|c| c.to_string())
                .collect();
            globals.odoh_allowed_target_domains = Some(allowed_target);
        };
    }

    let mut query_plugins = AppliedQueryPlugins::new();
    if let Some(override_list_path) = matches.value_of("domain_override") {
        if let Ok(content) = fs::read_to_string(override_list_path) {
            let truncate_vec: Vec<&str> = content.split('\n').filter(|c| !c.is_empty()).collect();
            query_plugins.add(QueryPlugin::PluginDomainOverride(Box::new(DomainOverrideRule::new(
                truncate_vec,
            ))));
            info!("[Query plugin] Server-side domain overriding is enabled");
        }
    }
    if let Some(blocklist_path) = matches.value_of("domain_block") {
        if let Ok(content) = fs::read_to_string(blocklist_path) {
            let truncate_vec: Vec<&str> = content.split('\n').filter(|c| !c.is_empty()).collect();
            query_plugins.add(QueryPlugin::PluginDomainBlock(Box::new(DomainBlockRule::new(
                truncate_vec,
            ))));
            info!("[Query plugin] Server-side domain blocking is enabled");
        }
    }

    // if options requiring to parse DNS message, this option is true
    if !query_plugins.plugins.is_empty() {
        globals.requires_dns_message_parsing = true;
        globals.query_plugins = Some(query_plugins);
    }

    #[cfg(feature = "tls")]
    {
        globals.tls_cert_path = matches.value_of("tls_cert_path").map(PathBuf::from);
        globals.tls_cert_key_path = matches
            .value_of("tls_cert_key_path")
            .map(PathBuf::from)
            .or_else(|| globals.tls_cert_path.clone());
    }

    #[cfg(feature = "odoh-proxy")]
    {
        globals.odoh_proxy_path = matches.value_of("odoh_proxy_path").unwrap().to_string();
        if !globals.odoh_proxy_path.starts_with('/') {
            globals.odoh_proxy_path = format!("/{}", globals.odoh_proxy_path);
        }
        globals.odoh_proxy = libdoh::odoh_proxy::ODoHProxy::new(globals.timeout).unwrap();
    }

    if let Some(hostname) = matches.value_of("hostname") {
        let mut builder =
            dnsstamps::DoHBuilder::new(hostname.to_string(), globals.path.to_string());
        if let Some(public_address) = matches.value_of("public_address") {
            builder = builder.with_address(public_address.to_string());
        }
        if let Some(public_port) = matches.value_of("public_port") {
            let public_port = public_port.parse().expect("Invalid public port");
            builder = builder.with_port(public_port);
        }
        info!(
            "Test DNS stamp to reach [{}] over DoH: [{}]\n",
            hostname,
            builder.serialize().unwrap()
        );

        let mut builder =
            dnsstamps::ODoHTargetBuilder::new(hostname.to_string(), globals.path.to_string());
        if let Some(public_port) = matches.value_of("public_port") {
            let public_port = public_port.parse().expect("Invalid public port");
            builder = builder.with_port(public_port);
        }
        info!(
            "Test DNS stamp to reach [{}] over Oblivious DoH Target: [{}]\n",
            hostname,
            builder.serialize().unwrap()
        );

        #[cfg(feature = "odoh-proxy")]
        {
            let builder = dnsstamps::ODoHRelayBuilder::new(
                hostname.to_string(),
                globals.odoh_proxy_path.to_string(),
            );
            info!(
                "Test DNS stamp to reach [{}] over Oblivious DoH Proxy: [{}]\n",
                hostname,
                builder.serialize().unwrap()
            );
        }

        info!("Check out https://dnscrypt.info/stamps/ to compute the actual stamps.\n")
    } else {
        info!("Please provide a fully qualified hostname (-H <hostname> command-line option) to get test DNS stamps for your server.\n");
    }
}
