use crate::constants::*;
use clap::{Arg, ArgGroup};
use libdoh::plugin::{AppliedQueryPlugins, QueryPlugin};
use libdoh::plugin_block_domains::DomainBlockRule;
use libdoh::plugin_override_domains::DomainOverrideRule;
use libdoh::reexports::jwt_simple::prelude::*;
use libdoh::*;
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
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
    let options = app_from_crate!()
        .arg(
            Arg::with_name("hostname")
                .short("H")
                .long("hostname")
                .takes_value(true)
                .help("Host name (not IP address) DoH clients will use to connect"),
        )
        .arg(
            Arg::with_name("public_address")
                .short("g")
                .long("public-address")
                .takes_value(true)
                .help("External IP address DoH clients will connect to"),
        )
        .arg(
            Arg::with_name("listen_address")
                .short("l")
                .long("listen-address")
                .takes_value(true)
                .default_value(LISTEN_ADDRESS)
                .validator(verify_sock_addr)
                .help("Address to listen to"),
        )
        .arg(
            Arg::with_name("server_address")
                .short("u")
                .long("server-address")
                .takes_value(true)
                .default_value(SERVER_ADDRESS)
                .validator(verify_remote_server)
                .help("Address to connect to"),
        )
        .arg(
            Arg::with_name("local_bind_address")
                .short("b")
                .long("local-bind-address")
                .takes_value(true)
                .validator(verify_sock_addr)
                .help("Address to connect from"),
        )
        .arg(
            Arg::with_name("path")
                .short("p")
                .long("path")
                .takes_value(true)
                .default_value(PATH)
                .help("URI path"),
        )
        .arg(
            Arg::with_name("max_clients")
                .short("c")
                .long("max-clients")
                .takes_value(true)
                .default_value(&max_clients)
                .help("Maximum number of simultaneous clients"),
        )
        .arg(
            Arg::with_name("max_concurrent")
                .short("C")
                .long("max-concurrent")
                .takes_value(true)
                .default_value(&max_concurrent_streams)
                .help("Maximum number of concurrent requests per client"),
        )
        .arg(
            Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .takes_value(true)
                .default_value(&timeout_sec)
                .help("Timeout, in seconds"),
        )
        .arg(
            Arg::with_name("min_ttl")
                .short("T")
                .long("min-ttl")
                .takes_value(true)
                .default_value(&min_ttl)
                .help("Minimum TTL, in seconds"),
        )
        .arg(
            Arg::with_name("max_ttl")
                .short("X")
                .long("max-ttl")
                .takes_value(true)
                .default_value(&max_ttl)
                .help("Maximum TTL, in seconds"),
        )
        .arg(
            Arg::with_name("err_ttl")
                .short("E")
                .long("err-ttl")
                .takes_value(true)
                .default_value(&err_ttl)
                .help("TTL for errors, in seconds"),
        )
        .arg(
            Arg::with_name("disable_keepalive")
                .short("K")
                .long("disable-keepalive")
                .help("Disable keepalive"),
        )
        .arg(
            Arg::with_name("disable_post")
                .short("P")
                .long("disable-post")
                .help("Disable POST queries"),
        )
        .arg(
            Arg::with_name("allow_odoh_post")
                .short("O")
                .long("allow-odoh-post")
                .help("Allow POST queries over ODoH even if they have been disabled for DoH"),
        )
        .arg(
            Arg::with_name("disable_auth")
                .short("D")
                .long("disable-auth")
                .help("Disable authentication using HTTP Authorization header"),
        )
        .arg(
            Arg::with_name("validation_key")
                .short("V")
                .long("validation-key")
                .takes_value(true)
                .help("Validation key"),
        )
        .arg(
            Arg::with_name("validation_key_path")
                .short("W")
                .long("validation-key-path")
                .takes_value(true)
                .help("Validation key file path like \"./public_key.pem\""),
        )
        .groups(&[
            ArgGroup::with_name("validation").args(&["validation_key", "validation_key_path"])
        ])
        .arg(
            Arg::with_name("validation_algorithm")
                .short("A")
                .long("validation-algorithm")
                .takes_value(true)
                .default_value(VALIDATION_ALGORITHM)
                .help("Signing algorithm: HS256|ES256"),
        )
        .arg(
            Arg::with_name("token_issuer")
                .short("I")
                .long("token-issuer")
                .validator(verify_url)
                .takes_value(true)
                .help(
                    "Allowed issuer of Id token specified as URL like \"https://example.com/issue\"",
                ),
        )
        .arg(
            Arg::with_name("client_ids")
                .short("J")
                .long("client-ids")
                .takes_value(true)
                .help(
                    "Allowed client ids of Id token, separated with comma like \"id_a,id_b\"",
                ),
        )
        .arg(
            Arg::with_name("domain_block")
                .short("B")
                .long("domain-block-rule")
                .takes_value(true)
                .help("Domains block rule file path like \"./domains_block.txt\""),
        )
        .arg(
            Arg::with_name("domain_override")
                .short("R")
                .long("domain-override-rule")
                .takes_value(true)
                .help("Domains override rule file path like \"./domains_override.txt\""),
        );

    #[cfg(feature = "tls")]
    let options = options
        .arg(
            Arg::with_name("tls_cert_path")
                .short("i")
                .long("tls-cert-path")
                .takes_value(true)
                .help(
                    "Path to the PEM/PKCS#8-encoded certificates (only required for built-in TLS)",
                ),
        )
        .arg(
            Arg::with_name("tls_cert_key_path")
                .short("I")
                .long("tls-cert-key-path")
                .takes_value(true)
                .help("Path to the PEM-encoded secret keys (only required for built-in TLS)"),
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
    globals.disable_auth = matches.is_present("disable_auth");

    if let Some(a) = matches.value_of("validation_algorithm") {
        globals.set_validation_algorithm(a);
    }

    if matches.is_present("validation") {
        if let Some(s) = matches.value_of("validation_key") {
            globals.set_validation_key(s);
        } else {
            if let Some(p) = matches.value_of("validation_key_path") {
                if let Ok(content) = fs::read_to_string(p) {
                    if globals.is_hmac() {
                        let truncate_vec: Vec<&str> = content.split("\n").collect();
                        assert_eq!(truncate_vec.len() > 0, true);
                        globals.set_validation_key(truncate_vec[0]);
                    } else {
                        globals.set_validation_key(&content);
                        //println!("{:?}", globals.validation_key);
                    }
                }
            }
        }
    } else {
        if !globals.disable_auth {
            panic!("Validation key must be specified if auth is not disabled");
        }
    }

    // Treat a given token as ID token
    // Check audience and issuer if they are set when start
    let mut options = VerificationOptions::default();
    if let Some(iss) = matches.value_of("token_issuer") {
        options.allowed_issuers = Some(HashSet::from_strings(&vec![iss]));
    }
    if let Some(cids) = matches.value_of("client_ids") {
        let cids_vec: Vec<String> = cids.split(',').map(|x| x.to_string()).collect();
        options.allowed_audiences = Some(HashSet::from_strings(&cids_vec));
    }
    globals.validation_options = Some(options);

    let mut query_plugins = AppliedQueryPlugins::new();
    if let Some(override_list_path) = matches.value_of("domain_override") {
        if let Ok(content) = fs::read_to_string(override_list_path) {
            let truncate_vec: Vec<&str> = content.split("\n").filter(|c| c.len() != 0).collect();
            query_plugins.add(QueryPlugin::PluginDomainOverride(DomainOverrideRule::new(
                truncate_vec,
            )));
            // globals.set_domain_override(truncate_vec);
        }
    }
    if let Some(blocklist_path) = matches.value_of("domain_block") {
        if let Ok(content) = fs::read_to_string(blocklist_path) {
            let truncate_vec: Vec<&str> = content.split("\n").filter(|c| c.len() != 0).collect();
            query_plugins.add(QueryPlugin::PluginDomainBlock(DomainBlockRule::new(
                truncate_vec,
            )));
            // globals.set_domain_block(truncate_vec);
        }
    }

    // if options requiring to parse DNS message, this option is true
    if query_plugins.plugins.len() > 0 {
        globals.requires_dns_message_parsing = true;
        globals.query_plugins = Some(query_plugins);
    } else {
        globals.requires_dns_message_parsing = true;
    }

    #[cfg(feature = "tls")]
    {
        globals.tls_cert_path = matches.value_of("tls_cert_path").map(PathBuf::from);
        globals.tls_cert_key_path = matches
            .value_of("tls_cert_key_path")
            .map(PathBuf::from)
            .or_else(|| globals.tls_cert_path.clone());
    }

    if let Some(hostname) = matches.value_of("hostname") {
        let mut builder =
            dnsstamps::DoHBuilder::new(hostname.to_string(), globals.path.to_string());
        if let Some(public_address) = matches.value_of("public_address") {
            builder = builder.with_address(public_address.to_string());
        }
        println!(
            "Test DNS stamp to reach [{}] over DoH: [{}]\n",
            hostname,
            builder.serialize().unwrap()
        );

        let builder =
            dnsstamps::ODoHTargetBuilder::new(hostname.to_string(), globals.path.to_string());
        println!(
            "Test DNS stamp to reach [{}] over Oblivious DoH: [{}]\n",
            hostname,
            builder.serialize().unwrap()
        );

        println!("Check out https://dnscrypt.info/stamps/ to compute the actual stamps.\n")
    } else {
        println!("Please provide a fully qualified hostname (-H <hostname> command-line option) to get test DNS stamps for your server.\n");
    }
}
