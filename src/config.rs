use libdoh::*;

use crate::constants::*;

use clap::{Arg, ArgGroup};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::time::Duration;

#[cfg(feature = "tls")]
use std::path::PathBuf;

pub fn parse_opts(globals: &mut Globals) {
    use crate::utils::{verify_remote_server, verify_sock_addr};

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
                .help("Allow POST queries over ODoH even if they have been disabed for DoH"),
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
            ArgGroup::with_name("validation").args(&["validation_key_path", "validation_key_path"])
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
            Arg::with_name("domains_blocklist")
                .short("B")
                .long("domains-blocklist")
                .takes_value(true)
                .help("Domains blocklist file path like \"./dmoans_block.txt\""),
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

    if let Some(blocklist_path) = matches.value_of("domains_blocklist") {
        if let Ok(content) = fs::read_to_string(blocklist_path) {
            let truncate_vec: Vec<&str> = content.split("\n").filter(|c| c.len() != 0).collect();
            globals.set_domains_blocklist(truncate_vec);
        }
    }
    // if options requiring to parse DNS message, this option is true
    // TODO: update if new options are added.
    if let Some(_) = globals.domains_blocklist {
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
