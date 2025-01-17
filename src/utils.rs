// functions to verify the startup arguments as correct

use std::net::{SocketAddr, ToSocketAddrs};
use url::Url;

pub(crate) fn verify_sock_addr(arg_val: &str) -> Result<String, String> {
    match arg_val.parse::<SocketAddr>() {
        Ok(_addr) => Ok(arg_val.to_string()),
        Err(_) => Err(format!(
            "Could not parse \"{arg_val}\" as a valid socket address (with port)."
        )),
    }
}

pub(crate) fn verify_remote_server(arg_val: &str) -> Result<String, String> {
    match arg_val.to_socket_addrs() {
        Ok(mut addr_iter) => match addr_iter.next() {
            Some(_) => Ok(arg_val.to_string()),
            None => Err(format!(
                "Could not parse \"{arg_val}\" as a valid remote uri"
            )),
        },
        Err(err) => Err(format!("{err}")),
    }
}

pub(crate) fn verify_url(arg_val: &str) -> Result<String, String> {
    let url = match Url::parse(arg_val) {
        Ok(addr) => addr,
        Err(_) => return Err(format!("Could not parse \"{}\" as a valid url.", arg_val)),
    };

    match url.scheme() {
        "http" => (),
        "https" => (),
        _ => return Err("Invalid scheme".to_string()),
    };

    if url.cannot_be_a_base() {
        return Err("Invalid scheme".to_string());
    }
    Ok(url.to_string())
}
