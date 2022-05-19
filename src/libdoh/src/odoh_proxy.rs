use crate::constants::*;
use crate::errors::DoHError;
use hyper::http::StatusCode;
use regex::Regex;
use reqwest::header;
use std::collections::HashMap;

fn number_from_query_key(query_key: &str) -> usize {
    let regex_num = Regex::new(r"\d+").unwrap();
    let num_str = regex_num.captures(query_key).unwrap();
    (&num_str[0]).parse::<usize>().unwrap()
}

pub fn relay_url_from_query_string(
    http_query: &str,
) -> Result<Vec<(String, String)>, DoHError> {
    let mut hm_host_path: HashMap<usize, (Option<String>, Option<String>)> = HashMap::new();
    let relayhost_regex = Regex::new(&format!("{}{}{}", r"^", MODOH_PROXY_HOST_QUERY_PARAM, r"\[\d+\]$")).unwrap();
    let relaypath_regex = Regex::new(&format!("{}{}{}", r"^", MODOH_PROXY_PATH_QUERY_PARAM, r"\[\d+\]$")).unwrap();
    for parts in http_query.split('&') {
        let mut kv = parts.split('=');
        if let Some(k) = kv.next() {
            if relayhost_regex.is_match(k) {
                let num = number_from_query_key(k);
                let hp = hm_host_path.entry(num).or_insert((None, None));
                hp.0 = kv.next().map(str::to_string);
            }
            if relaypath_regex.is_match(k) {
                let num = number_from_query_key(k);
                let hp = hm_host_path.entry(num).or_insert((None, None));
                hp.1 = kv.next().map(str::to_string);
            }
        }
    }

    let mut vec_host_path: Vec<(String, String)> = Vec::new();
    for i in 0..hm_host_path.len() {
        match hm_host_path.get(&i) {
            Some((Some(h), Some(p))) => {
                    vec_host_path.push((h.to_string(), p.to_string()));
            },
            Some((_, _)) => {
                return Err(DoHError::InvalidData);
            },
            None => {
                return Err(DoHError::InvalidData);
            }
        }
    }
    Ok(vec_host_path)
}

pub fn target_uri_from_query_string(http_query: &str) -> (Option<String>, Option<String>) {
    let mut targethost = None;
    let mut targetpath = None;
    for parts in http_query.split('&') {
        let mut kv = parts.split('=');
        if let Some(k) = kv.next() {
            match k {
                ODOH_TARGET_HOST_QUERY_PARAM => {
                    targethost = kv.next().map(str::to_string);
                }
                ODOH_TARGET_PATH_QUERY_PARAM => {
                    targetpath = kv.next().map(str::to_string);
                }
                _ => (),
            }
        }
    }
    (targethost, targetpath)
}

#[derive(Debug, Clone)]
pub struct ODoHProxy {
    client: reqwest::Client,
}

impl ODoHProxy {
    pub fn new(timeout: std::time::Duration) -> Result<Self, DoHError> {
        // build client
        let mut headers = header::HeaderMap::new();
        let ct = "application/oblivious-dns-message";
        headers.insert("Accept", header::HeaderValue::from_str(ct).unwrap());
        headers.insert("Content-Type", header::HeaderValue::from_str(ct).unwrap());
        headers.insert(
            "Cache-Control",
            header::HeaderValue::from_str("no-cache, no-store").unwrap(),
        );

        let client = reqwest::Client::builder()
            .user_agent(format!("odoh-proxy/{}", env!("CARGO_PKG_VERSION")))
            .timeout(timeout)
            .trust_dns(true)
            .default_headers(headers)
            .build()
            .map_err(DoHError::Reqwest)?;

        Ok(ODoHProxy { client })
    }

    pub async fn forward_to_target(
        &self,
        encrypted_query: &[u8],
        target_uri: &str,
    ) -> Result<Vec<u8>, StatusCode> {
        // Only post method is allowed in ODoH
        let response = self
            .client
            .post(target_uri)
            .body(encrypted_query.to_owned())
            .send()
            .await
            .map_err(|e| {
                eprintln!("[ODoH Proxy] Upstream query error: {}", e);
                DoHError::Reqwest(e)
            })?;

        if response.status() != reqwest::StatusCode::OK {
            eprintln!("[ODoH Proxy] Response not ok: {:?}", response.status());
            return Err(response.status());
        }

        let body = response.bytes().await.map_err(DoHError::Reqwest)?;
        Ok(body.to_vec())
    }
}
