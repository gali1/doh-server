/*
// サンプルcurlコード
// for "secret" of HS256
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjI1NjUzNDMyLCJleHAiOjE2NTcxODk0MzJ9.REuGilzx8syXPYdKSpAwxutXtx3HAvfrTh3As1TBUOg" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
// for "random_secret" of HS256
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjI1NjUzNTYwLCJleHAiOjE2NTcxODk1NjB9.vbjO3RKchY1vTfZpERenbAnxGJivQU2VVw6tjhjKqTY" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
// for "ThisIsExampleSecret" (secret_key_hs256.example) of HS256
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjI1NjU1ODI3LCJleHAiOjE2NTcxOTE4Mjd9.Bm19G1-jT8PFKy086svAGTOM8k2Yhsr_FH1KQTwuZ6o" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
// for ES256 (public_key_es256.example)
curl -i -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJzYW1wbGUtc3ViamVjdCIsImlhdCI6MTYyNTY1NTM5NywiZXhwIjoxOTQxMDE1Mzk3fQ._Wxohc89qpyRw0zXMiFh8Gof8UdgOsh2enmmUeWaOLaTAaagqVkxYGCCgj6FqHlGUkm2vrB4JQES370z8xCTdQ" -H 'accept: application/dns-message' 'http://localhost:58080/dns-query?dns=rmUBAAABAAAAAAAAB2NhcmVlcnMHb3BlbmRucwNjb20AAAEAAQ' | hexdump -C
*/

use crate::constants::*;
use crate::globals::*;
use crate::log::*;
use hyper::{Body, Response, StatusCode};
use jwt_simple::prelude::{JWTClaims, NoCustomClaims};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

fn retrieve_item_ip(header_key: &str, headers: &hyper::header::HeaderMap) -> Option<IpAddr> {
  if let Some(val) = headers.get(header_key) {
    if let Ok(string_item) = val.to_str() {
      let items: Vec<&str> = string_item
        .split_whitespace()
        .flat_map(|x| x.split(","))
        .collect();
      if items.len() > 0 {
        if let Ok(parsed) = items[0].parse::<IpAddr>() {
          return Some(parsed);
        }
      }
    }
  };
  None
}
// This follows request-ip of npm
// https://www.npmjs.com/package/request-ip
fn retrieve_real_ip(req: &hyper::Request<hyper::Body>) -> Option<IpAddr> {
  let headers = req.headers();
  for i in HEADER_IP_KEYS {
    if let Some(item) = retrieve_item_ip(i, headers) {
      return Some(item);
    }
  }
  // if nothing is in the request header, return None. use remote_addr.
  None
}

pub fn authenticate(
  globals: &Globals,
  req: &hyper::Request<hyper::Body>,
  loc: ValidationLocation,
  peer_addr: &SocketAddr,
) -> Result<(Option<String>, Option<HashSet<String>>), Response<Body>> {
  let headers = req.headers();
  debug!("auth::authenticate, request header\n{:#?}", headers);

  let headers_map = headers.get(hyper::header::AUTHORIZATION);
  let res = match headers_map {
    None => {
      // (O)DOH Targetの場合、ソースIPをここでチェックして弾く。Allowの場合はJWT無しでもOKにする。
      if let ValidationLocation::Target = loc {
        match &globals.odoh_allowed_proxy_ips {
          Some(allowed_ips) => {
            debug!("peer's Socket addr from TCP stream: {:?}", peer_addr);
            let real_ip = if let Some(ip) = retrieve_real_ip(req) {
              ip
            } else {
              peer_addr.ip()
            };
            debug!("real_ip from http header or tcp stream: {:?}", real_ip);
            if allowed_ips.contains(&real_ip) {
              debug!("real_ip is in allow list");
              return Ok((None, None));
            }
          }
          None => (),
        }
      };
      warn!("No authorization header and source addr is not in allow list");
      Err(StatusCode::BAD_REQUEST)
    }
    Some(auth_header) => {
      if let Ok(s) = auth_header.to_str() {
        let v: Vec<&str> = s.split(" ").collect();
        if "Bearer" == v[0] && v.len() == 2 {
          verify_jwt(globals, v[1], loc)
        } else {
          error!("Invalid authorization header format");
          Err(StatusCode::BAD_REQUEST)
        }
      } else {
        error!("Invalid authorization header format");
        Err(StatusCode::BAD_REQUEST)
      }
    }
  };
  match res {
    Err(e) => Err(Response::builder().status(e).body(Body::empty()).unwrap()),
    Ok(clm) => {
      let aud = if let Some(a) = clm.audiences {
        Some(a.into_set())
      } else {
        None
      };
      Ok((clm.subject, aud))
    }
  }
}

fn verify_jwt(
  globals: &Globals,
  jwt: &str,
  loc: ValidationLocation,
) -> Result<JWTClaims<NoCustomClaims>, StatusCode> {
  debug!("auth::verify_jwt {:?}", jwt);
  let vk = match loc {
    ValidationLocation::Target => &globals.validation_key_target,
    ValidationLocation::Proxy => &globals.validation_key_proxy,
  };

  let pk = match vk {
    Some(pk) => pk,
    None => {
      error!("Invalid configuration");
      return Err(StatusCode::FORBIDDEN);
    }
  };
  let clm = pk.verify_token(jwt, globals, loc);
  // TODO: check sub?
  // I think it is not needed provided token expiration (short-term) is properly handled.
  match clm {
    Ok(c) => {
      return Ok(c);
    }
    Err(e) => {
      warn!("Invalid token: {:?}", e);
      return Err(StatusCode::FORBIDDEN);
    }
  }
}
