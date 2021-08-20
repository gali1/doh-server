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

use crate::globals::*;
use hyper::{Body, Response, StatusCode};
use jwt_simple::prelude::{JWTClaims, NoCustomClaims};
use log::{debug, error, info, warn};
use std::collections::HashSet;
// use serde_json;

pub fn authenticate(
  globals: &Globals,
  headers: &hyper::HeaderMap,
  loc: ValidationLocation,
) -> Result<(Option<String>, Option<HashSet<String>>), Response<Body>> {
  debug!("auth::authenticate, {:?}", headers);

  let headers_map = headers.get(hyper::header::AUTHORIZATION);
  let res = match headers_map {
    None => {
      warn!("No authorization header");
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
