use crate::globals::{Globals, ValidationLocation};
use anyhow::{anyhow, Error};
use jwt_simple::prelude::*;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::str::FromStr;

#[derive(Debug)]
pub enum Algorithm {
  ES256,
  HS256,
  HS384,
  HS512,
}
impl FromStr for Algorithm {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Error> {
    match s {
      "HS256" => Ok(Algorithm::HS256),
      "HS384" => Ok(Algorithm::HS384),
      "HS512" => Ok(Algorithm::HS512),
      "ES256" => Ok(Algorithm::ES256),
      // "ES384" => Ok(Algorithm::ES384),
      // "RS256" => Ok(Algorithm::RS256),
      // "RS384" => Ok(Algorithm::RS384),
      // "PS256" => Ok(Algorithm::PS256),
      // "PS384" => Ok(Algorithm::PS384),
      // "PS512" => Ok(Algorithm::PS512),
      // "RS512" => Ok(Algorithm::RS512),
      _ => Err(anyhow!("Invalid Algorithm Name")),
    }
  }
}
#[derive(Debug, Clone)]
pub enum JwtValidationKey {
  ES256(ES256PublicKey),
  HS256(HS256Key),
  HS384(HS384Key),
  HS512(HS512Key),
}

impl JwtValidationKey {
  pub fn new(validation_algorithm: &Algorithm, key_str: &str) -> Result<Self, Error> {
    let validation_key = match validation_algorithm {
      Algorithm::HS256 => JwtValidationKey::HS256(HS256Key::from_bytes(key_str.as_ref())),
      Algorithm::HS384 => JwtValidationKey::HS384(HS384Key::from_bytes(key_str.as_ref())),
      Algorithm::HS512 => JwtValidationKey::HS512(HS512Key::from_bytes(key_str.as_ref())),
      Algorithm::ES256 => {
        let public_key = key_str.parse::<p256::PublicKey>()?;
        let sec1key = public_key.to_encoded_point(false);
        JwtValidationKey::ES256(ES256PublicKey::from_bytes(sec1key.as_bytes())?)
      } // _ => {
        //   return Err("Unsupported Key Type")?;
        // }
    };
    Ok(validation_key)
  }

  pub fn verify_token(
    &self,
    jwt: &str,
    globals: &Globals,
    loc: ValidationLocation,
  ) -> Result<jwt_simple::claims::JWTClaims<NoCustomClaims>, Error> {
    // Treat a given token as ID token
    // Check audience and issuer if they are set when start
    let options = match loc {
      ValidationLocation::Target => globals.validation_options_target.clone(),
      ValidationLocation::Proxy => globals.validation_options_proxy.clone(),
    };
    let clm = match self {
      JwtValidationKey::ES256(pk) => pk.verify_token::<NoCustomClaims>(jwt, options),
      JwtValidationKey::HS256(k) => k.verify_token::<NoCustomClaims>(jwt, options),
      JwtValidationKey::HS384(k) => k.verify_token::<NoCustomClaims>(jwt, options),
      JwtValidationKey::HS512(k) => k.verify_token::<NoCustomClaims>(jwt, options),
      // _ => Err("Unsupported Algorithm")?,
    };
    match clm {
      Ok(c) => Ok(c),
      Err(e) => Err(e),
    }
  }
}
