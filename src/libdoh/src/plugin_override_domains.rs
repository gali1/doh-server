use crate::constants::*;
use crate::log::*;
use crate::utils::RequestQueryKey;
use regex::Regex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use trust_dns_proto::rr::record_type::RecordType;

#[derive(Debug, Clone)]
pub enum MapsTo {
  Ipv4Addr(Ipv4Addr),
  Ipv6Addr(Ipv6Addr),
  // DomainName(String),
}

impl MapsTo {
  pub fn new(override_target: &str) -> Option<MapsTo> {
    // let re_domain = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN, r"$")).unwrap();
    let re_ipv4 = Regex::new(&format!("{}{}{}", r"^", REGEXP_IPV4, r"$")).unwrap();
    let re_ipv6 = Regex::new(&format!("{}{}{}", r"^", REGEXP_IPV6, r"$")).unwrap();

    if re_ipv4.is_match(override_target) {
      if let Ok(ipv4addr) = override_target.parse::<Ipv4Addr>() {
        Some(MapsTo::Ipv4Addr(ipv4addr))
      } else {
        None
      }
    } else if re_ipv6.is_match(override_target) {
      if let Ok(ipv6addr) = override_target.parse::<Ipv6Addr>() {
        Some(MapsTo::Ipv6Addr(ipv6addr))
      } else {
        None
      }
    } else {
      None
    }
  }
}

#[derive(Debug, Clone)]
pub struct DomainOverrideRule {
  pub domain_maps: HashMap<String, Vec<MapsTo>>,
}

impl DomainOverrideRule {
  pub fn new(vec_domain_map_str: Vec<&str>) -> DomainOverrideRule {
    let redomain_split_space =
      Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN, r"\s+\S+$")).unwrap();
    let hm: HashMap<String, Vec<MapsTo>> = vec_domain_map_str
      .iter()
      .filter(|x| redomain_split_space.is_match(x)) // filter by primary key (domain)
      .filter_map(|x| {
        let split: Vec<&str> = x.split_whitespace().collect();
        if split.len() != 2 {
          warn!("Invalid override rule: {}", split[0]);
          None
        } else {
          let targets: Vec<MapsTo> = split[1].split(',').filter_map(MapsTo::new).collect();
          let original_len = split[1].split(',').count();
          let res = match original_len == targets.len() {
            true => Some((split[0].to_string(), targets)),
            false => {
              warn!("Invalid override rule: {}", split[0]);
              None
            }
          };
          res
        }
      })
      .collect();
    DomainOverrideRule { domain_maps: hm }
  }

  pub fn find_and_override(&self, q_key: &RequestQueryKey) -> Option<&MapsTo> {
    let q_type = q_key.query_type;
    // remove final dot
    let mut nn = q_key.clone().name;
    match nn.pop() {
      Some(dot) => {
        if dot != '.' {
          return None;
        }
      }
      None => {
        warn!("Null request!");
        return None;
      }
    }
    // find matches
    if let Some(targets) = self.domain_maps.get(&nn) {
      return targets.iter().find(|x| match x {
        MapsTo::Ipv4Addr(_) => q_type == RecordType::A,
        MapsTo::Ipv6Addr(_) => q_type == RecordType::AAAA,
      });
    } else {
      None
    }
  }
}
