use crate::constants::*;
use crate::log::*;
use crate::utils::RequestQueryKey;
use regex::Regex;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct DomainBlockRule {
  pub domains: HashSet<String>,
}

impl DomainBlockRule {
  pub fn new(vec_domain_str: Vec<&str>) -> DomainBlockRule {
    // TODO: currently either one of prefix or suffix match with '*' is supported
    // TODO: Change to Patricia Trie data structure
    let start_with_star = Regex::new(r"^\*\..+").unwrap();
    let re = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN_OR_PREFIX, r"$")).unwrap(); // TODO: TODO:
    let hs: HashSet<String> = vec_domain_str
      .iter()
      .map(|d| {
        if start_with_star.is_match(d) {
          &d[2..]
        } else {
          d
        }
      })
      .filter(|x| re.is_match(x))
      .map(|y| y.to_string())
      .collect();

    DomainBlockRule { domains: hs }
  }

  pub fn should_block(&self, q_key: &RequestQueryKey) -> bool {
    // remove final dot
    let mut nn = q_key.clone().name;
    match nn.pop() {
      Some(dot) => {
        if dot != '.' {
          return true;
        }
      }
      None => {
        warn!("Null request!");
        return true;
      }
    }

    // exact match
    if self.domains.contains(&nn) {
      info!("domain blocked!: {}", nn);
      return true;
    }

    let nn_part: Vec<&str> = nn.split('.').collect();
    let parts_num = nn_part.len();
    if parts_num > 1 {
      for i in 1..parts_num {
        let suffix = nn_part[i..parts_num].join(".");
        let prefix = nn_part[0..parts_num - i].join(".");
        if self.domains.contains(&suffix) {
          debug!("domain suffix blocked!: {}", nn);
          return true;
        }

        if self.domains.contains(&format!("{}.*", prefix)) {
          debug!("domain prefix blocked!: {}", nn);
          return true;
        }
      }

      // TODO: other matching patterns
    }

    false
  }
}
