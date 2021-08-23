use crate::constants::*;
use crate::log::*;
use crate::utils::{reverse_string, str_vec_to_domain, RequestQueryKey};
use qp_trie::Trie;
use regex::Regex;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct DomainBlockRule {
  pub domains: HashSet<String>,
  pub suffix_qp: Trie<qp_trie::wrapper::BString, ()>,
}

impl DomainBlockRule {
  pub fn new(vec_domain_str: Vec<&str>) -> DomainBlockRule {
    // TODO: currently either one of prefix or suffix match with '*' is supported
    // TODO: Change to Patricia Trie data structure
    let re = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN_OR_PREFIX, r"$")).unwrap(); // TODO: TODO:
    let hs: HashSet<String> = vec_domain_str
      .iter()
      .filter(|x| re.is_match(x))
      .map(|y| y.to_string())
      .collect();

    // QP Trie for suffix shortest match
    let mut suffix_qp: Trie<qp_trie::wrapper::BString, ()> = Trie::new();
    debug!("Creating qp trie for domain block");
    for domain in vec_domain_str.into_iter().enumerate() {
      suffix_qp.insert_str(&reverse_string(domain.1), ());
    }

    DomainBlockRule {
      domains: hs,
      suffix_qp,
    }
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

    let qp_start = std::time::Instant::now(); // TODO:

    // check longest common suffix with qptrie
    let rev_qn = reverse_string(&nn);
    let longest_common_suffix = self
      .suffix_qp
      .longest_common_prefix(rev_qn.as_bytes())
      .as_str();

    // retrieve the exact domain part of the matched suffix
    let vec_lcs_split = longest_common_suffix.split(".");
    let vec_rqn_split = rev_qn.split(".");
    let common_domain_suffix: Vec<&str> = vec_lcs_split
      .zip(vec_rqn_split)
      .filter(|(x, y)| x == y)
      .map(|(x, _)| x)
      .collect();
    // check from longer domain suffixes if it is included in the trie
    let domain_parts_num = common_domain_suffix.len();
    for idx in 0..domain_parts_num {
      let domain_to_match =
        str_vec_to_domain(&common_domain_suffix[0..domain_parts_num - idx].to_vec());
      if self.suffix_qp.contains_key_str(&domain_to_match) {
        info!("[Block] matched domain suffix rule: {}", domain_to_match);
        break;
      } else if self
        .suffix_qp
        .contains_key_str(&format!("{}.*", domain_to_match))
      {
        info!("[Block] matched domain suffix rule: {}", domain_to_match);
        break;
      }
    }
    let qp_end = qp_start.elapsed();

    info!(
      "[Block] QP: {:6}ms経過しました。",
      qp_end.subsec_nanos() / 1_000
    );

    let hs_start = std::time::Instant::now(); // TODO

    // exact match
    if self.domains.contains(&nn) {
      info!("domain blocked!: {}", nn);
      return true;
    }

    let mut return_val = false;
    let nn_part: Vec<&str> = nn.split('.').collect();
    let parts_num = nn_part.len();
    if parts_num > 2 {
      // suffix match patterns
      let mut suffix = nn_part[parts_num - 1].to_string();
      // prefix match patterns
      let mut prefix = nn_part[0].to_string();
      for i in 2..parts_num {
        suffix = format!("{}.{}", nn_part[parts_num - i], suffix);
        if self.domains.contains(&suffix) {
          info!("domain suffix blocked!: {}", nn);
          // return true;
          return_val = true;
          break;
        }

        if self.domains.contains(&format!("{}.*", prefix)) {
          info!("domain prefix blocked!: {}", nn);
          // return true;
          return_val = true;
          break;
        }
        prefix = format!("{}.{}", prefix, nn_part[i - 1]);
      }

      // TODO: other matching patterns
    }
    let hs_end = hs_start.elapsed();

    info!(
      "[Block] HS: {:6}ms経過しました。",
      hs_end.subsec_nanos() / 1_000
    );

    // false
    return return_val;
  }
}
