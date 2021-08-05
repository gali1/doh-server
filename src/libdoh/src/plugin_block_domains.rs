use crate::utils::RequestQueryKey;
use log::{debug, error, info, warn};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct DomainBlockList {
  pub domains: HashSet<String>,
}

impl DomainBlockList {
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
      debug!("domain blocked!: {}", nn);
      return true;
    }

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
          debug!("domain suffix blocked!: {}", nn);
          return true;
        }

        if self.domains.contains(&format!("{}.*", prefix)) {
          debug!("domain prefix blocked!: {}", nn);
          return true;
        }
        prefix = format!("{}.{}", prefix, nn_part[i - 1]);
      }

      // TODO: other matching patterns
    }
    false
  }
}
