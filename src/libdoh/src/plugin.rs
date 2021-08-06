use crate::errors::DoHError;
use crate::plugin_block_domains::DomainBlockRule;
use crate::plugin_override_domains::DomainOverrideRule;
use crate::utils;
use crate::utils::RequestQueryKey;
use log::{debug, error, info, warn};
use trust_dns_proto::op::Message;

#[derive(Debug, Clone)]
pub struct QueryPluginExecutionResult {
  pub action: QueryPluginAction,
  pub response_msg: Option<Message>,
}

#[derive(Debug, Clone)]
pub enum QueryPluginAction {
  Blocked,
  Overridden,
  Pass,
}

#[derive(Debug, Clone)]
pub struct AppliedQueryPlugins {
  pub plugins: Vec<QueryPlugin>,
}

impl AppliedQueryPlugins {
  pub fn new() -> AppliedQueryPlugins {
    AppliedQueryPlugins {
      plugins: Vec::new(),
    }
  }

  pub fn add(&mut self, plugin: QueryPlugin) {
    self.plugins.push(plugin);
  }

  pub fn execute(
    self,
    dns_msg: &Message,
    q_key: &RequestQueryKey,
    min_ttl: u32,
  ) -> Result<QueryPluginExecutionResult, DoHError> {
    let mut response = QueryPluginExecutionResult {
      action: QueryPluginAction::Pass,
      response_msg: None,
    };

    for plugin in self.plugins {
      match plugin {
        QueryPlugin::PluginDomainOverride(override_rule) => {
          if let Some(mapsto) = override_rule.find_and_override(q_key) {
            info!("Query {} maps to {:?}", q_key.name, mapsto);
            response.action = QueryPluginAction::Overridden;
            response.response_msg = Some(
              utils::generate_override_message(&dns_msg, q_key, mapsto, min_ttl)
                .map_err(|_| DoHError::InvalidData)?,
            );
            break;
          }
        }
        QueryPlugin::PluginDomainBlock(block_rule) => {
          if block_rule.should_block(q_key) {
            info!("Query {} is blocked", q_key.name);
            response.action = QueryPluginAction::Blocked;
            response.response_msg = Some(utils::generate_block_message(&dns_msg));
          }
        }
      }
    }
    Ok(response)
  }
}

#[derive(Debug, Clone)]
pub enum QueryPlugin {
  PluginDomainBlock(DomainBlockRule),
  PluginDomainOverride(DomainOverrideRule),
}
