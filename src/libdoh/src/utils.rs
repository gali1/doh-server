use crate::log::*;
use crate::plugin_override_domains::MapsTo;
use anyhow::Error;
use std::convert::TryFrom;
use std::str::FromStr;
use trust_dns_proto::error::ProtoResult;
use trust_dns_proto::op::header::MessageType;
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::dns_class::DNSClass;
use trust_dns_proto::rr::domain::Name;
use trust_dns_proto::rr::record_data::RData;
use trust_dns_proto::rr::record_type::RecordType;
use trust_dns_proto::rr::resource::Record;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};

// https://github.com/aaronriekenberg/rust-doh-proxy/blob/master/src/doh/utils.rs
pub fn decode_dns_message(buf: Vec<u8>) -> ProtoResult<Message> {
  let mut decoder = BinDecoder::new(&buf);
  match Message::read(&mut decoder) {
    Ok(message) => Ok(message),
    Err(e) => {
      error!("Failed to decode dns message {}", e);
      Err(e)
    }
  }
}

pub fn encode_dns_message(msg: &Message) -> ProtoResult<Vec<u8>> {
  let mut request_buffer = Vec::new();

  let mut encoder = BinEncoder::new(&mut request_buffer);
  match msg.emit(&mut encoder) {
    Ok(_) => {
      let len = request_buffer.len();
      debug!("encoded message request_buffer.len = {}", len);
      Ok(request_buffer)
    }
    Err(e) => {
      error!("error encoding message request buffer {}", e);
      Err(e)
    }
  }
}

pub fn generate_block_message(msg: &Message) -> Message {
  let mut res = msg.clone();
  res.set_message_type(trust_dns_proto::op::MessageType::Response);
  // res.set_response_code(trust_dns_proto::op::ResponseCode::ServFail);
  res.set_response_code(trust_dns_proto::op::ResponseCode::NXDomain);
  res
}

pub fn generate_override_message(
  msg: &Message,
  q_key: &RequestQueryKey,
  mapsto: &MapsTo,
  min_ttl: u32,
) -> Result<Message, Error> {
  let mut res = msg.clone();
  res.set_message_type(trust_dns_proto::op::MessageType::Response);
  res.set_response_code(trust_dns_proto::op::ResponseCode::NoError);
  let name = Name::from_str(&q_key.name)?;
  match mapsto {
    MapsTo::Ipv4Addr(ipv4) => {
      res.insert_answers(vec![Record::from_rdata(name, min_ttl, RData::A(*ipv4))]);
    }
    MapsTo::Ipv6Addr(ipv6) => {
      res.insert_answers(vec![Record::from_rdata(name, min_ttl, RData::AAAA(*ipv6))]);
    }
  }
  Ok(res)
}

// https://github.com/aaronriekenberg/rust-doh-proxy/blob/master/src/doh/request_key.rs
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestQueryKey {
  pub name: String,
  pub query_type: RecordType,
  pub query_class: DNSClass,
}

impl RequestQueryKey {
  pub fn key_string(self) -> String {
    format!("{:?} {:?} {}", self.query_type, self.query_class, self.name)
  }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestKey {
  query_keys: Vec<RequestQueryKey>,
}

impl<'a> RequestKey {
  pub fn keys(&'a self) -> &'a Vec<RequestQueryKey> {
    &self.query_keys
  }
}

impl TryFrom<&Message> for RequestKey {
  type Error = &'static str;

  fn try_from(message: &Message) -> Result<Self, Self::Error> {
    if message.message_type() != MessageType::Query {
      return Err("Invalid query");
    }
    let mut query_keys = Vec::with_capacity(message.queries().len());

    for query in message.queries() {
      let mut name_string = query.name().to_string();
      name_string.make_ascii_lowercase();

      query_keys.push(RequestQueryKey {
        name: name_string,
        query_type: query.query_type(),
        query_class: query.query_class(),
      });
    }

    match query_keys.len() {
      0 => Err("query_keys is empty"),
      1 => Ok(RequestKey { query_keys }),
      _ => {
        query_keys.sort();
        Ok(RequestKey { query_keys })
      }
    }
  }
}
