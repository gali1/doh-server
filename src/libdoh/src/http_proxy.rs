use crate::errors::DoHError;
use hyper::http::StatusCode;
use reqwest::header;

#[derive(Debug, Clone)]
pub enum ProxyMethod {
  GET,
  POST,
}

#[derive(Debug, Clone)]
pub struct HttpProxyClient {
  client: reqwest::Client,
  method: ProxyMethod,
}

impl HttpProxyClient {
  pub fn new(timeout: std::time::Duration) -> Result<Self, DoHError> {
    // build client
    let mut headers = header::HeaderMap::new();
    let ct = "application/oblivious-dns-message";
    headers.insert("Accept", header::HeaderValue::from_str(&ct).unwrap());
    headers.insert("Content-Type", header::HeaderValue::from_str(&ct).unwrap());

    let client = reqwest::Client::builder()
      .user_agent(format!("odoh-proxy/{}", env!("CARGO_PKG_VERSION")))
      .timeout(timeout)
      .trust_dns(true)
      .default_headers(headers)
      .build()
      .map_err(|e| DoHError::Reqwest(e))?;

    Ok(HttpProxyClient {
      client,
      method: ProxyMethod::POST, // TODO: GET対応
    })
  }

  pub async fn forward_to_target(
    &self,
    encrypted_query: &Vec<u8>,
    target_uri: &str,
  ) -> Result<Vec<u8>, StatusCode> {
    // TODO: GET対応
    let response = self
      .client
      .post(target_uri)
      .body(encrypted_query.clone())
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

    let body = response.bytes().await.map_err(|e| DoHError::Reqwest(e))?;
    Ok(body.to_vec())
  }
}
