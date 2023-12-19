use crate::config::ServerConfig;
use crate::servers::mix_rpc::{MixReq, MixResp};
use crate::tor;
use grin_onion::crypto::dalek::{self, DalekPublicKey};
use grin_onion::onion::Onion;

use async_trait::async_trait;
use grin_api::json_rpc::{build_request, Response};
use grin_core::ser;
use grin_core::ser::ProtocolVersion;
use grin_wallet_util::OnionV3Address;
use hyper::client::HttpConnector;
use hyper::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};
use hyper_socks2::SocksConnector;
use serde_json;
use thiserror::Error;

/// Error types for interacting with nodes
#[derive(Error, Debug)]
pub enum ClientError {
	#[error("Tor Error: {0:?}")]
	Tor(tor::TorError),
	#[error("API Error: {0:?}")]
	API(grin_api::Error),
	#[error("Dalek Error: {0:?}")]
	Dalek(dalek::DalekError),
	#[error("Error decoding JSON response: {0:?}")]
	DecodeResponseError(serde_json::Error),
	#[error("Error in JSON-RPC response: {0:?}")]
	ResponseError(grin_api::json_rpc::RpcError),
	#[error("Custom client error: {0:?}")]
	Custom(String),
}

/// A client for consuming a mix API
#[async_trait]
pub trait MixClient: Send + Sync {
	/// Swaps the outputs provided and returns the final swapped outputs and kernels.
	async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, ClientError>;
}

pub struct MixClientImpl {
	config: ServerConfig,
	addr: OnionV3Address,
}

impl MixClientImpl {
	pub fn new(config: ServerConfig, next_pubkey: DalekPublicKey) -> Self {
		let addr = OnionV3Address::from_bytes(next_pubkey.as_ref().to_bytes());
		MixClientImpl { config, addr }
	}

	async fn async_send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		addr: &OnionV3Address,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, ClientError> {
		let proxy = {
			let proxy_uri = format!(
				"socks5://{}:{}",
				self.config.socks_proxy_addr.ip(),
				self.config.socks_proxy_addr.port()
			)
			.parse()
			.unwrap();
			let mut connector = HttpConnector::new();
			connector.enforce_http(false);
			let proxy_connector = SocksConnector {
				proxy_addr: proxy_uri,
				auth: None,
				connector,
			};
			proxy_connector
		};

		let url = format!("{}/v1", addr.to_http_str());

		let body =
			hyper::body::Body::from(serde_json::to_string(&build_request(method, params)).unwrap());

		let req = hyper::Request::builder()
			.method(hyper::Method::POST)
			.uri(url)
			.header(USER_AGENT, "grin-client")
			.header(ACCEPT, "application/json")
			.header(CONTENT_TYPE, "application/json")
			.body(body)
			.map_err(|e| {
				ClientError::API(grin_api::Error::RequestError(format!(
					"Cannot make request: {}",
					e
				)))
			})?;

		let client = hyper::Client::builder().build::<_, hyper::Body>(proxy);
		let res = client.request(req).await.unwrap();

		let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
		let res = String::from_utf8(body_bytes.to_vec()).unwrap();

		let response: Response =
			serde_json::from_str(&res).map_err(ClientError::DecodeResponseError)?;

		if let Some(ref e) = response.error {
			return Err(ClientError::ResponseError(e.clone()));
		}

		let result = match response.result.clone() {
			Some(r) => serde_json::from_value(r).map_err(ClientError::DecodeResponseError),
			None => serde_json::from_value(serde_json::Value::Null)
				.map_err(ClientError::DecodeResponseError),
		}?;

		Ok(result)
	}
}

#[async_trait]
impl MixClient for MixClientImpl {
	async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, ClientError> {
		let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
		let sig =
			dalek::sign(&self.config.key, serialized.as_slice()).map_err(ClientError::Dalek)?;
		// println!(
		// 	"Created sig ({:?}) with public key ({}) for server ({})",
		// 	&sig,
		// 	DalekPublicKey::from_secret(&self.config.key).to_hex(),
		// 	self.config.next_server.as_ref().unwrap().to_hex()
		// );
		let mix = MixReq::new(onions.clone(), sig);

		let params = serde_json::json!([mix]);

		self.async_send_json_request::<MixResp>(&self.addr, "mix", &params)
			.await
	}
}

#[cfg(test)]
pub mod mock {
	use super::{ClientError, MixClient};
	use grin_onion::onion::Onion;

	use crate::servers::mix_rpc::MixResp;
	use async_trait::async_trait;
	use std::collections::HashMap;

	pub struct MockMixClient {
		results: HashMap<Vec<Onion>, MixResp>,
	}

	impl MockMixClient {
		pub fn new() -> MockMixClient {
			MockMixClient {
				results: HashMap::new(),
			}
		}

		pub fn set_response(&mut self, onions: &Vec<Onion>, r: MixResp) {
			self.results.insert(onions.clone(), r);
		}
	}

	#[async_trait]
	impl MixClient for MockMixClient {
		async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, ClientError> {
			self.results
				.get(onions)
				.map(|r| Ok(r.clone()))
				.unwrap_or(Err(ClientError::Custom("No response set for input".into())))
		}
	}
}

#[cfg(test)]
pub mod test_util {
	use super::{ClientError, MixClient};
	use crate::servers::mix::MixServer;
	use crate::servers::mix_rpc::MixResp;
	use async_trait::async_trait;
	use grin_core::ser;
	use grin_core::ser::ProtocolVersion;
	use grin_onion::crypto::dalek::{self, DalekPublicKey};
	use grin_onion::crypto::secp::SecretKey;
	use grin_onion::onion::Onion;
	use std::sync::Arc;

	/// Implementation of the 'MixClient' trait that calls a mix server implementation directly.
	/// No JSON-RPC serialization or socket communication occurs.
	#[derive(Clone)]
	pub struct DirectMixClient {
		pub key: SecretKey,
		pub mix_server: Arc<dyn MixServer>,
	}

	#[async_trait]
	impl MixClient for DirectMixClient {
		async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, ClientError> {
			let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
			let sig = dalek::sign(&self.key, serialized.as_slice()).map_err(ClientError::Dalek)?;

			sig.verify(
				&DalekPublicKey::from_secret(&self.key),
				serialized.as_slice(),
			)
			.unwrap();
			Ok(self.mix_server.mix_outputs(&onions, &sig).await.unwrap())
		}
	}
}
