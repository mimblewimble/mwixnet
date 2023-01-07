use crate::config::ServerConfig;
use crate::crypto::dalek;
use crate::onion::Onion;
use crate::servers::mix_rpc::MixReq;
use crate::tx::TxComponents;
use crate::{tor, DalekPublicKey};

use grin_api::client;
use grin_api::json_rpc::build_request;
use grin_core::ser;
use grin_core::ser::ProtocolVersion;
use grin_wallet_util::OnionV3Address;
use hyper::client::HttpConnector;
use hyper_proxy::{Intercept, Proxy, ProxyConnector};
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
	#[error("Error parsing response: {0:?}")]
	ResponseParse(serde_json::Error),
	#[error("Custom client error: {0:?}")]
	Custom(String),
}

/// A client for consuming a mix API
pub trait MixClient: Send + Sync {
	/// Swaps the outputs provided and returns the final swapped outputs and kernels.
	fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<(Vec<usize>, TxComponents), ClientError>;
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

	fn send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		addr: &OnionV3Address,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, ClientError> {
		let _tor = tor::init_tor_sender(&self.config).map_err(ClientError::Tor)?;

		let proxy = {
			let proxy_uri = format!("http://{:?}", self.config.socks_proxy_addr)
				.parse()
				.unwrap();
			let proxy = Proxy::new(Intercept::All, proxy_uri);
			//proxy.set_authorization(Authorization::basic("John Doe", "Agent1234"));
			let connector = HttpConnector::new();
			let proxy_connector = ProxyConnector::from_proxy(connector, proxy).unwrap();
			proxy_connector
		};

		let url = format!("{}/v1", addr.to_http_str());
		let mut req = client::create_post_request(&url, None, &build_request(method, params))
			.map_err(ClientError::API)?;

		let uri = url.parse().unwrap();
		if let Some(headers) = proxy.http_headers(&uri) {
			req.headers_mut().extend(headers.clone().into_iter());
		}

		let res = client::send_request(req).map_err(ClientError::API)?;

		serde_json::from_str(&res).map_err(ClientError::ResponseParse)
	}
}

impl MixClient for MixClientImpl {
	fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<(Vec<usize>, TxComponents), ClientError> {
		let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
		let sig =
			dalek::sign(&self.config.key, serialized.as_slice()).map_err(ClientError::Dalek)?;
		let mix = MixReq::new(onions.clone(), sig);

		let params = serde_json::json!(mix);

		self.send_json_request::<(Vec<usize>, TxComponents)>(&self.addr, "mix", &params)
	}
}

#[cfg(test)]
pub mod mock {
	use super::{ClientError, MixClient};
	use crate::onion::Onion;
	use crate::tx::TxComponents;

	use std::collections::HashMap;

	pub struct MockMixClient {
		results: HashMap<Vec<Onion>, (Vec<usize>, TxComponents)>,
	}

	impl MockMixClient {
		pub fn new() -> MockMixClient {
			MockMixClient {
				results: HashMap::new(),
			}
		}

		pub fn set_response(&mut self, onions: &Vec<Onion>, r: (Vec<usize>, TxComponents)) {
			self.results.insert(onions.clone(), r);
		}
	}

	impl MixClient for MockMixClient {
		fn mix_outputs(
			&self,
			onions: &Vec<Onion>,
		) -> Result<(Vec<usize>, TxComponents), ClientError> {
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
	use crate::crypto::dalek;
	use crate::crypto::secp::SecretKey;
	use crate::onion::Onion;
	use crate::servers::mix::MixServer;
	use crate::tx::TxComponents;
	use crate::DalekPublicKey;
	use grin_core::ser;
	use grin_core::ser::ProtocolVersion;
	use std::sync::Arc;

	/// Implementation of the 'MixClient' trait that calls a mix server implementation directly.
	/// No JSON-RPC serialization or socket communication occurs.
	#[derive(Clone)]
	pub struct DirectMixClient {
		pub key: SecretKey,
		pub mix_server: Arc<dyn MixServer>,
	}

	impl MixClient for DirectMixClient {
		fn mix_outputs(
			&self,
			onions: &Vec<Onion>,
		) -> Result<(Vec<usize>, TxComponents), ClientError> {
			let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
			let sig = dalek::sign(&self.key, serialized.as_slice()).map_err(ClientError::Dalek)?;

			sig.verify(
				&DalekPublicKey::from_secret(&self.key),
				serialized.as_slice(),
			)
			.unwrap();
			Ok(self.mix_server.mix_outputs(&onions, &sig).unwrap())
		}
	}
}
