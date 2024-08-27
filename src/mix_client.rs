use std::sync::Arc;

use async_trait::async_trait;
use grin_api::json_rpc::{build_request, Response};
use grin_core::ser;
use grin_core::ser::ProtocolVersion;
use grin_wallet_util::OnionV3Address;
use serde_json;
use serde_json::json;
use thiserror::Error;
use tor_rtcompat::Runtime;

use grin_wallet_libwallet::mwixnet::onion as grin_onion;
use grin_onion::crypto::dalek::{self, DalekPublicKey};
use grin_onion::onion::Onion;

use crate::config::ServerConfig;
use crate::servers::mix_rpc::{MixReq, MixResp};
use crate::tor::TorService;
use crate::{http, tor};

/// Error types for interacting with nodes
#[derive(Error, Debug)]
pub enum MixClientError {
	#[error("Tor Error: {0:?}")]
	Tor(tor::TorError),
	#[error("Communication Error: {0:?}")]
	CommError(http::HttpError),
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
	async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError>;
}

pub struct MixClientImpl<R: Runtime> {
	config: ServerConfig,
	tor: Arc<grin_util::Mutex<TorService<R>>>,
	addr: OnionV3Address,
}

impl<R: Runtime> MixClientImpl<R> {
	pub fn new(
		config: ServerConfig,
		tor: Arc<grin_util::Mutex<TorService<R>>>,
		next_pubkey: DalekPublicKey,
	) -> Self {
		let addr = OnionV3Address::from_bytes(next_pubkey.as_ref().to_bytes());
		MixClientImpl { config, tor, addr }
	}

	async fn async_send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		addr: &OnionV3Address,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, MixClientError> {
		let url = format!("{}/v1", addr.to_http_str());
		let request_str = serde_json::to_string(&build_request(method, params)).unwrap();
		let hyper_request =
			http::build_request(&url, &None, request_str).map_err(MixClientError::CommError)?;

		let hyper_client = self.tor.lock().new_hyper_client();
		let res = hyper_client.request(hyper_request).await.unwrap();

		let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap();
		let res = String::from_utf8(body_bytes.to_vec()).unwrap();

		let response: Response =
			serde_json::from_str(&res).map_err(MixClientError::DecodeResponseError)?;

		if let Some(ref e) = response.error {
			return Err(MixClientError::ResponseError(e.clone()));
		}

		let result = match response.result.clone() {
			Some(r) => serde_json::from_value(r).map_err(MixClientError::DecodeResponseError),
			None => serde_json::from_value(serde_json::Value::Null)
				.map_err(MixClientError::DecodeResponseError),
		}?;

		Ok(result)
	}
}

#[async_trait]
impl<R: Runtime> MixClient for MixClientImpl<R> {
	async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
		let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
		let sig =
			dalek::sign(&self.config.key, serialized.as_slice()).map_err(MixClientError::Dalek)?;
		let mix = MixReq::new(onions.clone(), sig);

		self.async_send_json_request::<MixResp>(&self.addr, "mix", &json!([mix]))
			.await
	}
}

#[cfg(test)]
pub mod mock {
	use std::collections::HashMap;

	use async_trait::async_trait;

	use grin_onion::onion::Onion;

	use crate::servers::mix_rpc::MixResp;

	use super::{MixClient, MixClientError};

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
		async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
			self.results
				.get(onions)
				.map(|r| Ok(r.clone()))
				.unwrap_or(Err(MixClientError::Custom(
					"No response set for input".into(),
				)))
		}
	}
}

#[cfg(test)]
pub mod test_util {
	use std::sync::Arc;

	use async_trait::async_trait;
	use grin_core::ser;
	use grin_core::ser::ProtocolVersion;

	use grin_onion::crypto::dalek::{self, DalekPublicKey};
	use grin_onion::crypto::secp::SecretKey;
	use grin_onion::onion::Onion;

	use crate::servers::mix::MixServer;
	use crate::servers::mix_rpc::MixResp;

	use super::{MixClient, MixClientError};

	/// Implementation of the 'MixClient' trait that calls a mix server implementation directly.
	/// No JSON-RPC serialization or socket communication occurs.
	#[derive(Clone)]
	pub struct DirectMixClient {
		pub key: SecretKey,
		pub mix_server: Arc<dyn MixServer>,
	}

	#[async_trait]
	impl MixClient for DirectMixClient {
		async fn mix_outputs(&self, onions: &Vec<Onion>) -> Result<MixResp, MixClientError> {
			let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
			let sig =
				dalek::sign(&self.key, serialized.as_slice()).map_err(MixClientError::Dalek)?;

			sig.verify(
				&DalekPublicKey::from_secret(&self.key),
				serialized.as_slice(),
			)
			.unwrap();
			Ok(self.mix_server.mix_outputs(&onions, &sig).await.unwrap())
		}
	}
}
