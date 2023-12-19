use async_trait::async_trait;
use grin_api::client;
use grin_api::json_rpc::{build_request, Request, Response, RpcError};
use grin_core::core::Output;
use grin_core::libtx::secp_ser;
use grin_keychain::BlindingFactor;
use grin_onion::crypto::secp;
use grin_util::{ToHex, ZeroingString};
use grin_wallet_api::{EncryptedRequest, EncryptedResponse, JsonId, Token};
use secp256k1zkp::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use thiserror::Error;

#[async_trait]
pub trait Wallet: Send + Sync {
	/// Builds an output for the wallet with the provided amount.
	async fn async_build_output(
		&self,
		amount: u64,
	) -> Result<(BlindingFactor, Output), WalletError>;
}

/// Error types for interacting with wallets
#[derive(Error, Debug)]
pub enum WalletError {
	#[error("Error encrypting request: {0:?}")]
	EncryptRequestError(grin_wallet_libwallet::Error),
	#[error("Error decrypting response: {0:?}")]
	DecryptResponseError(grin_wallet_libwallet::Error),
	#[error("Error decoding JSON response: {0:?}")]
	DecodeResponseError(serde_json::Error),
	#[error("JSON-RPC API communication error: {0:?}")]
	ApiCommError(grin_api::Error),
	#[error("Error decoding JSON-RPC response: {0:?}")]
	ResponseParseError(grin_api::json_rpc::Error),
	#[error("Unsucessful response returned: {0:?}")]
	ResponseRpcError(Option<RpcError>),
}

/// HTTP (JSONRPC) implementation of the 'Wallet' trait.
#[derive(Clone)]
pub struct HttpWallet {
	wallet_owner_url: SocketAddr,
	wallet_owner_secret: Option<String>,
	shared_key: SecretKey,
	token: Token,
}

const ENDPOINT: &str = "/v3/owner";

/// Wrapper for ECDH Public keys
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct ECDHPubkey {
	/// public key, flattened
	#[serde(with = "secp_ser::pubkey_serde")]
	pub ecdh_pubkey: PublicKey,
}

impl HttpWallet {
	/// Calls the 'open_wallet' using the RPC API.
	pub async fn async_open_wallet(
		wallet_owner_url: &SocketAddr,
		wallet_owner_secret: &Option<String>,
		wallet_pass: &ZeroingString,
	) -> Result<HttpWallet, WalletError> {
		info!("Opening wallet at {}", wallet_owner_url);
		let shared_key =
			HttpWallet::async_init_secure_api(&wallet_owner_url, &wallet_owner_secret).await?;
		let open_wallet_params = json!({
			"name": null,
			"password": wallet_pass.to_string()
		});
		let token: Token = HttpWallet::async_send_enc_request(
			&wallet_owner_url,
			&wallet_owner_secret,
			"open_wallet",
			&open_wallet_params,
			&shared_key,
		)
		.await?;
		info!("Connected to wallet");

		Ok(HttpWallet {
			wallet_owner_url: wallet_owner_url.clone(),
			wallet_owner_secret: wallet_owner_secret.clone(),
			shared_key: shared_key.clone(),
			token: token.clone(),
		})
	}

	async fn async_init_secure_api(
		wallet_owner_url: &SocketAddr,
		wallet_owner_secret: &Option<String>,
	) -> Result<SecretKey, WalletError> {
		let secp = Secp256k1::new();
		let ephemeral_sk = secp::random_secret();
		let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk).unwrap();
		let init_params = json!({
			"ecdh_pubkey": ephemeral_pk.serialize_vec(&secp, true).to_hex()
		});

		let response_pk: ECDHPubkey = HttpWallet::async_send_json_request(
			&wallet_owner_url,
			&wallet_owner_secret,
			"init_secure_api",
			&init_params,
		)
		.await?;

		let shared_key = {
			let mut shared_pubkey = response_pk.ecdh_pubkey.clone();
			shared_pubkey.mul_assign(&secp, &ephemeral_sk).unwrap();

			let x_coord = shared_pubkey.serialize_vec(&secp, true);
			SecretKey::from_slice(&secp, &x_coord[1..]).unwrap()
		};

		Ok(shared_key)
	}

	pub async fn async_perform_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, WalletError> {
		HttpWallet::async_send_enc_request(
			&self.wallet_owner_url,
			&self.wallet_owner_secret,
			method,
			params,
			&self.shared_key,
		)
		.await
	}

	async fn async_send_enc_request<D: serde::de::DeserializeOwned>(
		wallet_owner_url: &SocketAddr,
		wallet_owner_secret: &Option<String>,
		method: &str,
		params: &serde_json::Value,
		shared_key: &SecretKey,
	) -> Result<D, WalletError> {
		let url = format!("http://{}{}", wallet_owner_url, ENDPOINT);
		let req = json!({
			"method": method,
			"params": params,
			"id": JsonId::IntId(1),
			"jsonrpc": "2.0",
		});
		let enc_req = EncryptedRequest::from_json(&JsonId::IntId(1), &req, &shared_key)
			.map_err(WalletError::EncryptRequestError)?;
		let res = client::post_async::<EncryptedRequest, EncryptedResponse>(
			url.as_str(),
			&enc_req,
			wallet_owner_secret.clone(),
		)
		.await
		.map_err(WalletError::ApiCommError)?;
		let decrypted = res
			.decrypt(&shared_key)
			.map_err(WalletError::DecryptResponseError)?;
		let response: Response =
			serde_json::from_value(decrypted).map_err(WalletError::DecodeResponseError)?;
		let result = response
			.result
			.ok_or(WalletError::ResponseRpcError(response.error.clone()))?;
		let ok = result
			.get("Ok")
			.ok_or(WalletError::ResponseRpcError(response.error.clone()))?;
		let parsed =
			serde_json::from_value(ok.clone()).map_err(WalletError::DecodeResponseError)?;
		Ok(parsed)
	}

	async fn async_send_json_request<D: serde::de::DeserializeOwned>(
		wallet_owner_url: &SocketAddr,
		wallet_owner_secret: &Option<String>,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, WalletError> {
		let url = format!("http://{}{}", wallet_owner_url, ENDPOINT);
		let req = build_request(method, params);
		let res = client::post_async::<Request, Response>(
			url.as_str(),
			&req,
			wallet_owner_secret.clone(),
		)
		.await
		.map_err(WalletError::ApiCommError)?;
		let parsed = res
			.clone()
			.into_result()
			.map_err(WalletError::ResponseParseError)?;
		Ok(parsed)
	}

	pub fn get_token(&self) -> Token {
		self.token.clone()
	}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputWithBlind {
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	blind: BlindingFactor,
	output: Output,
}

#[async_trait]
impl Wallet for HttpWallet {
	/// Builds an 'Output' for the wallet using the 'build_output' RPC API.
	async fn async_build_output(
		&self,
		amount: u64,
	) -> Result<(BlindingFactor, Output), WalletError> {
		let req_json = json!({
			"token": self.token,
			"features": "Plain",
			"amount":  amount
		});
		let output: OutputWithBlind = HttpWallet::async_send_enc_request(
			&self.wallet_owner_url,
			&self.wallet_owner_secret,
			"build_output",
			&req_json,
			&self.shared_key,
		)
		.await?;
		Ok((output.blind, output.output))
	}
}

#[cfg(test)]
pub mod mock {
	use super::{Wallet, WalletError};
	use std::borrow::BorrowMut;

	use async_trait::async_trait;
	use grin_core::core::{Output, OutputFeatures};
	use grin_keychain::BlindingFactor;
	use grin_onion::crypto::secp;
	use secp256k1zkp::pedersen::Commitment;
	use secp256k1zkp::Secp256k1;
	use std::sync::{Arc, Mutex};

	/// Mock implementation of the 'Wallet' trait for unit-tests.
	#[derive(Clone)]
	pub struct MockWallet {
		built_outputs: Arc<Mutex<Vec<Commitment>>>,
	}

	impl MockWallet {
		/// Creates a new, empty MockWallet.
		pub fn new() -> Self {
			MockWallet {
				built_outputs: Arc::new(Mutex::new(Vec::new())),
			}
		}

		/// Returns the commitments of all outputs built for the wallet.
		pub fn built_outputs(&self) -> Vec<Commitment> {
			self.built_outputs.lock().unwrap().clone()
		}
	}

	#[async_trait]
	impl Wallet for MockWallet {
		/// Builds an 'Output' for the wallet using the 'build_output' RPC API.
		async fn async_build_output(
			&self,
			amount: u64,
		) -> Result<(BlindingFactor, Output), WalletError> {
			let secp = Secp256k1::new();
			let blind = secp::random_secret();
			let commit = secp::commit(amount, &blind).unwrap();
			let proof = secp.bullet_proof(
				amount,
				blind.clone(),
				secp::random_secret(),
				secp::random_secret(),
				None,
				None,
			);
			let output = Output::new(OutputFeatures::Plain, commit.clone(), proof);

			let mut locked = self.built_outputs.lock().unwrap();
			locked.borrow_mut().push(output.commitment().clone());

			Ok((BlindingFactor::from_secret_key(blind), output))
		}
	}
}
