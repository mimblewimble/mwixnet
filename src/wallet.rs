use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use async_trait::async_trait;
use grin_core::core::Output;
use grin_core::libtx::secp_ser;
use grin_keychain::BlindingFactor;
use grin_util::{ToHex, ZeroingString};
use grin_wallet_api::Token;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use grin_wallet_libwallet::mwixnet::onion as grin_onion;
use grin_onion::crypto::secp;
use secp256k1zkp::{PublicKey, Secp256k1, SecretKey};

use crate::http;

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
	#[error("Error communication with wallet: {0:?}")]
	WalletCommError(http::HttpError),
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
		wallet_owner_url: &str,
		wallet_owner_secret: &Option<String>,
		wallet_pass: &ZeroingString,
	) -> Result<HttpWallet, WalletError> {
		info!("Opening wallet at {}", wallet_owner_url);
		let mut addrs_iter = wallet_owner_url.to_socket_addrs().unwrap();
		let wallet_owner_url = addrs_iter.next().unwrap();
		let shared_key =
			HttpWallet::async_init_secure_api(&wallet_owner_url, &wallet_owner_secret).await?;
		let open_wallet_params = json!({
			"name": null,
			"password": wallet_pass.to_string()
		});
		let url = format!("http://{}{}", wallet_owner_url, ENDPOINT);
		let token: Token = http::async_send_enc_request(
			&url,
			&wallet_owner_secret,
			"open_wallet",
			&open_wallet_params,
			&shared_key,
		)
		.await
		.map_err(WalletError::WalletCommError)?;
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
		let ephemeral_pk_bytes = ephemeral_pk.serialize_vec(&secp, true);
		let init_params = json!({
			"ecdh_pubkey": ephemeral_pk_bytes.to_hex()
		});

		let url = format!("http://{}{}", wallet_owner_url, ENDPOINT);
		let response_pk: ECDHPubkey = http::async_send_json_request(
			&url,
			&wallet_owner_secret,
			"init_secure_api",
			&init_params,
		)
		.await
		.map_err(WalletError::WalletCommError)?;

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
		let url = format!("http://{}{}", self.wallet_owner_url, ENDPOINT);
		http::async_send_enc_request(
			&url,
			&self.wallet_owner_secret,
			method,
			params,
			&self.shared_key,
		)
		.await
		.map_err(WalletError::WalletCommError)
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
		let params = json!({
			"token": self.token,
			"features": "Plain",
			"amount":  amount
		});

		let url = format!("http://{}{}", self.wallet_owner_url, ENDPOINT);
		let output: OutputWithBlind = http::async_send_enc_request(
			&url,
			&self.wallet_owner_secret,
			"build_output",
			&params,
			&self.shared_key,
		)
		.await
		.map_err(WalletError::WalletCommError)?;
		Ok((output.blind, output.output))
	}
}

#[cfg(test)]
pub mod mock {
	use std::borrow::BorrowMut;
	use std::sync::{Arc, Mutex};

	use async_trait::async_trait;
	use grin_core::core::{Output, OutputFeatures};
	use grin_keychain::BlindingFactor;

	use grin_onion::crypto::secp;
	use secp256k1zkp::pedersen::Commitment;
	use secp256k1zkp::Secp256k1;

	use super::{Wallet, WalletError};

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
