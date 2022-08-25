use crate::secp;

use grin_api::client;
use grin_api::json_rpc::{build_request, Request, Response};
use grin_core::core::{
	FeeFields, Input, Inputs, KernelFeatures, Output, Transaction, TransactionBody, TxKernel,
};
use grin_core::libtx::secp_ser;
use grin_keychain::BlindingFactor;
use grin_util::{ToHex, ZeroingString};
use grin_wallet_api::{EncryptedRequest, EncryptedResponse, JsonId, Token};
use secp256k1zkp::{ContextFlag, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

pub trait Wallet: Send + Sync {
	/// Builds an output for the wallet with the provided amount.
	fn build_output(&self, amount: u64) -> Result<(BlindingFactor, Output), WalletError>;
}

/// Error types for interacting with wallets
#[derive(Error, Debug)]
pub enum WalletError {
	#[error("Error building kernel's fee fields: {0:?}")]
	KernelFeeError(grin_core::core::transaction::Error),
	#[error("Error computing kernel's excess: {0:?}")]
	KernelExcessError(secp256k1zkp::Error),
	#[error("Error computing kernel's signature message: {0:?}")]
	KernelSigMessageError(grin_core::core::transaction::Error),
	#[error("Error signing kernel: {0:?}")]
	KernelSigError(secp256k1zkp::Error),
	#[error("Built kernel failed to verify: {0:?}")]
	KernelVerifyError(grin_core::core::transaction::Error),
	#[error("Output blinding factor is invalid: {0:?}")]
	OutputBlindError(secp256k1zkp::Error),
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
}

/// Builds and verifies a 'Transaction' using the provided components.
pub fn assemble_tx(
	wallet: &Arc<dyn Wallet>,
	inputs: &Vec<Input>,
	outputs: &Vec<Output>,
	fee_base: u64,
	total_fee: u64,
	excesses: &Vec<SecretKey>,
) -> Result<Transaction, WalletError> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let txn_inputs = Inputs::from(inputs.as_slice());
	let mut txn_outputs = outputs.clone();
	let mut txn_excesses = excesses.clone();
	let mut kernel_fee = total_fee;

	// calculate fee required if we add our own output
	let fee_required =
		TransactionBody::weight_by_iok(inputs.len() as u64, (outputs.len() + 1) as u64, 1)
			* fee_base;

	// calculate fee to spend the output to ensure there's enough leftover to cover the fees for spending it
	let fee_to_spend = TransactionBody::weight_by_iok(1, 0, 0) * fee_base;

	// collect any leftover fees
	if total_fee > fee_required + fee_to_spend {
		let amount = total_fee - fee_required;
		kernel_fee -= amount;

		let wallet_output = wallet.build_output(amount)?;
		txn_outputs.push(wallet_output.1);

		let output_excess = SecretKey::from_slice(&secp, &wallet_output.0.as_ref())
			.map_err(WalletError::OutputBlindError)?;
		txn_excesses.push(output_excess);
	}

	// generate random transaction offset
	let offset = secp::random_secret();

	// calculate kernel excess
	let kern_excess = secp
		.blind_sum(txn_excesses, vec![offset.clone()])
		.map_err(WalletError::KernelExcessError)?;

	// build and verify kernel
	let mut kernel = TxKernel::with_features(KernelFeatures::Plain {
		fee: FeeFields::new(0, kernel_fee).map_err(WalletError::KernelFeeError)?,
	});
	let msg = kernel
		.msg_to_sign()
		.map_err(WalletError::KernelSigMessageError)?;
	kernel.excess = secp::commit(0, &kern_excess).map_err(WalletError::KernelExcessError)?;
	kernel.excess_sig = secp::sign(&kern_excess, &msg).map_err(WalletError::KernelSigError)?;
	kernel.verify().map_err(WalletError::KernelVerifyError)?;

	// assemble the transaction
	let tx = Transaction::new(txn_inputs, &txn_outputs, &[kernel])
		.with_offset(BlindingFactor::from_secret_key(offset));
	Ok(tx)
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
	pub fn open_wallet(
		wallet_owner_url: &SocketAddr,
		wallet_owner_secret: &Option<String>,
		wallet_pass: &ZeroingString,
	) -> Result<HttpWallet, WalletError> {
		println!("Opening wallet at {}", wallet_owner_url);
		let shared_key = HttpWallet::init_secure_api(&wallet_owner_url, &wallet_owner_secret)?;

		let open_wallet_params = json!({
			"name": null,
			"password": wallet_pass.to_string()
		});
		let token: Token = HttpWallet::send_enc_request(
			&wallet_owner_url,
			&wallet_owner_secret,
			"open_wallet",
			&open_wallet_params,
			&shared_key,
		)?;
		println!("Connected to wallet");

		Ok(HttpWallet {
			wallet_owner_url: wallet_owner_url.clone(),
			wallet_owner_secret: wallet_owner_secret.clone(),
			shared_key: shared_key.clone(),
			token: token.clone(),
		})
	}

	fn init_secure_api(
		wallet_owner_url: &SocketAddr,
		wallet_owner_secret: &Option<String>,
	) -> Result<SecretKey, WalletError> {
		let secp = Secp256k1::new();
		let ephemeral_sk = secp::random_secret();
		let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk).unwrap();
		let init_params = json!({
			"ecdh_pubkey": ephemeral_pk.serialize_vec(&secp, true).to_hex()
		});

		let response_pk: ECDHPubkey = HttpWallet::send_json_request(
			&wallet_owner_url,
			&wallet_owner_secret,
			"init_secure_api",
			&init_params,
		)?;

		let shared_key = {
			let mut shared_pubkey = response_pk.ecdh_pubkey.clone();
			shared_pubkey.mul_assign(&secp, &ephemeral_sk).unwrap();

			let x_coord = shared_pubkey.serialize_vec(&secp, true);
			SecretKey::from_slice(&secp, &x_coord[1..]).unwrap()
		};

		Ok(shared_key)
	}

	fn send_enc_request<D: serde::de::DeserializeOwned>(
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
		let res = client::post::<EncryptedRequest, EncryptedResponse>(
			url.as_str(),
			wallet_owner_secret.clone(),
			&enc_req,
		)
		.map_err(WalletError::ApiCommError)?;
		let decrypted = res
			.decrypt(&shared_key)
			.map_err(WalletError::DecryptResponseError)?;
		let response: Response =
			serde_json::from_value(decrypted).map_err(WalletError::DecodeResponseError)?;
		let ok = response.result.unwrap().get("Ok").unwrap().clone();
		let parsed = serde_json::from_value(ok).map_err(WalletError::DecodeResponseError)?;
		Ok(parsed)
	}

	fn send_json_request<D: serde::de::DeserializeOwned>(
		wallet_owner_url: &SocketAddr,
		wallet_owner_secret: &Option<String>,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, WalletError> {
		let url = format!("http://{}{}", wallet_owner_url, ENDPOINT);
		let req = build_request(method, params);
		let res =
			client::post::<Request, Response>(url.as_str(), wallet_owner_secret.clone(), &req)
				.map_err(WalletError::ApiCommError)?;
		let parsed = res
			.clone()
			.into_result()
			.map_err(WalletError::ResponseParseError)?;
		Ok(parsed)
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

impl Wallet for HttpWallet {
	/// Builds an 'Output' for the wallet using the 'build_output' RPC API.
	fn build_output(&self, amount: u64) -> Result<(BlindingFactor, Output), WalletError> {
		let req_json = json!({
			"token": self.token.keychain_mask.clone().unwrap().0,
			"features": "Plain",
			"amount":  amount
		});
		let output: OutputWithBlind = HttpWallet::send_enc_request(
			&self.wallet_owner_url,
			&self.wallet_owner_secret,
			"build_output",
			&req_json,
			&self.shared_key,
		)?;
		Ok((output.blind, output.output))
	}
}

#[cfg(test)]
pub mod mock {
	use super::{Wallet, WalletError};
	use crate::secp;

	use grin_core::core::{Output, OutputFeatures};
	use grin_keychain::BlindingFactor;
	use secp256k1zkp::Secp256k1;

	/// HTTP (JSONRPC) implementation of the 'Wallet' trait.
	#[derive(Clone)]
	pub struct MockWallet {}

	impl Wallet for MockWallet {
		/// Builds an 'Output' for the wallet using the 'build_output' RPC API.
		fn build_output(&self, amount: u64) -> Result<(BlindingFactor, Output), WalletError> {
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
			Ok((BlindingFactor::from_secret_key(blind), output))
		}
	}
}
