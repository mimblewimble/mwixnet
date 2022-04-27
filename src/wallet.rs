use crate::error::{ErrorKind, Result};
use crate::secp::{self, SecretKey};

use grin_api::client;
use grin_api::json_rpc::{build_request, Request, Response};
use grin_core::core::{FeeFields, Input, Inputs, KernelFeatures, Output, Transaction, TransactionBody, TxKernel};
use grin_core::libtx::secp_ser;
use grin_keychain::BlindingFactor;
use grin_util::ZeroingString;
use grin_wallet_api::Token;
use secp256k1zkp::{ContextFlag, Secp256k1};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

pub trait Wallet : Send + Sync {
    /// Builds an output for the wallet with the provided amount.
    fn build_output(&self, amount: u64) -> Result<(BlindingFactor, Output)>;
}

/// Builds and verifies a 'Transaction' using the provided components.
pub fn assemble_tx(wallet: &Arc<dyn Wallet>, inputs: &Vec<Input>, outputs: &Vec<Output>, fee_base: u64, total_fee: u64, excesses: &Vec<SecretKey>) -> Result<Transaction> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let txn_inputs = Inputs::from(inputs.as_slice());
    let mut txn_outputs = outputs.clone();
    let mut txn_excesses = excesses.clone();
    let mut kernel_fee = total_fee;

    // calculate fee required if we add our own output
    let fee_required = TransactionBody::weight_by_iok(inputs.len() as u64, (outputs.len() + 1) as u64, 1) * fee_base;

    // calculate fee to spend the output to ensure there's enough leftover to cover the fees for spending it
    let fee_to_spend = TransactionBody::weight_by_iok(1, 0, 0) * fee_base;

    // collect any leftover fees
    if total_fee > fee_required + fee_to_spend {
        let amount = total_fee - fee_required;
        kernel_fee -= amount;

        let wallet_output = wallet.build_output(amount)?;
        txn_outputs.push(wallet_output.1);

        let output_excess = wallet_output.0.secret_key(&secp)
            .map_err(|_| ErrorKind::CorruptedData)?;
            txn_excesses.push(output_excess);
    }

    // generate random transaction offset
    let offset = secp::random_secret();

    // calculate kernel excess
    let kern_excess = secp.blind_sum(txn_excesses, vec![offset.clone()])?;

    // build and verify kernel
    let mut kernel = TxKernel::with_features(KernelFeatures::Plain {
        fee: FeeFields::new(0, kernel_fee).unwrap(),
    });
    let msg = kernel.msg_to_sign()?;
    kernel.excess = secp::commit(0, &kern_excess)?;
    kernel.excess_sig = secp::sign(&kern_excess, &msg)?;
    kernel.verify()?;

    // assemble the transaction
    let tx = Transaction::new(txn_inputs, &txn_outputs, &[kernel])
        .with_offset(BlindingFactor::from_secret_key(offset));
    Ok(tx)
}

/// HTTP (JSONRPC) implementation of the 'Wallet' trait.
#[derive(Clone)]
pub struct HttpWallet {
    wallet_owner_url: SocketAddr,
    token: Token,
}

const ENDPOINT: &str = "/v3/owner";

impl HttpWallet {
    /// Calls the 'open_wallet' using the RPC API.
    pub fn open_wallet(wallet_owner_url: &SocketAddr, wallet_pass: &ZeroingString) -> Result<HttpWallet> {
        let open_wallet_params = json!({
            "name": null,
            "password": wallet_pass.to_string()
        });
        let token: Token = HttpWallet::send_json_request(&wallet_owner_url, "open_wallet", &open_wallet_params)?;

        Ok(HttpWallet { 
            wallet_owner_url: wallet_owner_url.clone(),
            token: token,
        })
    }

    fn send_json_request<D: serde::de::DeserializeOwned>(
        wallet_owner_url: &SocketAddr,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<D> {
        let url = format!("http://{}{}", wallet_owner_url, ENDPOINT);
        let req = build_request(method, params);
        let res = client::post::<Request, Response>(url.as_str(), None, &req)?;
        let parsed = res.clone().into_result()?;
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
    fn build_output(&self, amount: u64) -> Result<(BlindingFactor, Output)> {
        let req_json = json!({
			"token": self.token.keychain_mask.clone().unwrap().0,
			"features": "Plain",
			"amount":  amount
        });
        let output: OutputWithBlind = HttpWallet::send_json_request(&self.wallet_owner_url, "build_output", &req_json)?;
        Ok((output.blind, output.output))
    }
}

use grin_core::core::OutputFeatures;

/// HTTP (JSONRPC) implementation of the 'Wallet' trait.
#[derive(Clone)]
pub struct MockWallet {
}

impl Wallet for MockWallet {
    /// Builds an 'Output' for the wallet using the 'build_output' RPC API.
    fn build_output(&self, amount: u64) -> Result<(BlindingFactor, Output)> {
        let secp = Secp256k1::new();
        let blind = secp::random_secret();
        let commit = secp::commit(amount, &blind)?;
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