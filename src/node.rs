use crate::error::{ErrorKind, Result};
use crate::secp::Commitment;

use grin_api::client;
use grin_api::json_rpc::{build_request, Request, Response};
use grin_api::{OutputPrintable, OutputType, Tip};
use grin_core::consensus::COINBASE_MATURITY;
use grin_core::core::{Input, OutputFeatures, Transaction};
use grin_util::ToHex;

use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

pub trait GrinNode: Send + Sync {
	/// Retrieves the unspent output with a matching commitment
	fn get_utxo(&self, output_commit: &Commitment) -> Result<Option<OutputPrintable>>;

	/// Gets the height of the chain tip
	fn get_chain_height(&self) -> Result<u64>;

	/// Posts a transaction to the grin node
	fn post_tx(&self, tx: &Transaction) -> Result<()>;
}

/// Checks if a commitment is in the UTXO set
pub fn is_unspent(node: &Arc<dyn GrinNode>, commit: &Commitment) -> Result<bool> {
	let utxo = node.get_utxo(&commit)?;
	Ok(utxo.is_some())
}

/// Checks whether a commitment is spendable at the block height provided
pub fn is_spendable(
	node: &Arc<dyn GrinNode>,
	output_commit: &Commitment,
	next_block_height: u64,
) -> Result<bool> {
	let output = node.get_utxo(&output_commit)?;
	if let Some(out) = output {
		let is_coinbase = match out.output_type {
			OutputType::Coinbase => true,
			OutputType::Transaction => false,
		};

		if is_coinbase {
			if let Some(block_height) = out.block_height {
				if block_height + COINBASE_MATURITY < next_block_height {
					return Ok(false);
				}
			} else {
				return Ok(false);
			}
		}

		return Ok(true);
	}

	Ok(false)
}

/// Builds an input for an unspent output commitment
pub fn build_input(node: &Arc<dyn GrinNode>, output_commit: &Commitment) -> Result<Option<Input>> {
	let output = node.get_utxo(&output_commit)?;

	if let Some(out) = output {
		let features = match out.output_type {
			OutputType::Coinbase => OutputFeatures::Coinbase,
			OutputType::Transaction => OutputFeatures::Plain,
		};

		let input = Input::new(features, out.commit);
		return Ok(Some(input));
	}

	Ok(None)
}

/// HTTP (JSON-RPC) implementation of the 'GrinNode' trait
#[derive(Clone)]
pub struct HttpGrinNode {
	node_url: SocketAddr,
	node_api_secret: Option<String>,
}

const ENDPOINT: &str = "/v2/foreign";

impl HttpGrinNode {
	pub fn new(node_url: &SocketAddr, node_api_secret: &Option<String>) -> HttpGrinNode {
		HttpGrinNode {
			node_url: node_url.to_owned(),
			node_api_secret: node_api_secret.to_owned(),
		}
	}

	fn send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D> {
		let url = format!("http://{}{}", self.node_url, ENDPOINT);
		let req = build_request(method, params);
		let res =
			client::post::<Request, Response>(url.as_str(), self.node_api_secret.clone(), &req)?;
		let parsed = res.clone().into_result()?;
		Ok(parsed)
	}
}

impl GrinNode for HttpGrinNode {
	fn get_utxo(&self, output_commit: &Commitment) -> Result<Option<OutputPrintable>> {
		let commits: Vec<String> = vec![output_commit.to_hex()];
		let start_height: Option<u64> = None;
		let end_height: Option<u64> = None;
		let include_proof: Option<bool> = Some(false);
		let include_merkle_proof: Option<bool> = Some(false);

		let params = json!([
			Some(commits),
			start_height,
			end_height,
			include_proof,
			include_merkle_proof
		]);
		let outputs = self.send_json_request::<Vec<OutputPrintable>>("get_outputs", &params)?;
		if outputs.is_empty() {
			return Ok(None);
		}

		Ok(Some(outputs[0].clone()))
	}

	fn get_chain_height(&self) -> Result<u64> {
		let params = json!([]);
		let tip_json = self.send_json_request::<serde_json::Value>("get_tip", &params)?;

		let tip: Result<Tip> = serde_json::from_value(tip_json["Ok"].clone())
			.map_err(|e| ErrorKind::SerdeJsonError(e.to_string()).into());

		Ok(tip?.height)
	}

	fn post_tx(&self, tx: &Transaction) -> Result<()> {
		let params = json!([tx, true]);
		self.send_json_request::<serde_json::Value>("push_transaction", &params)?;
		Ok(())
	}
}

/// Implementation of 'GrinNode' trait that mocks a grin node instance.
/// Use only for testing purposes.
pub struct MockGrinNode {
	utxos: HashMap<Commitment, OutputPrintable>,
	txns_posted: RwLock<Vec<Transaction>>,
}

impl MockGrinNode {
	pub fn new() -> MockGrinNode {
		MockGrinNode {
			utxos: HashMap::new(),
			txns_posted: RwLock::new(Vec::new()),
		}
	}

	pub fn add_utxo(&mut self, output_commit: &Commitment, utxo: &OutputPrintable) {
		self.utxos.insert(output_commit.clone(), utxo.clone());
	}

	pub fn add_default_utxo(&mut self, output_commit: &Commitment) {
		let utxo = OutputPrintable {
			output_type: OutputType::Transaction,
			commit: output_commit.to_owned(),
			spent: false,
			proof: None,
			proof_hash: String::from(""),
			block_height: None,
			merkle_proof: None,
			mmr_index: 0,
		};

		self.add_utxo(&output_commit, &utxo);
	}

	pub fn get_posted_txns(&self) -> Vec<Transaction> {
		let read = self.txns_posted.read().unwrap();
		read.clone()
	}
}

impl GrinNode for MockGrinNode {
	fn get_utxo(&self, output_commit: &Commitment) -> Result<Option<OutputPrintable>> {
		if let Some(utxo) = self.utxos.get(&output_commit) {
			return Ok(Some(utxo.clone()));
		}

		Ok(None)
	}

	fn get_chain_height(&self) -> Result<u64> {
		Ok(100)
	}

	fn post_tx(&self, tx: &Transaction) -> Result<()> {
		let mut write = self.txns_posted.write().unwrap();
		write.push(tx.clone());
		Ok(())
	}
}
