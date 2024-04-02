use grin_onion::crypto::secp::Commitment;

use grin_api::json_rpc::{build_request, Request, Response};
use grin_api::{client, LocatedTxKernel};
use grin_api::{OutputPrintable, OutputType, Tip};
use grin_core::consensus::COINBASE_MATURITY;
use grin_core::core::{Committed, Input, OutputFeatures, Transaction};
use grin_util::ToHex;

use async_trait::async_trait;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use grin_core::core::hash::Hash;
use thiserror::Error;

#[async_trait]
pub trait GrinNode: Send + Sync {
	/// Retrieves the unspent output with a matching commitment
	async fn async_get_utxo(
		&self,
		output_commit: &Commitment,
	) -> Result<Option<OutputPrintable>, NodeError>;

    /// Gets the height and hash of the chain tip
    async fn async_get_chain_tip(&self) -> Result<(u64, Hash), NodeError>;

	/// Posts a transaction to the grin node
	async fn async_post_tx(&self, tx: &Transaction) -> Result<(), NodeError>;

	/// Returns a LocatedTxKernel based on the kernel excess.
	/// The min_height and max_height parameters are both optional.
	/// If not supplied, min_height will be set to 0 and max_height will be set to the head of the chain.
	/// The method will start at the block height max_height and traverse the kernel MMR backwards, until either the kernel is found or min_height is reached.
	async fn async_get_kernel(
		&self,
		excess: &Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<LocatedTxKernel>, NodeError>;
}

/// Error types for interacting with nodes
#[derive(Error, Debug)]
pub enum NodeError {
	#[error("Error decoding JSON response: {0:?}")]
	DecodeResponseError(serde_json::Error),
	#[error("JSON-RPC API communication error: {0:?}")]
	ApiCommError(grin_api::Error),
	#[error("Error decoding JSON-RPC response: {0:?}")]
	ResponseParseError(grin_api::json_rpc::Error),
}

/// Checks if a commitment is in the UTXO set
pub async fn async_is_unspent(
	node: &Arc<dyn GrinNode>,
	commit: &Commitment,
) -> Result<bool, NodeError> {
	let utxo = node.async_get_utxo(&commit).await?;
	Ok(utxo.is_some())
}

/// Checks whether a commitment is spendable at the block height provided
pub async fn async_is_spendable(
	node: &Arc<dyn GrinNode>,
	commit: &Commitment,
	next_block_height: u64,
) -> Result<bool, NodeError> {
	let output = node.async_get_utxo(&commit).await?;
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
pub async fn async_build_input(
	node: &Arc<dyn GrinNode>,
	output_commit: &Commitment,
) -> Result<Option<Input>, NodeError> {
	let output = node.async_get_utxo(&output_commit).await?;

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

pub async fn async_is_tx_valid(node: &Arc<dyn GrinNode>, tx: &Transaction) -> Result<bool, NodeError> {
    let next_block_height = node.async_get_chain_tip().await?.0 + 1;
    for input_commit in &tx.inputs_committed() {
        if !async_is_spendable(&node, &input_commit, next_block_height).await? {
            return Ok(false);
        }
    }

    for output_commit in &tx.outputs_committed() {
        if async_is_unspent(&node, &output_commit).await? {
            return Ok(false);
        }
    }

    Ok(true)
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

	async fn async_send_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, NodeError> {
		let url = format!("http://{}{}", self.node_url, ENDPOINT);
		let req = build_request(method, params);
		let res = client::post_async::<Request, Response>(
			url.as_str(),
			&req,
			self.node_api_secret.clone(),
		)
		.await
		.map_err(NodeError::ApiCommError)?;
		let parsed = res
			.clone()
			.into_result()
			.map_err(NodeError::ResponseParseError)?;
		Ok(parsed)
	}
}

#[async_trait]
impl GrinNode for HttpGrinNode {
	async fn async_get_utxo(
		&self,
		output_commit: &Commitment,
	) -> Result<Option<OutputPrintable>, NodeError> {
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
		let outputs = self
			.async_send_request::<Vec<OutputPrintable>>("get_outputs", &params)
			.await?;
		if outputs.is_empty() {
			return Ok(None);
		}

		Ok(Some(outputs[0].clone()))
	}

    async fn async_get_chain_tip(&self) -> Result<(u64, Hash), NodeError> {
		let params = json!([]);
		let tip_json = self
			.async_send_request::<serde_json::Value>("get_tip", &params)
			.await?;
		let tip =
			serde_json::from_value::<Tip>(tip_json).map_err(NodeError::DecodeResponseError)?;

        Ok((tip.height, Hash::from_hex(tip.last_block_pushed.as_str()).unwrap()))
	}

	async fn async_post_tx(&self, tx: &Transaction) -> Result<(), NodeError> {
		let params = json!([tx, true]);
		self.async_send_request::<serde_json::Value>("push_transaction", &params)
			.await?;
		Ok(())
	}

	async fn async_get_kernel(
		&self,
		excess: &Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<LocatedTxKernel>, NodeError> {
		let params = json!([excess.0.as_ref().to_hex(), min_height, max_height]);
		let value = self
			.async_send_request::<serde_json::Value>("get_kernel", &params)
			.await?;

		let contents = format!("{:?}", value);
		if contents.contains("NotFound") {
			return Ok(None);
		}

		let located_kernel = serde_json::from_value::<LocatedTxKernel>(value)
			.map_err(NodeError::DecodeResponseError)?;
		Ok(Some(located_kernel))
	}
}

#[cfg(test)]
pub mod mock {
	use super::{GrinNode, NodeError};

	use async_trait::async_trait;
	use grin_api::{LocatedTxKernel, OutputPrintable, OutputType};
	use grin_core::core::Transaction;
	use grin_onion::crypto::secp::Commitment;
	use std::collections::HashMap;
	use std::sync::RwLock;
    use grin_core::core::hash::Hash;

	/// Implementation of 'GrinNode' trait that mocks a grin node instance.
	/// Use only for testing purposes.
	pub struct MockGrinNode {
		utxos: HashMap<Commitment, OutputPrintable>,
		txns_posted: RwLock<Vec<Transaction>>,
		kernels: HashMap<Commitment, LocatedTxKernel>,
	}

	impl MockGrinNode {
		pub fn new() -> Self {
			MockGrinNode {
				utxos: HashMap::new(),
				txns_posted: RwLock::new(Vec::new()),
				kernels: HashMap::new(),
			}
		}

		pub fn new_with_utxos(utxos: &Vec<&Commitment>) -> Self {
			let mut node = MockGrinNode {
				utxos: HashMap::new(),
				txns_posted: RwLock::new(Vec::new()),
				kernels: HashMap::new(),
			};
			for utxo in utxos {
				node.add_default_utxo(utxo);
			}
			node
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

		pub fn add_kernel(&mut self, kernel: &LocatedTxKernel) {
			self.kernels
				.insert(kernel.tx_kernel.excess.clone(), kernel.clone());
		}
	}

	#[async_trait]
	impl GrinNode for MockGrinNode {
		async fn async_get_utxo(
			&self,
			output_commit: &Commitment,
		) -> Result<Option<OutputPrintable>, NodeError> {
			if let Some(utxo) = self.utxos.get(&output_commit) {
				return Ok(Some(utxo.clone()));
			}

			Ok(None)
		}

        async fn async_get_chain_tip(&self) -> Result<(u64, Hash), NodeError> {
            Ok((100, Hash::default()))
		}

		async fn async_post_tx(&self, tx: &Transaction) -> Result<(), NodeError> {
			let mut write = self.txns_posted.write().unwrap();
			write.push(tx.clone());
			Ok(())
		}

		async fn async_get_kernel(
			&self,
			excess: &Commitment,
			_min_height: Option<u64>,
			_max_height: Option<u64>,
		) -> Result<Option<LocatedTxKernel>, NodeError> {
			if let Some(kernel) = self.kernels.get(&excess) {
				return Ok(Some(kernel.clone()));
			}

			Ok(None)
		}
	}
}
