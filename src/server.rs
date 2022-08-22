use crate::config::ServerConfig;
use crate::node::{self, GrinNode};
use crate::onion::{Onion, OnionError};
use crate::secp::{ComSignature, Commitment, RangeProof, Secp256k1, SecretKey};
use crate::wallet::{self, Wallet};

use grin_core::core::{Input, Output, OutputFeatures, TransactionBody};
use grin_core::global::DEFAULT_ACCEPT_FEE_BASE;
use itertools::Itertools;
use std::collections::HashMap;
use std::result::Result;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
struct Submission {
	/// The total excess for the output commitment
	excess: SecretKey,
	/// The derived output commitment after applying excess and fee
	output_commit: Commitment,
	/// The rangeproof, included only for the final hop (node N)
	rangeproof: Option<RangeProof>,
	/// Transaction input being spent
	input: Input,
	/// Transaction fee
	fee: u64,
	/// The remaining onion after peeling off our layer
	onion: Onion,
}

/// Swap error types
#[derive(Clone, Error, Debug, PartialEq)]
pub enum SwapError {
	#[error("Invalid number of payloads provided (expected {expected:?}, found {found:?})")]
	InvalidPayloadLength { expected: usize, found: usize },
	#[error("Commitment Signature is invalid")]
	InvalidComSignature,
	#[error("Rangeproof is invalid")]
	InvalidRangeproof,
	#[error("Rangeproof is required but was not supplied")]
	MissingRangeproof,
	#[error("Output {commit:?} does not exist, or is already spent.")]
	CoinNotFound { commit: Commitment },
	#[error("Output {commit:?} is already in the swap list.")]
	AlreadySwapped { commit: Commitment },
	#[error("Failed to peel onion layer: {0:?}")]
	PeelOnionFailure(OnionError),
	#[error("Fee too low (expected >= {minimum_fee:?}, actual {actual_fee:?})")]
	FeeTooLow { minimum_fee: u64, actual_fee: u64 },
	#[error("{0}")]
	UnknownError(String),
}

/// A MWixnet server
pub trait Server: Send + Sync {
	/// Submit a new output to be swapped.
	fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError>;

	/// Iterate through all saved submissions, filter out any inputs that are no longer spendable,
	/// and assemble the coinswap transaction, posting the transaction to the configured node.
	///
	/// Currently only a single mix node is used. Milestone 3 will include support for multiple mix nodes.
	fn execute_round(&self) -> crate::error::Result<()>;
}

/// The standard MWixnet server implementation
#[derive(Clone)]
pub struct ServerImpl {
	server_config: ServerConfig,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
	submissions: Arc<Mutex<HashMap<Commitment, Submission>>>,
}

impl ServerImpl {
	/// Create a new MWixnet server
	pub fn new(
		server_config: ServerConfig,
		wallet: Arc<dyn Wallet>,
		node: Arc<dyn GrinNode>,
	) -> Self {
		ServerImpl {
			server_config,
			wallet,
			node,
			submissions: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	/// The fee base to use. For now, just using the default.
	fn get_fee_base(&self) -> u64 {
		DEFAULT_ACCEPT_FEE_BASE
	}

	/// Minimum fee to perform a swap.
	/// Requires enough fee for the mwixnet server's kernel, 1 input and its output to swap.
	fn get_minimum_swap_fee(&self) -> u64 {
		TransactionBody::weight_by_iok(1, 1, 1) * self.get_fee_base()
	}
}

impl Server for ServerImpl {
	fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError> {
		// milestone 3: check that enc_payloads length matches number of configured servers
		if onion.enc_payloads.len() != 1 {
			return Err(SwapError::InvalidPayloadLength {
				expected: 1,
				found: onion.enc_payloads.len(),
			});
		}

		// Verify commitment signature to ensure caller owns the output
		let serialized_onion = onion
			.serialize()
			.map_err(|e| SwapError::UnknownError(e.to_string()))?;
		let _ = comsig
			.verify(&onion.commit, &serialized_onion)
			.map_err(|_| SwapError::InvalidComSignature)?;

		// Verify that commitment is unspent
		let input = node::build_input(&self.node, &onion.commit)
			.map_err(|e| SwapError::UnknownError(e.to_string()))?;
		let input = input.ok_or(SwapError::CoinNotFound {
			commit: onion.commit.clone(),
		})?;

		let peeled = onion
			.peel_layer(&self.server_config.key)
			.map_err(|e| SwapError::PeelOnionFailure(e))?;

		// Verify the fee meets the minimum
		let fee: u64 = peeled.0.fee.into();
		if fee < self.get_minimum_swap_fee() {
			return Err(SwapError::FeeTooLow {
				minimum_fee: self.get_minimum_swap_fee(),
				actual_fee: fee,
			});
		}

		// Verify the bullet proof and build the final output
		if let Some(r) = peeled.0.rangeproof {
			let secp = Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
			secp.verify_bullet_proof(peeled.1.commit, r, None)
				.map_err(|_| SwapError::InvalidRangeproof)?;
		} else {
			// milestone 3: only the last hop will have a rangeproof
			return Err(SwapError::MissingRangeproof);
		}

		let mut locked = self.submissions.lock().unwrap();
		if locked.contains_key(&onion.commit) {
			return Err(SwapError::AlreadySwapped {
				commit: onion.commit.clone(),
			});
		}

		locked.insert(
			onion.commit,
			Submission {
				excess: peeled.0.excess,
				output_commit: peeled.1.commit,
				rangeproof: peeled.0.rangeproof,
				input,
				fee,
				onion: peeled.1,
			},
		);
		Ok(())
	}

	fn execute_round(&self) -> crate::error::Result<()> {
		let mut locked_state = self.submissions.lock().unwrap();
		let next_block_height = self.node.get_chain_height()? + 1;

		let spendable: Vec<Submission> = locked_state
			.values()
			.into_iter()
			.unique_by(|s| s.output_commit)
			.filter(|s| {
				node::is_spendable(&self.node, &s.input.commit, next_block_height).unwrap_or(false)
			})
			.filter(|s| !node::is_unspent(&self.node, &s.output_commit).unwrap_or(true))
			.cloned()
			.collect();

		if spendable.len() == 0 {
			return Ok(());
		}

		let total_fee: u64 = spendable.iter().enumerate().map(|(_, s)| s.fee).sum();

		let inputs: Vec<Input> = spendable.iter().enumerate().map(|(_, s)| s.input).collect();

		let outputs: Vec<Output> = spendable
			.iter()
			.enumerate()
			.map(|(_, s)| {
				Output::new(
					OutputFeatures::Plain,
					s.output_commit,
					s.rangeproof.unwrap(),
				)
			})
			.collect();

		let excesses: Vec<SecretKey> = spendable
			.iter()
			.enumerate()
			.map(|(_, s)| s.excess.clone())
			.collect();

		let tx = wallet::assemble_tx(
			&self.wallet,
			&inputs,
			&outputs,
			self.get_fee_base(),
			total_fee,
			&excesses,
		)?;

		self.node.post_tx(&tx)?;
		locked_state.clear();

		Ok(())
	}
}

#[cfg(test)]
pub mod mock {
	use super::{Server, SwapError};
	use crate::onion::Onion;
	use crate::secp::ComSignature;

	use std::collections::HashMap;

	pub struct MockServer {
		errors: HashMap<Onion, SwapError>,
	}

	impl MockServer {
		pub fn new() -> MockServer {
			MockServer {
				errors: HashMap::new(),
			}
		}

		pub fn set_response(&mut self, onion: &Onion, e: SwapError) {
			self.errors.insert(onion.clone(), e);
		}
	}

	impl Server for MockServer {
		fn swap(&self, onion: &Onion, _comsig: &ComSignature) -> Result<(), SwapError> {
			if let Some(e) = self.errors.get(&onion) {
				return Err(e.clone());
			}

			Ok(())
		}

		fn execute_round(&self) -> crate::error::Result<()> {
			Ok(())
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::config::ServerConfig;
	use crate::node::mock::MockGrinNode;
	use crate::onion::test_util::{self, Hop};
	use crate::onion::Onion;
	use crate::secp::{
		self, ComSignature, Commitment, PublicKey, RangeProof, Secp256k1, SecretKey,
	};
	use crate::server::{Server, ServerImpl, Submission, SwapError};
	use crate::types::Payload;
	use crate::wallet::mock::MockWallet;

	use grin_core::core::{Committed, FeeFields, Input, OutputFeatures, Transaction, Weighting};
	use grin_core::global::{self, ChainTypes};
	use std::net::TcpListener;
	use std::sync::Arc;

	macro_rules! assert_error_type {
		($result:expr, $error_type:pat) => {
			assert!($result.is_err());
			assert!(if let $error_type = $result.unwrap_err() {
				true
			} else {
				false
			});
		};
	}

	fn new_server(
		server_key: &SecretKey,
		utxos: &Vec<&Commitment>,
	) -> (ServerImpl, Arc<MockGrinNode>) {
		let config = ServerConfig {
			key: server_key.clone(),
			interval_s: 1,
			addr: TcpListener::bind("127.0.0.1:0")
				.unwrap()
				.local_addr()
				.unwrap(),
			grin_node_url: "127.0.0.1:3413".parse().unwrap(),
			grin_node_secret_path: None,
			wallet_owner_url: "127.0.0.1:3420".parse().unwrap(),
			wallet_owner_secret_path: None,
		};
		let wallet = Arc::new(MockWallet {});
		let mut mut_node = MockGrinNode::new();
		for utxo in utxos {
			mut_node.add_default_utxo(&utxo);
		}
		let node = Arc::new(mut_node);

		let server = ServerImpl::new(config, wallet.clone(), node.clone());
		(server, node)
	}

	fn proof(value: u64, fee: u64, input_blind: &SecretKey, hop_excess: &SecretKey) -> RangeProof {
		let secp = Secp256k1::new();
		let nonce = secp::random_secret();

		let mut blind = input_blind.clone();
		blind.add_assign(&secp, &hop_excess).unwrap();

		secp.bullet_proof(
			value - fee,
			blind.clone(),
			nonce.clone(),
			nonce.clone(),
			None,
			None,
		)
	}

	fn new_hop(
		server_key: &SecretKey,
		hop_excess: &SecretKey,
		fee: u64,
		proof: Option<RangeProof>,
	) -> Hop {
		let secp = Secp256k1::new();
		Hop {
			pubkey: PublicKey::from_secret_key(&secp, &server_key).unwrap(),
			payload: Payload {
				excess: hop_excess.clone(),
				fee: FeeFields::from(fee as u32),
				rangeproof: proof,
			},
		}
	}

	/// Single hop to demonstrate request validation and onion unwrapping.
	#[test]
	fn swap_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let proof = proof(value, fee, &blind, &hop_excess);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, node) = new_server(&server_key, &vec![&input_commit]);
		server.swap(&onion, &comsig)?;

		// Make sure entry is added to server.
		let output_commit = secp::add_excess(&input_commit, &hop_excess)?;
		let output_commit = secp::sub_value(&output_commit, fee)?;

		let expected = Submission {
			excess: hop_excess.clone(),
			output_commit: output_commit.clone(),
			rangeproof: Some(proof),
			input: Input::new(OutputFeatures::Plain, input_commit.clone()),
			fee,
			onion: Onion {
				ephemeral_pubkey: test_util::next_ephemeral_pubkey(&onion, &server_key)?,
				commit: output_commit.clone(),
				enc_payloads: vec![],
			},
		};

		{
			let submissions = server.submissions.lock().unwrap();
			assert_eq!(1, submissions.len());
			assert!(submissions.contains_key(&input_commit));
			assert_eq!(&expected, submissions.get(&input_commit).unwrap());
		}

		server.execute_round()?;

		// Make sure entry is removed from server.submissions
		assert!(server.submissions.lock().unwrap().is_empty());

		// check that the transaction was posted
		let posted_txns = node.get_posted_txns();
		assert_eq!(posted_txns.len(), 1);
		let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
		assert!(posted_txn.inputs_committed().contains(&input_commit));
		assert!(posted_txn.outputs_committed().contains(&output_commit));
		// todo: check that outputs also contain the commitment generated by our wallet

		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		posted_txn.validate(Weighting::AsTransaction)?;

		Ok(())
	}

	/// Returns InvalidPayloadLength when too many payloads are provided.
	#[test]
	fn swap_too_many_payloads() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let proof = proof(value, fee, &blind, &hop_excess);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let hops: Vec<Hop> = vec![hop.clone(), hop.clone()]; // Multiple payloads
		let onion = test_util::create_onion(&input_commit, &hops)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![&input_commit]);
		let result = server.swap(&onion, &comsig);
		assert_eq!(
			Err(SwapError::InvalidPayloadLength {
				expected: 1,
				found: 2
			}),
			result
		);

		// Make sure no entry is added to server.submissions
		assert!(server.submissions.lock().unwrap().is_empty());

		Ok(())
	}

	/// Returns InvalidComSignature when ComSignature fails to verify.
	#[test]
	fn swap_invalid_com_signature() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let proof = proof(value, fee, &blind, &hop_excess);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;

		let wrong_blind = secp::random_secret();
		let comsig = ComSignature::sign(value, &wrong_blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![&input_commit]);
		let result = server.swap(&onion, &comsig);
		assert_eq!(Err(SwapError::InvalidComSignature), result);

		// Make sure no entry is added to server.submissions
		assert!(server.submissions.lock().unwrap().is_empty());

		Ok(())
	}

	/// Returns InvalidRangeProof when the rangeproof fails to verify for the commitment.
	#[test]
	fn swap_invalid_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let wrong_value = value + 10_000_000;
		let proof = proof(wrong_value, fee, &blind, &hop_excess);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![&input_commit]);
		let result = server.swap(&onion, &comsig);
		assert_eq!(Err(SwapError::InvalidRangeproof), result);

		// Make sure no entry is added to server.submissions
		assert!(server.submissions.lock().unwrap().is_empty());

		Ok(())
	}

	/// Returns MissingRangeproof when no rangeproof is provided.
	#[test]
	fn swap_missing_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let hop = new_hop(&server_key, &hop_excess, fee, None);

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![&input_commit]);
		let result = server.swap(&onion, &comsig);
		assert_eq!(Err(SwapError::MissingRangeproof), result);

		// Make sure no entry is added to server.submissions
		assert!(server.submissions.lock().unwrap().is_empty());

		Ok(())
	}

	/// Returns CoinNotFound when there's no matching output in the UTXO set.
	#[test]
	fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let proof = proof(value, fee, &blind, &hop_excess);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![]);
		let result = server.swap(&onion, &comsig);
		assert_eq!(
			Err(SwapError::CoinNotFound {
				commit: input_commit.clone()
			}),
			result
		);

		// Make sure no entry is added to server.submissions
		assert!(server.submissions.lock().unwrap().is_empty());

		Ok(())
	}

	/// Returns AlreadySwapped when trying to swap the same commitment multiple times.
	#[test]
	fn swap_already_swapped() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let proof = proof(value, fee, &blind, &hop_excess);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![&input_commit]);
		server.swap(&onion, &comsig)?;

		// Call swap a second time
		let result = server.swap(&onion, &comsig);
		assert_eq!(
			Err(SwapError::AlreadySwapped {
				commit: input_commit.clone()
			}),
			result
		);

		Ok(())
	}

	/// Returns PeelOnionFailure when a failure occurs trying to decrypt the onion payload.
	#[test]
	fn swap_peel_onion_failure() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let proof = proof(value, fee, &blind, &hop_excess);

		let wrong_server_key = secp::random_secret();
		let hop = new_hop(&wrong_server_key, &hop_excess, fee, Some(proof));

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![&input_commit]);
		let result = server.swap(&onion, &comsig);

		assert!(result.is_err());
		assert_error_type!(result, SwapError::PeelOnionFailure(_));

		Ok(())
	}

	/// Returns FeeTooLow when the minimum fee is not met.
	#[test]
	fn swap_fee_too_low() -> Result<(), Box<dyn std::error::Error>> {
		let value: u64 = 200_000_000;
		let fee: u64 = 1_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let proof = proof(value, fee, &blind, &hop_excess);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = test_util::create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let (server, _node) = new_server(&server_key, &vec![&input_commit]);
		let result = server.swap(&onion, &comsig);
		assert_eq!(
			Err(SwapError::FeeTooLow {
				minimum_fee: 12_500_000,
				actual_fee: fee
			}),
			result
		);

		Ok(())
	}
}
