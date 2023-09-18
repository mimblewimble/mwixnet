use crate::client::MixClient;
use crate::config::ServerConfig;
use crate::crypto::comsig::ComSignature;
use crate::crypto::secp::{Commitment, Secp256k1, SecretKey};
use crate::node::{self, GrinNode};
use crate::store::{StoreError, SwapData, SwapStatus, SwapStore};
use crate::tx;
use crate::wallet::Wallet;

use grin_core::core::hash::Hashed;
use grin_core::core::{Input, Output, OutputFeatures, Transaction, TransactionBody};
use grin_core::global::DEFAULT_ACCEPT_FEE_BASE;
use grin_onion::onion::{Onion, OnionError};
use itertools::Itertools;
use secp256k1zkp::key::ZERO_KEY;
use std::collections::HashSet;
use std::result::Result;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Swap error types
#[derive(Clone, Error, Debug, PartialEq)]
pub enum SwapError {
	#[error("Invalid number of payloads provided")]
	InvalidPayloadLength,
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
	#[error("Error saving swap to data store: {0}")]
	StoreError(StoreError),
	#[error("Client communication error: {0:?}")]
	ClientError(String),
	#[error("{0}")]
	UnknownError(String),
}

/// A public MWixnet server - the "Swap Server"
pub trait SwapServer: Send + Sync {
	/// Submit a new output to be swapped.
	fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError>;

	/// Iterate through all saved submissions, filter out any inputs that are no longer spendable,
	/// and assemble the coinswap transaction, posting the transaction to the configured node.
	fn execute_round(&self) -> Result<Option<Transaction>, Box<dyn std::error::Error>>;
}

/// The standard MWixnet server implementation
#[derive(Clone)]
pub struct SwapServerImpl {
	server_config: ServerConfig,
	next_server: Option<Arc<dyn MixClient>>,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
	store: Arc<Mutex<SwapStore>>,
}

impl SwapServerImpl {
	/// Create a new MWixnet server
	pub fn new(
		server_config: ServerConfig,
		next_server: Option<Arc<dyn MixClient>>,
		wallet: Arc<dyn Wallet>,
		node: Arc<dyn GrinNode>,
		store: SwapStore,
	) -> Self {
		SwapServerImpl {
			server_config,
			next_server,
			wallet,
			node,
			store: Arc::new(Mutex::new(store)),
		}
	}

	/// The fee base to use. For now, just using the default.
	fn get_fee_base(&self) -> u64 {
		DEFAULT_ACCEPT_FEE_BASE
	}

	/// Minimum fee to perform a swap.
	/// Requires enough fee for the swap server's kernel, 1 input and its output to swap.
	fn get_minimum_swap_fee(&self) -> u64 {
		TransactionBody::weight_by_iok(1, 1, 1) * self.get_fee_base()
	}
}

impl SwapServer for SwapServerImpl {
	fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError> {
		// Verify that more than 1 payload exists when there's a next server,
		// or that exactly 1 payload exists when this is the final server
		if self.server_config.next_server.is_some() && onion.enc_payloads.len() <= 1
			|| self.server_config.next_server.is_none() && onion.enc_payloads.len() != 1
		{
			return Err(SwapError::InvalidPayloadLength);
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

		// Peel off top layer of encryption
		let peeled = onion
			.peel_layer(&self.server_config.key)
			.map_err(|e| SwapError::PeelOnionFailure(e))?;

		// Verify the fee meets the minimum
		let fee: u64 = peeled.payload.fee.into();
		if fee < self.get_minimum_swap_fee() {
			return Err(SwapError::FeeTooLow {
				minimum_fee: self.get_minimum_swap_fee(),
				actual_fee: fee,
			});
		}

		// Verify the rangeproof
		if let Some(r) = peeled.payload.rangeproof {
			let secp = Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
			secp.verify_bullet_proof(peeled.onion.commit, r, None)
				.map_err(|_| SwapError::InvalidRangeproof)?;
		} else if peeled.onion.enc_payloads.is_empty() {
			// A rangeproof is required in the last payload
			return Err(SwapError::MissingRangeproof);
		}

		let locked = self.store.lock().unwrap();

		locked
			.save_swap(
				&SwapData {
					excess: peeled.payload.excess,
					output_commit: peeled.onion.commit,
					rangeproof: peeled.payload.rangeproof,
					input,
					fee: fee as u64,
					onion: peeled.onion,
					status: SwapStatus::Unprocessed,
				},
				false,
			)
			.map_err(|e| match e {
				StoreError::AlreadyExists(_) => SwapError::AlreadySwapped {
					commit: onion.commit.clone(),
				},
				_ => SwapError::StoreError(e),
			})?;
		Ok(())
	}

	fn execute_round(&self) -> Result<Option<Transaction>, Box<dyn std::error::Error>> {
		let locked_store = self.store.lock().unwrap();
		let next_block_height = self.node.get_chain_height()? + 1;

		let spendable: Vec<SwapData> = locked_store
			.swaps_iter()?
			.unique_by(|s| s.output_commit)
			.filter(|s| match s.status {
				SwapStatus::Unprocessed => true,
				_ => false,
			})
			.filter(|s| {
				node::is_spendable(&self.node, &s.input.commit, next_block_height).unwrap_or(false)
			})
			.filter(|s| !node::is_unspent(&self.node, &s.output_commit).unwrap_or(true))
			.sorted_by(|a, b| a.output_commit.partial_cmp(&b.output_commit).unwrap())
			.collect();

		if spendable.len() == 0 {
			return Ok(None);
		}

		let (filtered, failed, offset, outputs, kernels) = if let Some(client) = &self.next_server {
			// Call next mix server
			let onions = spendable.iter().map(|s| s.onion.clone()).collect();
			let (indices, mixed) = client
				.mix_outputs(&onions)
				.map_err(|e| SwapError::ClientError(e.to_string()))?;

			// Filter out failed entries
			let kept_indices = HashSet::<_>::from_iter(indices.clone());
			let filtered = spendable
				.iter()
				.enumerate()
				.filter(|(i, _)| kept_indices.contains(i))
				.map(|(_, j)| j.clone())
				.collect();

			let failed = spendable
				.iter()
				.enumerate()
				.filter(|(i, _)| !kept_indices.contains(i))
				.map(|(_, j)| j.clone())
				.collect();

			(filtered, failed, mixed.offset, mixed.outputs, mixed.kernels)
		} else {
			// Build plain outputs for each swap entry
			let outputs: Vec<Output> = spendable
				.iter()
				.map(|s| {
					Output::new(
						OutputFeatures::Plain,
						s.output_commit,
						s.rangeproof.unwrap(),
					)
				})
				.collect();

			(spendable, Vec::new(), ZERO_KEY, outputs, Vec::new())
		};

		let fees_paid: u64 = filtered.iter().map(|s| s.fee).sum();
		let inputs: Vec<Input> = filtered.iter().map(|s| s.input).collect();
		let output_excesses: Vec<SecretKey> = filtered.iter().map(|s| s.excess.clone()).collect();

		let tx = tx::assemble_tx(
			&self.wallet,
			&inputs,
			&outputs,
			&kernels,
			self.get_fee_base(),
			fees_paid,
			&offset,
			&output_excesses,
		)?;

		self.node.post_tx(&tx)?;

		// Update status to in process
		let kernel_hash = tx.kernels().first().unwrap().hash();
		for mut swap in filtered {
			swap.status = SwapStatus::InProcess { kernel_hash };
			locked_store.save_swap(&swap, true)?;
		}

		// Update status of failed swaps
		for mut swap in failed {
			swap.status = SwapStatus::Failed;
			locked_store.save_swap(&swap, true)?;
		}

		Ok(Some(tx))
	}
}

#[cfg(test)]
pub mod mock {
	use super::{SwapError, SwapServer};
	use crate::crypto::comsig::ComSignature;

	use grin_core::core::Transaction;
	use grin_onion::onion::Onion;
	use std::collections::HashMap;

	pub struct MockSwapServer {
		errors: HashMap<Onion, SwapError>,
	}

	impl MockSwapServer {
		pub fn new() -> MockSwapServer {
			MockSwapServer {
				errors: HashMap::new(),
			}
		}

		pub fn set_response(&mut self, onion: &Onion, e: SwapError) {
			self.errors.insert(onion.clone(), e);
		}
	}

	impl SwapServer for MockSwapServer {
		fn swap(&self, onion: &Onion, _comsig: &ComSignature) -> Result<(), SwapError> {
			if let Some(e) = self.errors.get(&onion) {
				return Err(e.clone());
			}

			Ok(())
		}

		fn execute_round(&self) -> Result<Option<Transaction>, Box<dyn std::error::Error>> {
			Ok(None)
		}
	}
}

#[cfg(test)]
pub mod test_util {
	use crate::crypto::dalek::DalekPublicKey;
	use crate::crypto::secp::SecretKey;
	use crate::servers::swap::SwapServerImpl;
	use crate::wallet::mock::MockWallet;
	use crate::{config, GrinNode, MixClient, SwapStore};
	use std::sync::Arc;

	pub fn new_swapper(
		test_dir: &str,
		server_key: &SecretKey,
		next_server: Option<(&DalekPublicKey, &Arc<dyn MixClient>)>,
		node: Arc<dyn GrinNode>,
	) -> (Arc<SwapServerImpl>, Arc<MockWallet>) {
		let config =
			config::test_util::local_config(&server_key, &None, &next_server.map(|n| n.0.clone()))
				.unwrap();

		let wallet = Arc::new(MockWallet::new());
		let store = SwapStore::new(test_dir).unwrap();
		let swap_server = Arc::new(SwapServerImpl::new(
			config,
			next_server.map(|n| n.1.clone()),
			wallet.clone(),
			node,
			store,
		));

		(swap_server, wallet)
	}
}

#[cfg(test)]
mod tests {
	use crate::node::mock::MockGrinNode;
	use crate::servers::swap::{SwapError, SwapServer};
	use crate::store::{SwapData, SwapStatus};
	use crate::tx::TxComponents;
	use crate::{client, tx, MixClient};

	use ::function_name::named;
	use grin_core::core::hash::Hashed;
	use grin_core::core::{Committed, Input, Output, OutputFeatures, Transaction, Weighting};
	use grin_onion::crypto::comsig::ComSignature;
	use grin_onion::crypto::secp;
	use grin_onion::onion::Onion;
	use grin_onion::test_util as onion_test_util;
	use grin_onion::{create_onion, new_hop, Hop};
	use secp256k1zkp::key::ZERO_KEY;
	use std::sync::Arc;
	use x25519_dalek::PublicKey as xPublicKey;

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

	macro_rules! init_test {
		() => {{
			grin_core::global::set_local_chain_type(
				grin_core::global::ChainTypes::AutomatedTesting,
			);
			let test_dir = concat!("./target/tmp/.", function_name!());
			let _ = std::fs::remove_dir_all(test_dir);
			test_dir
		}};
	}

	/// Standalone swap server to demonstrate request validation and onion unwrapping.
	#[test]
	#[named]
	fn swap_standalone() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let (output_commit, proof) = onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop.clone()])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		server.swap(&onion, &comsig)?;

		// Make sure entry is added to server.
		let expected = SwapData {
			excess: hop_excess.clone(),
			output_commit: output_commit.clone(),
			rangeproof: Some(proof),
			input: Input::new(OutputFeatures::Plain, input_commit.clone()),
			fee: fee as u64,
			onion: Onion {
				ephemeral_pubkey: xPublicKey::from([0u8; 32]),
				commit: output_commit.clone(),
				enc_payloads: vec![],
			},
			status: SwapStatus::Unprocessed,
		};

		{
			let store = server.store.lock().unwrap();
			assert_eq!(1, store.swaps_iter().unwrap().count());
			assert!(store.swap_exists(&input_commit).unwrap());
			assert_eq!(expected, store.get_swap(&input_commit).unwrap());
		}

		let tx = server.execute_round()?;
		assert!(tx.is_some());

		{
			// check that status was updated
			let store = server.store.lock().unwrap();
			assert!(match store.get_swap(&input_commit)?.status {
				SwapStatus::InProcess { kernel_hash } =>
					kernel_hash == tx.unwrap().kernels().first().unwrap().hash(),
				_ => false,
			});
		}

		// check that the transaction was posted
		let posted_txns = node.get_posted_txns();
		assert_eq!(posted_txns.len(), 1);
		let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
		assert!(posted_txn.inputs_committed().contains(&input_commit));
		assert!(posted_txn.outputs_committed().contains(&output_commit));
		// todo: check that outputs also contain the commitment generated by our wallet

		posted_txn.validate(Weighting::AsTransaction)?;

		Ok(())
	}

	/// Multi-server test to verify proper MixClient communication.
	#[test]
	#[named]
	fn swap_multiserver() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		// Setup input
		let value: u64 = 200_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;
		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));

		// Swapper data
		let swap_fee: u32 = 50_000_000;
		let (swap_sk, _swap_pk) = onion_test_util::rand_keypair();
		let swap_hop_excess = secp::random_secret();
		let swap_hop = new_hop(&swap_sk, &swap_hop_excess, swap_fee, None);

		// Mixer data
		let mixer_fee: u32 = 30_000_000;
		let (mixer_sk, mixer_pk) = onion_test_util::rand_keypair();
		let mixer_hop_excess = secp::random_secret();
		let (output_commit, proof) = onion_test_util::proof(
			value,
			swap_fee + mixer_fee,
			&blind,
			&vec![&swap_hop_excess, &mixer_hop_excess],
		);
		let mixer_hop = new_hop(&mixer_sk, &mixer_hop_excess, mixer_fee, Some(proof));

		// Create onion
		let onion = create_onion(&input_commit, &vec![swap_hop, mixer_hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		// Mock mixer
		let mixer_onion = onion.peel_layer(&swap_sk)?.onion;
		let mut mock_mixer = client::mock::MockMixClient::new();
		let mixer_response = TxComponents {
			offset: ZERO_KEY,
			outputs: vec![Output::new(
				OutputFeatures::Plain,
				output_commit.clone(),
				proof.clone(),
			)],
			kernels: vec![tx::build_kernel(&mixer_hop_excess, mixer_fee as u64)?],
		};
		mock_mixer.set_response(
			&vec![mixer_onion.clone()],
			(vec![0 as usize], mixer_response),
		);

		let mixer: Arc<dyn MixClient> = Arc::new(mock_mixer);
		let (swapper, _) = super::test_util::new_swapper(
			&test_dir,
			&swap_sk,
			Some((&mixer_pk, &mixer)),
			node.clone(),
		);
		swapper.swap(&onion, &comsig)?;

		let tx = swapper.execute_round()?;
		assert!(tx.is_some());

		// check that the transaction was posted
		let posted_txns = node.get_posted_txns();
		assert_eq!(posted_txns.len(), 1);
		let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
		assert!(posted_txn.inputs_committed().contains(&input_commit));
		assert!(posted_txn.outputs_committed().contains(&output_commit));
		// todo: check that outputs also contain the commitment generated by our wallet

		posted_txn.validate(Weighting::AsTransaction)?;

		Ok(())
	}

	/// Returns InvalidPayloadLength when too many payloads are provided.
	#[test]
	#[named]
	fn swap_too_many_payloads() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let hops: Vec<Hop> = vec![hop.clone(), hop.clone()]; // Multiple payloads
		let onion = create_onion(&input_commit, &hops)?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig);
		assert_eq!(Err(SwapError::InvalidPayloadLength), result);

		// Make sure no entry is added to the store
		assert_eq!(
			0,
			server.store.lock().unwrap().swaps_iter().unwrap().count()
		);

		Ok(())
	}

	/// Returns InvalidComSignature when ComSignature fails to verify.
	#[test]
	#[named]
	fn swap_invalid_com_signature() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop])?;

		let wrong_blind = secp::random_secret();
		let comsig = ComSignature::sign(value, &wrong_blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig);
		assert_eq!(Err(SwapError::InvalidComSignature), result);

		// Make sure no entry is added to the store
		assert_eq!(
			0,
			server.store.lock().unwrap().swaps_iter().unwrap().count()
		);

		Ok(())
	}

	/// Returns InvalidRangeProof when the rangeproof fails to verify for the commitment.
	#[test]
	#[named]
	fn swap_invalid_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let wrong_value = value + 10_000_000;
		let (_output_commit, proof) =
			onion_test_util::proof(wrong_value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig);
		assert_eq!(Err(SwapError::InvalidRangeproof), result);

		// Make sure no entry is added to the store
		assert_eq!(
			0,
			server.store.lock().unwrap().swaps_iter().unwrap().count()
		);

		Ok(())
	}

	/// Returns MissingRangeproof when no rangeproof is provided.
	#[test]
	#[named]
	fn swap_missing_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let hop = new_hop(&server_key, &hop_excess, fee, None);

		let onion = create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig);
		assert_eq!(Err(SwapError::MissingRangeproof), result);

		// Make sure no entry is added to the store
		assert_eq!(
			0,
			server.store.lock().unwrap().swaps_iter().unwrap().count()
		);

		Ok(())
	}

	/// Returns CoinNotFound when there's no matching output in the UTXO set.
	#[test]
	#[named]
	fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new());
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig);
		assert_eq!(
			Err(SwapError::CoinNotFound {
				commit: input_commit.clone()
			}),
			result
		);

		// Make sure no entry is added to the store
		assert_eq!(
			0,
			server.store.lock().unwrap().swaps_iter().unwrap().count()
		);

		Ok(())
	}

	/// Returns AlreadySwapped when trying to swap the same commitment multiple times.
	#[test]
	#[named]
	fn swap_already_swapped() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
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
	#[named]
	fn swap_peel_onion_failure() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 50_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);

		let wrong_server_key = secp::random_secret();
		let hop = new_hop(&wrong_server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig);

		assert!(result.is_err());
		assert_error_type!(result, SwapError::PeelOnionFailure(_));

		Ok(())
	}

	/// Returns FeeTooLow when the minimum fee is not met.
	#[test]
	#[named]
	fn swap_fee_too_low() -> Result<(), Box<dyn std::error::Error>> {
		let test_dir = init_test!();

		let value: u64 = 200_000_000;
		let fee: u32 = 1_000_000;
		let blind = secp::random_secret();
		let input_commit = secp::commit(value, &blind)?;

		let server_key = secp::random_secret();
		let hop_excess = secp::random_secret();
		let (_output_commit, proof) =
			onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
		let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

		let onion = create_onion(&input_commit, &vec![hop])?;
		let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

		let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
		let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
		let result = server.swap(&onion, &comsig);
		assert_eq!(
			Err(SwapError::FeeTooLow {
				minimum_fee: 12_500_000,
				actual_fee: fee as u64
			}),
			result
		);

		Ok(())
	}
}
