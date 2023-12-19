use crate::client::MixClient;
use crate::config::ServerConfig;
use crate::node::{self, GrinNode};
use crate::tx::{self, TxComponents};
use crate::wallet::Wallet;

use crate::servers::mix_rpc::MixResp;
use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use grin_core::core::{Output, OutputFeatures, TransactionBody};
use grin_core::global::DEFAULT_ACCEPT_FEE_BASE;
use grin_core::ser;
use grin_core::ser::ProtocolVersion;
use grin_onion::crypto::dalek::{self, DalekSignature};
use grin_onion::onion::{Onion, OnionError, PeeledOnion};
use itertools::Itertools;
use secp256k1zkp::key::ZERO_KEY;
use secp256k1zkp::Secp256k1;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;

/// Mixer error types
#[derive(Error, Debug)]
pub enum MixError {
	#[error("Invalid number of payloads provided")]
	InvalidPayloadLength,
	#[error("Signature is invalid")]
	InvalidSignature,
	#[error("Rangeproof is invalid")]
	InvalidRangeproof,
	#[error("Rangeproof is required but was not supplied")]
	MissingRangeproof,
	#[error("Failed to peel onion layer: {0:?}")]
	PeelOnionFailure(OnionError),
	#[error("Fee too low (expected >= {minimum_fee:?}, actual {actual_fee:?})")]
	FeeTooLow { minimum_fee: u64, actual_fee: u64 },
	#[error("None of the outputs could be mixed")]
	NoValidOutputs,
	#[error("Dalek error: {0:?}")]
	Dalek(dalek::DalekError),
	#[error("Secp error: {0:?}")]
	Secp(grin_util::secp::Error),
	#[error("Error building transaction: {0:?}")]
	TxError(tx::TxError),
	#[error("Wallet error: {0:?}")]
	WalletError(crate::wallet::WalletError),
	#[error("Client comm error: {0:?}")]
	Client(crate::client::ClientError),
}

/// An internal MWixnet server - a "Mixer"
#[async_trait]
pub trait MixServer: Send + Sync {
	/// Swaps the outputs provided and returns the final swapped outputs and kernels.
	async fn mix_outputs(
		&self,
		onions: &Vec<Onion>,
		sig: &DalekSignature,
	) -> Result<MixResp, MixError>;
}

/// The standard MWixnet "Mixer" implementation
#[derive(Clone)]
pub struct MixServerImpl {
	secp: Secp256k1,
	server_config: ServerConfig,
	mix_client: Option<Arc<dyn MixClient>>,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
}

impl MixServerImpl {
	/// Create a new 'Mix' server
	pub fn new(
		server_config: ServerConfig,
		mix_client: Option<Arc<dyn MixClient>>,
		wallet: Arc<dyn Wallet>,
		node: Arc<dyn GrinNode>,
	) -> Self {
		MixServerImpl {
			secp: Secp256k1::new(),
			server_config,
			mix_client,
			wallet,
			node,
		}
	}

	/// The fee base to use. For now, just using the default.
	fn get_fee_base(&self) -> u64 {
		DEFAULT_ACCEPT_FEE_BASE
	}

	/// Minimum fee to perform a mix.
	/// Requires enough fee for the mixer's kernel.
	fn get_minimum_mix_fee(&self) -> u64 {
		TransactionBody::weight_by_iok(0, 0, 1) * self.get_fee_base()
	}

	fn peel_onion(&self, onion: &Onion) -> Result<PeeledOnion, MixError> {
		// Verify that more than 1 payload exists when there's a next server,
		// or that exactly 1 payload exists when this is the final server
		if self.server_config.next_server.is_some() && onion.enc_payloads.len() <= 1
			|| self.server_config.next_server.is_none() && onion.enc_payloads.len() != 1
		{
			return Err(MixError::InvalidPayloadLength);
		}

		// Peel the top layer
		let peeled = onion
			.peel_layer(&self.server_config.key)
			.map_err(|e| MixError::PeelOnionFailure(e))?;

		// Verify the fee meets the minimum
		let fee: u64 = peeled.payload.fee.into();
		if fee < self.get_minimum_mix_fee() {
			return Err(MixError::FeeTooLow {
				minimum_fee: self.get_minimum_mix_fee(),
				actual_fee: fee,
			});
		}

		if let Some(r) = peeled.payload.rangeproof {
			// Verify the bullet proof
			self.secp
				.verify_bullet_proof(peeled.onion.commit, r, None)
				.map_err(|_| MixError::InvalidRangeproof)?;
		} else if peeled.onion.enc_payloads.is_empty() {
			// A rangeproof is required in the last payload
			return Err(MixError::MissingRangeproof);
		}

		Ok(peeled)
	}

	async fn async_build_final_outputs(
		&self,
		peeled: &Vec<(usize, PeeledOnion)>,
	) -> Result<MixResp, MixError> {
		// Filter out commitments that already exist in the UTXO set
		let filtered: Vec<&(usize, PeeledOnion)> = stream::iter(peeled.iter())
			.filter(|(_, p)| async {
				!node::async_is_unspent(&self.node, &p.onion.commit)
					.await
					.unwrap_or(true)
			})
			.collect()
			.await;

		// Build plain outputs for each mix entry
		let outputs: Vec<Output> = filtered
			.iter()
			.map(|(_, p)| {
				Output::new(
					OutputFeatures::Plain,
					p.onion.commit,
					p.payload.rangeproof.unwrap(),
				)
			})
			.collect();

		let fees_paid = filtered.iter().map(|(_, p)| p.payload.fee.fee()).sum();
		let output_excesses = filtered
			.iter()
			.map(|(_, p)| p.payload.excess.clone())
			.collect();

		let components = tx::async_assemble_components(
			&self.wallet,
			&TxComponents {
				offset: ZERO_KEY,
				kernels: Vec::new(),
				outputs,
			},
			&output_excesses,
			self.get_fee_base(),
			fees_paid,
		)
		.await
		.map_err(MixError::TxError)?;

		let indices = filtered.iter().map(|(i, _)| *i).collect();

		Ok(MixResp {
			indices,
			components,
		})
	}

	async fn call_next_mixer(
		&self,
		peeled: &Vec<(usize, PeeledOnion)>,
	) -> Result<MixResp, MixError> {
		// Sort by commitment
		let mut onions_with_index = peeled.clone();
		onions_with_index
			.sort_by(|(_, a), (_, b)| a.onion.commit.partial_cmp(&b.onion.commit).unwrap());

		// Create map of prev indices to next indices
		let map_indices: HashMap<usize, usize> =
			HashMap::from_iter(onions_with_index.iter().enumerate().map(|(i, j)| (j.0, i)));

		// Call next server
		let onions = peeled.iter().map(|(_, p)| p.onion.clone()).collect();
		let mixed = self
			.mix_client
			.as_ref()
			.unwrap()
			.mix_outputs(&onions)
			.await
			.map_err(MixError::Client)?;

		// Remove filtered entries
		let kept_next_indices = HashSet::<_>::from_iter(mixed.indices.clone());
		let filtered_onions: Vec<&(usize, PeeledOnion)> = onions_with_index
			.iter()
			.filter(|(i, _)| {
				map_indices.contains_key(i)
					&& kept_next_indices.contains(map_indices.get(i).unwrap())
			})
			.collect();

		// Calculate excess of entries kept
		let excesses = filtered_onions
			.iter()
			.map(|(_, p)| p.payload.excess.clone())
			.collect();

		// Calculate total fee of entries kept
		let fees_paid = filtered_onions
			.iter()
			.fold(0, |f, (_, p)| f + p.payload.fee.fee());

		let indices = kept_next_indices.into_iter().sorted().collect();

		let components = tx::async_assemble_components(
			&self.wallet,
			&mixed.components,
			&excesses,
			self.get_fee_base(),
			fees_paid,
		)
		.await
		.map_err(MixError::TxError)?;

		Ok(MixResp {
			indices,
			components,
		})
	}
}

#[async_trait]
impl MixServer for MixServerImpl {
	async fn mix_outputs(
		&self,
		onions: &Vec<Onion>,
		sig: &DalekSignature,
	) -> Result<MixResp, MixError> {
		// Verify Signature
		let serialized = ser::ser_vec(&onions, ProtocolVersion::local()).unwrap();
		sig.verify(
			self.server_config.prev_server.as_ref().unwrap(),
			serialized.as_slice(),
		)
		.map_err(|_| MixError::InvalidSignature)?;

		// Peel onions and filter
		let mut peeled: Vec<(usize, PeeledOnion)> = onions
			.iter()
			.enumerate()
			.filter_map(|(i, o)| match self.peel_onion(&o) {
				Ok(p) => Some((i, p)),
				Err(e) => {
					println!("Error peeling onion: {:?}", e);
					None
				}
			})
			.collect();

		// Remove duplicate commitments
		peeled.sort_by_key(|(_, o)| o.onion.commit);
		peeled.dedup_by_key(|(_, o)| o.onion.commit);
		peeled.sort_by_key(|(i, _)| *i);

		if peeled.is_empty() {
			return Err(MixError::NoValidOutputs);
		}

		if self.server_config.next_server.is_some() {
			self.call_next_mixer(&peeled).await
		} else {
			self.async_build_final_outputs(&peeled).await
		}
	}
}

#[cfg(test)]
mod test_util {
	use crate::client::test_util::DirectMixClient;
	use crate::client::MixClient;
	use crate::config;
	use crate::node::mock::MockGrinNode;
	use crate::servers::mix::MixServerImpl;
	use crate::wallet::mock::MockWallet;

	use grin_onion::crypto::dalek::DalekPublicKey;
	use secp256k1zkp::SecretKey;
	use std::sync::Arc;

	pub fn new_mixer(
		server_key: &SecretKey,
		prev_server: (&SecretKey, &DalekPublicKey),
		next_server: &Option<(DalekPublicKey, Arc<dyn MixClient>)>,
		node: &Arc<MockGrinNode>,
	) -> (Arc<DirectMixClient>, Arc<MockWallet>) {
		let config = config::test_util::local_config(
			&server_key,
			&Some(prev_server.1.clone()),
			&next_server.as_ref().map(|(k, _)| k.clone()),
		)
		.unwrap();

		let wallet = Arc::new(MockWallet::new());
		let mix_server = Arc::new(MixServerImpl::new(
			config,
			next_server.as_ref().map(|(_, c)| c.clone()),
			wallet.clone(),
			node.clone(),
		));
		let client = Arc::new(DirectMixClient {
			key: prev_server.0.clone(),
			mix_server: mix_server.clone(),
		});

		(client, wallet)
	}
}

#[cfg(test)]
mod tests {
	use crate::client::MixClient;
	use crate::node::mock::MockGrinNode;

	use ::function_name::named;
	use grin_onion::crypto::dalek::DalekPublicKey;
	use grin_onion::crypto::secp::{self, Commitment};
	use grin_onion::test_util as onion_test_util;
	use grin_onion::{create_onion, new_hop, Hop};
	use secp256k1zkp::pedersen::RangeProof;
	use secp256k1zkp::SecretKey;
	use std::collections::HashSet;
	use std::sync::Arc;

	macro_rules! init_test {
		() => {{
			grin_core::global::set_local_chain_type(
				grin_core::global::ChainTypes::AutomatedTesting,
			);
			let db_root = concat!("./target/tmp/.", function_name!());
			let _ = std::fs::remove_dir_all(db_root);
			()
		}};
	}

	struct ServerVars {
		fee: u32,
		sk: SecretKey,
		pk: DalekPublicKey,
		excess: SecretKey,
	}

	impl ServerVars {
		fn new(fee: u32) -> Self {
			let (sk, pk) = onion_test_util::rand_keypair();
			let excess = secp::random_secret();
			ServerVars {
				fee,
				sk,
				pk,
				excess,
			}
		}

		fn build_hop(&self, proof: Option<RangeProof>) -> Hop {
			new_hop(&self.sk, &self.excess, self.fee, proof)
		}
	}

	/// Tests the happy path for a 3 server setup.
	///
	/// Servers:
	/// * Swap Server - Simulated by test
	/// * Mixer 1 - Internal MixServerImpl directly called by test
	/// * Mixer 2 - Final MixServerImpl called by Mixer 1
	#[tokio::test]
	#[named]
	async fn mix_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
		init_test!();

		// Setup Input(s)
		let input1_value: u64 = 200_000_000;
		let input1_blind = secp::random_secret();
		let input1_commit = secp::commit(input1_value, &input1_blind)?;
		let input_commits = vec![&input1_commit];

		// Setup Servers
		let (swap_vars, mix1_vars, mix2_vars) = (
			ServerVars::new(50_000_000),
			ServerVars::new(50_000_000),
			ServerVars::new(50_000_000),
		);

		let node = Arc::new(MockGrinNode::new_with_utxos(&input_commits));
		let (mixer2_client, mixer2_wallet) = super::test_util::new_mixer(
			&mix2_vars.sk,
			(&mix1_vars.sk, &mix1_vars.pk),
			&None,
			&node,
		);

		let (mixer1_client, mixer1_wallet) = super::test_util::new_mixer(
			&mix1_vars.sk,
			(&swap_vars.sk, &swap_vars.pk),
			&Some((mix2_vars.pk.clone(), mixer2_client.clone())),
			&node,
		);

		// Build rangeproof
		let (output_commit, proof) = onion_test_util::proof(
			input1_value,
			swap_vars.fee + mix1_vars.fee + mix2_vars.fee,
			&input1_blind,
			&vec![&swap_vars.excess, &mix1_vars.excess, &mix2_vars.excess],
		);

		// Create Onion
		let onion = create_onion(
			&input1_commit,
			&vec![
				swap_vars.build_hop(None),
				mix1_vars.build_hop(None),
				mix2_vars.build_hop(Some(proof)),
			],
		)?;

		// Simulate the swap server peeling the onion and then calling mix1
		let mix1_onion = onion.peel_layer(&swap_vars.sk)?;
		let mixed = mixer1_client
			.mix_outputs(&vec![mix1_onion.onion.clone()])
			.await?;

		// Verify 3 outputs are returned: mixed output, mixer1's output, and mixer2's output
		assert_eq!(mixed.indices, vec![0 as usize]);
		assert_eq!(mixed.components.outputs.len(), 3);
		let output_commits: HashSet<Commitment> = mixed
			.components
			.outputs
			.iter()
			.map(|o| o.identifier.commit.clone())
			.collect();
		assert!(output_commits.contains(&output_commit));

		assert_eq!(mixer1_wallet.built_outputs().len(), 1);
		assert!(output_commits.contains(mixer1_wallet.built_outputs().get(0).unwrap()));

		assert_eq!(mixer2_wallet.built_outputs().len(), 1);
		assert!(output_commits.contains(mixer2_wallet.built_outputs().get(0).unwrap()));

		Ok(())
	}
}
