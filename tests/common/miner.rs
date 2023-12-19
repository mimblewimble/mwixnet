// Copyright 2021 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Mining service, gets a block to mine, and based on mining configuration
//! chooses a version of the cuckoo miner to mine the block and produce a valid
//! header with its proof-of-work.  Any valid mined blocks are submitted to the
//! network.

use crate::common::types::BlockFees;
use crate::common::wallet::IntegrationGrinWallet;
use chrono::prelude::Utc;
use chrono::{DateTime, NaiveDateTime};
use grin_chain::Chain;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{Block, BlockHeader, Transaction};
use grin_core::{consensus, global};
use grin_keychain::Identifier;
use grin_util::Mutex;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use std::time::Duration;

pub struct Miner {
	chain: Arc<Chain>,
}

impl Miner {
	// Creates a new Miner. Needs references to the chain state and its
	/// storage.
	pub fn new(chain: Arc<Chain>) -> Miner {
		Miner { chain }
	}

	pub async fn async_mine_empty_blocks(
		&self,
		wallet: &Arc<Mutex<IntegrationGrinWallet>>,
		num_blocks: usize,
	) {
		for _ in 0..num_blocks {
			self.async_mine_next_block(wallet, &vec![]).await;
		}
	}

	/// Builds a new block on top of the existing chain.
	pub async fn async_mine_next_block(
		&self,
		wallet: &Arc<Mutex<IntegrationGrinWallet>>,
		txs: &Vec<Transaction>,
	) {
		info!("Starting test miner loop.");

		// iteration, we keep the returned derivation to provide it back when
		// nothing has changed. We only want to create a new key_id for each new block.
		let mut key_id = None;

		loop {
			// get the latest chain state and build a block on top of it
			let head = self.chain.head_header().unwrap();
			let mut latest_hash = self.chain.head().unwrap().last_block_h;

			let (mut b, block_fees) = self.async_get_block(wallet, txs, key_id.clone()).await;
			let sol = self.inner_mining_loop(&mut b, &head, &mut latest_hash);

			// we found a solution, push our block through the chain processing pipeline
			if sol {
				info!(
					"Found valid proof of work, adding block {} (prev_root {}).",
					b.hash(),
					b.header.prev_root,
				);
				let res = self.chain.process_block(b, grin_chain::Options::MINE);
				if let Err(e) = res {
					error!("Error validating mined block: {:?}", e);
				} else {
					return;
				}
				key_id = None;
			} else {
				key_id = block_fees.key_id();
			}
		}
	}

	/// The inner part of mining loop for the internal miner
	/// kept around mostly for automated testing purposes
	fn inner_mining_loop(&self, b: &mut Block, head: &BlockHeader, latest_hash: &mut Hash) -> bool {
		while head.hash() == *latest_hash {
			let mut ctx = global::create_pow_context::<u32>(
				head.height,
				global::min_edge_bits(),
				global::proofsize(),
				10,
			)
			.unwrap();
			ctx.set_header_nonce(b.header.pre_pow(), None, true)
				.unwrap();
			if let Ok(proofs) = ctx.find_cycles() {
				b.header.pow.proof = proofs[0].clone();
				let proof_diff = b.header.pow.to_difficulty(b.header.height);
				if proof_diff >= (b.header.total_difficulty() - head.total_difficulty()) {
					return true;
				}
			}

			b.header.pow.nonce += 1;
			*latest_hash = self.chain.head().unwrap().last_block_h;
		}

		false
	}

	// Ensure a block suitable for mining is built and returned
	// If a wallet listener URL is not provided the reward will be "burnt"
	// Warning: This call does not return until/unless a new block can be built
	async fn async_get_block(
		&self,
		wallet: &Arc<Mutex<IntegrationGrinWallet>>,
		txs: &Vec<Transaction>,
		key_id: Option<Identifier>,
	) -> (Block, BlockFees) {
		let wallet_retry_interval = 5;
		// get the latest chain state and build a block on top of it
		let mut result = self.async_build_block(wallet, txs, key_id.clone()).await;
		while let Err(e) = result {
			println!("Error: {:?}", &e);
			let mut new_key_id = key_id.to_owned();
			match e {
				grin_servers::common::types::Error::Chain(c) => match c {
					grin_chain::Error::DuplicateCommitment(_) => {
						debug!(
						"Duplicate commit for potential coinbase detected. Trying next derivation."
					);
						// use the next available key to generate a different coinbase commitment
						new_key_id = None;
					}
					_ => {
						error!("Chain Error: {}", c);
					}
				},
				grin_servers::common::types::Error::WalletComm(_) => {
					error!(
						"Error building new block: Can't connect to wallet listener; will retry"
					);
					async_std::task::sleep(Duration::from_secs(wallet_retry_interval)).await;
				}
				ae => {
					warn!("Error building new block: {:?}. Retrying.", ae);
				}
			}

			// only wait if we are still using the same key: a different coinbase commitment is unlikely
			// to have duplication
			if new_key_id.is_some() {
				async_std::task::sleep(Duration::from_millis(100)).await;
			}

			result = self.async_build_block(wallet, txs, new_key_id).await;
		}
		return result.unwrap();
	}

	/// Builds a new block with the chain head as previous and eligible
	/// transactions from the pool.
	async fn async_build_block(
		&self,
		wallet: &Arc<Mutex<IntegrationGrinWallet>>,
		txs: &Vec<Transaction>,
		key_id: Option<Identifier>,
	) -> Result<(Block, BlockFees), grin_servers::common::types::Error> {
		let head = self.chain.head_header()?;

		// prepare the block header timestamp
		let mut now_sec = Utc::now().timestamp();
		let head_sec = head.timestamp.timestamp();
		if now_sec <= head_sec {
			now_sec = head_sec + 1;
		}

		// Determine the difficulty our block should be at.
		// Note: do not keep the difficulty_iter in scope (it has an active batch).
		let difficulty = consensus::next_difficulty(head.height + 1, self.chain.difficulty_iter()?);

		// build the coinbase and the block itself
		let fees = txs.iter().map(|tx| tx.fee()).sum();
		let height = head.height + 1;
		let block_fees = BlockFees {
			fees,
			key_id,
			height,
		};

		let res = wallet.lock().async_create_coinbase(&block_fees).await?;
		let output = res.output;
		let kernel = res.kernel;
		let block_fees = BlockFees {
			key_id: res.key_id,
			..block_fees
		};
		let mut b = Block::from_reward(&head, &txs, output, kernel, difficulty.difficulty)?;

		// making sure we're not spending time mining a useless block
		b.validate(&head.total_kernel_offset)?;

		b.header.pow.nonce = thread_rng().gen();
		b.header.pow.secondary_scaling = difficulty.secondary_scaling;
		b.header.timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
			NaiveDateTime::from_timestamp_opt(now_sec, 0).unwrap(),
			Utc,
		);

		debug!(
			"Built new block with {} inputs and {} outputs, block difficulty: {}, cumulative difficulty {}",
			b.inputs().len(),
			b.outputs().len(),
			difficulty.difficulty,
			b.header.total_difficulty().to_num(),
		);

		// Now set txhashset roots and sizes on the header of the block being built.
		match self.chain.set_txhashset_roots(&mut b) {
			Ok(_) => Ok((b, block_fees)),
			Err(e) => {
				match e {
					// If this is a duplicate commitment then likely trying to use
					// a key that hass already been derived but not in the wallet
					// for some reason, allow caller to retry.
					grin_chain::Error::DuplicateCommitment(e) => {
						Err(grin_servers::common::types::Error::Chain(
							grin_chain::Error::DuplicateCommitment(e),
						))
					}

					// Some other issue, possibly duplicate kernel
					_ => {
						error!("Error setting txhashset root to build a block: {:?}", e);
						Err(grin_servers::common::types::Error::Chain(
							grin_chain::Error::Other(format!("{:?}", e)),
						))
					}
				}
			}
		}
	}
}
