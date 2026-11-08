// Copyright 2026 The Grin Developers
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

mod common;

#[macro_use]
extern crate log;

use crate::common::miner::Miner;
use crate::common::node::GrinNodeManager;
use crate::common::server::Servers;
use crate::common::wallet::GrinWalletManager;

use grin_chain::{Chain, Options};
use grin_core::core::hash::Hashed;
use grin_core::global;
use grin_p2p::tor::start_tor;
use grin_util::logger::LoggingConfig;
use mwixnet::config::TorMwixnetConfig;

use function_name::named;
use log::Level;
use std::ops::Deref;

fn setup_test(test_name: &str) -> (GrinNodeManager, GrinWalletManager, tempfile::TempDir) {
	// Avoid checkout permissions affecting Tor
	let test_dir = tempfile::Builder::new()
		.prefix(test_name)
		.tempdir()
		.unwrap();
	let test_path = test_dir.path().to_str().unwrap();

	let logger = LoggingConfig {
		log_to_file: false,
		stdout_log_level: Level::Error,
		..Default::default()
	};
	grin_util::init_logger(Some(logger), None);
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(50_000_000);
	global::init_global_chain_type(global::ChainTypes::AutomatedTesting);

	let nodes = GrinNodeManager::new(test_path);
	let wallets = GrinWalletManager::new(test_path);

	(nodes, wallets, test_dir)
}

fn copy_blocks(source: &Chain, target: &Chain, start_height: u64, end_height: u64) {
	for height in start_height..=end_height {
		let hash = source.get_header_by_height(height).unwrap().hash();
		let block = source.get_block(&hash).unwrap();
		target.process_block(block, Options::MINE).unwrap();
	}
}

#[test]
#[named]
#[allow(clippy::await_holding_lock)]
fn integration_test() -> Result<(), Box<dyn std::error::Error>> {
	let (mut nodes, mut wallets, test_dir) = setup_test(function_name!());
	let rt = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()?;

	// Create node
	let node1 = nodes.new_node();
	let node1_url = node1.lock().api_address();
	let node1_server = node1.lock().start();

	// Start Tor
	let tor_config = TorMwixnetConfig {
		data_file_dir: test_dir.path().display().to_string(),
		..Default::default()
	};
	start_tor(&tor_config)?;

	// Setup swap & mix servers and their wallets
	let rt_handle = rt.handle().clone();
	let mut servers = rt.block_on(Servers::async_setup(
		test_dir.path().to_str().unwrap(),
		&rt_handle,
		&mut wallets,
		&node1,
		2usize,
	));

	rt.block_on(async {
		// Setup wallet to use with miner
		let mining_wallet = wallets.async_new_wallet(&node1_url).await;

		// Mine enough blocks to have spendable coins
		let miner = Miner::new(node1_server.chain.clone());
		miner
			.async_mine_empty_blocks(&mining_wallet, 5 + global::coinbase_maturity() as usize)
			.await;

		// Setup wallets for swap users
		let user1_wallet = wallets.async_new_wallet(&node1_url).await;
		let user2_wallet = wallets.async_new_wallet(&node1_url).await;

		// Send from mining_wallet to user1_wallet
		let tx1 = mining_wallet
			.lock()
			.async_send(user1_wallet.lock().deref(), 10_000_000_000)
			.await
			.unwrap();
		let tx2 = mining_wallet
			.lock()
			.async_send(user2_wallet.lock().deref(), 20_000_000_000)
			.await
			.unwrap();
		miner
			.async_mine_next_block(&mining_wallet, &[tx1, tx2])
			.await;
		let fork_height = node1_server.chain.head_header().unwrap().height;

		let user1_km = user1_wallet.lock().keychain_mask();
		let (_, outputs) = user1_wallet
			.lock()
			.owner_api()
			.retrieve_outputs(user1_km.as_ref(), false, true, None)
			.unwrap();
		assert_eq!(outputs.len(), 1);
		for output in &outputs {
			let creation = user1_wallet
				.lock()
				.async_create_mwixnet_req(&output.commit, &servers.get_server_keys())
				.await
				.unwrap();
			assert!(creation.tx_id.is_some());
			servers.swapper.async_swap(&creation.request).await.unwrap();
		}

		let mining_wallet_info = mining_wallet
			.lock()
			.async_retrieve_summary_info()
			.await
			.unwrap();
		println!("Mining wallet: {:?}", mining_wallet_info);
		let user1_wallet_info = user1_wallet
			.lock()
			.async_retrieve_summary_info()
			.await
			.unwrap();
		println!("User1 wallet: {:?}", user1_wallet_info);
		let user2_wallet_info = user2_wallet
			.lock()
			.async_retrieve_summary_info()
			.await
			.unwrap();
		println!("User2 wallet: {:?}", user2_wallet_info);

		let tx = servers
			.swapper
			.async_execute_round()
			.await
			.unwrap()
			.unwrap();
		miner
			.async_mine_next_block(&mining_wallet, &[tx.as_ref().clone()])
			.await;
		let user1_wallet_info = user1_wallet
			.lock()
			.async_retrieve_summary_info()
			.await
			.unwrap();
		assert_eq!(user1_wallet_info.amount_currently_spendable, 9_850_000_000);
		assert_eq!(user1_wallet_info.amount_locked, 0);

		// Save the confirmation before the reorg
		assert!(servers
			.swapper
			.async_check_reorg(&tx)
			.await
			.unwrap()
			.is_some());

		let node2 = nodes.new_node();
		let node2_server = node2.lock().start();
		copy_blocks(&node1_server.chain, &node2_server.chain, 1, fork_height);
		let fork_miner = Miner::new(node2_server.chain.clone());
		fork_miner.async_mine_empty_blocks(&mining_wallet, 2).await;
		copy_blocks(
			&node2_server.chain,
			&node1_server.chain,
			fork_height + 1,
			fork_height + 2,
		);
		user1_wallet.lock().async_scan().await.unwrap();
		let user1_wallet_info = user1_wallet
			.lock()
			.async_retrieve_summary_info()
			.await
			.unwrap();
		assert_eq!(user1_wallet_info.amount_currently_spendable, 10_000_000_000);
		assert_eq!(user1_wallet_info.amount_locked, 0);

		let tx = servers
			.swapper
			.async_check_reorg(&tx)
			.await
			.unwrap()
			.unwrap();
		miner
			.async_mine_next_block(&mining_wallet, &[tx.as_ref().clone()])
			.await;
		user1_wallet.lock().async_scan().await.unwrap();
		let user1_wallet_info = user1_wallet
			.lock()
			.async_retrieve_summary_info()
			.await
			.unwrap();
		assert_eq!(user1_wallet_info.amount_currently_spendable, 9_850_000_000);
		assert_eq!(user1_wallet_info.amount_locked, 0);
	});

	servers.stop_all();
	nodes.stop_all();

	Ok(())
}
