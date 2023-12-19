use crate::common::miner::Miner;
use crate::common::node::GrinNodeManager;
use crate::common::server::Servers;
use crate::common::wallet::GrinWalletManager;
use function_name::named;
use grin_core::global;
use grin_util::logger::LoggingConfig;
use log::Level;
use std::ops::Deref;

mod common;

#[macro_use]
extern crate log;

/// Just removes all results from previous runs
fn clean_all_output(test_dir: &str) {
	if let Err(e) = remove_dir_all::remove_dir_all(test_dir) {
		println!("can't remove output from previous test :{}, may be ok", e);
	}
}

fn setup_test(test_name: &str) -> (GrinNodeManager, GrinWalletManager, String) {
	let test_dir = format!("./target/tmp/.{}", test_name);
	clean_all_output(test_dir.as_str());

	let mut logger = LoggingConfig::default();
	logger.log_to_file = false;
	logger.stdout_log_level = Level::Error;
	grin_util::init_logger(Some(logger), None);
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(50_000_000);
	global::init_global_chain_type(global::ChainTypes::AutomatedTesting);

	let nodes = GrinNodeManager::new(test_dir.as_str());
	let wallets = GrinWalletManager::new(test_dir.as_str());

	(nodes, wallets, test_dir)
}

#[test]
#[named]
fn integration_test() -> Result<(), Box<dyn std::error::Error>> {
	let (mut nodes, mut wallets, test_dir) = setup_test(function_name!());
	let mut rt = tokio::runtime::Builder::new()
		.threaded_scheduler()
		.enable_all()
		.build()?;

	// Create node
	let node1 = nodes.new_node();
	let node1_url = node1.lock().api_address();
	let node1_server = node1.lock().start();

	// Setup swap & mix servers and their wallets
	let rt_handle = rt.handle().clone();
	let mut servers = rt.block_on(Servers::async_setup(
		test_dir.as_str(),
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
			.async_mine_next_block(&mining_wallet, &vec![tx1, tx2])
			.await;

		let user1_km = user1_wallet.lock().keychain_mask();
		let (_, outputs) = user1_wallet
			.lock()
			.owner_api()
			.retrieve_outputs(user1_km.as_ref(), false, false, None)
			.unwrap();
		assert_eq!(outputs.len(), 1);
		for output in &outputs {
			let (onion, comsig) = user1_wallet
				.lock()
				.build_onion(&output.commit, &servers.get_pub_keys())
				.unwrap();
			servers.swapper.async_swap(&onion, &comsig).await.unwrap();
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

		let _tx = servers.swapper.async_execute_round().await.unwrap();
	});

	servers.stop_all();
	nodes.stop_all();

	Ok(())
}
