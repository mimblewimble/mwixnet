use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use grin_core::core::{Output, Transaction, TxKernel};
use grin_core::global::ChainTypes;
use grin_keychain::{ExtKeychain, Identifier};
use grin_util::{Mutex, ToHex, ZeroingString};
use grin_wallet_api::Owner;
use grin_wallet_config::WalletConfig;
use grin_wallet_controller::controller;
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
use grin_wallet_libwallet::mwixnet::{MwixnetReqCreationResult, MwixnetServerPublicKey};
use grin_wallet_libwallet::{InitTxArgs, Slate, VersionedSlate, WalletInfo, WalletInst};
use log::error;
use mwixnet::http;
use mwixnet::wallet::HttpWallet;
use secp256k1zkp::pedersen::Commitment;
use secp256k1zkp::SecretKey;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;

use crate::common::types::BlockFees;

/// Response to build a coinbase output.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CbData {
	/// Output
	pub output: Output,
	/// Kernel
	pub kernel: TxKernel,
	/// Key Id
	pub key_id: Option<Identifier>,
}

pub struct IntegrationGrinWallet {
	api_listen_port: u16,
	owner_api:
		Arc<Owner<DefaultLCProvider<HTTPNodeClient, ExtKeychain>, HTTPNodeClient, ExtKeychain>>,
	http_client: Arc<HttpWallet>,
}

impl IntegrationGrinWallet {
	pub async fn async_new_wallet(
		wallet_dir: String,
		api_listen_port: u16,
		node_api: String,
	) -> IntegrationGrinWallet {
		std::fs::create_dir_all(&wallet_dir).unwrap();
		let node_client = HTTPNodeClient::new(&node_api, None, Duration::from_secs(30)).unwrap();
		let mut wallet =
			Box::new(DefaultWalletImpl::<HTTPNodeClient>::new(node_client.clone()).unwrap())
				as Box<
					dyn WalletInst<
						'static,
						DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
						HTTPNodeClient,
						ExtKeychain,
					>,
				>;

		// Wallet LifeCycle Provider provides all functions init wallet and work with seeds, etc...
		let lc = wallet.lc_provider().unwrap();

		let mut wallet_config = WalletConfig::default();
		wallet_config.check_node_api_http_addr = node_api.clone();
		wallet_config.owner_api_listen_port = Some(api_listen_port);
		wallet_config.api_secret_path = None;
		wallet_config.data_file_dir = wallet_dir.clone();

		// The top level wallet directory should be set manually (in the reference implementation,
		// this is provided in the WalletConfig)
		let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);

		lc.create_config(
			&ChainTypes::AutomatedTesting,
			"grin-wallet.toml",
			Some(wallet_config.clone()),
			None,
			None,
		)
		.unwrap();

		lc.create_wallet(None, None, 12, ZeroingString::from("pass"), false)
			.unwrap();

		// Start owner API
		let km = Arc::new(Mutex::new(None));
		let wallet = Arc::new(Mutex::new(wallet));
		let config_path = PathBuf::from(&wallet_dir).join("grin-wallet.toml");
		let owner_api = Arc::new(Owner::new(wallet.clone(), None, config_path.clone()));

		let address_str = format!("127.0.0.1:{}", api_listen_port);
		let address_str_2 = format!("127.0.0.1:{}", api_listen_port);
		let mut listener_api = Owner::new(wallet.clone(), None, config_path);
		let _thread_handle = thread::spawn(move || {
			controller::owner_listener(
				&mut listener_api,
				km,
				address_str.as_str(),
				None,
				None,
				Some(true),
				false,
			)
			.unwrap()
		});

		let http_client = Arc::new(
			HttpWallet::async_open_wallet(&address_str_2, &None, &ZeroingString::from("pass"))
				.await
				.unwrap(),
		);

		IntegrationGrinWallet {
			api_listen_port,
			owner_api,
			http_client,
		}
	}

	pub async fn async_retrieve_summary_info(&self) -> Result<WalletInfo, mwixnet::WalletError> {
		let params = json!({
			"token": self.http_client.clone().get_token(),
			"refresh_from_node": true,
			"minimum_confirmations": 1
		});
		let (_, wallet_info): (bool, WalletInfo) = self
			.http_client
			.clone()
			.async_perform_request("retrieve_summary_info", &params)
			.await?;
		Ok(wallet_info)
	}

	pub async fn async_scan(&self) -> Result<(), mwixnet::WalletError> {
		let params = json!({
			"token": self.http_client.get_token(),
			"start_height": null,
			"delete_unconfirmed": false,
		});
		self.http_client
			.clone()
			.async_perform_request("scan", &params)
			.await
	}

	pub async fn async_send(
		&self,
		receiving_wallet: &IntegrationGrinWallet,
		amount: u64,
	) -> Result<Transaction, mwixnet::WalletError> {
		let slate = self.async_init_send_tx(amount).await.unwrap();
		let slate = receiving_wallet.async_receive_tx(&slate).await.unwrap();
		let slate = self.async_finalize_tx(&slate).await.unwrap();
		let tx = Slate::from(slate).tx_or_err().unwrap().clone();
		Ok(tx)
	}

	async fn async_init_send_tx(
		&self,
		amount: u64,
	) -> Result<VersionedSlate, mwixnet::WalletError> {
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 0,
			max_outputs: 10,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		let params = json!({
			"token": self.http_client.clone().get_token(),
			"args": args
		});

		let slate: VersionedSlate = self
			.http_client
			.clone()
			.async_perform_request("init_send_tx", &params)
			.await?;

		let params = json!({
			"token": self.http_client.clone().get_token(),
			"slate": &slate
		});
		self.http_client
			.clone()
			.async_perform_request::<()>("tx_lock_outputs", &params)
			.await?;

		Ok(slate)
	}

	pub async fn async_receive_tx(
		&self,
		slate: &VersionedSlate,
	) -> Result<VersionedSlate, grin_servers::common::types::Error> {
		let params = json!([slate, null, null]);
		let response =
			http::async_send_json_request(&self.foreign_api(), &None, "receive_tx", &params)
				.await
				.map_err(|e| {
					let report = format!("Failed to receive tx. Is the wallet listening? {}", e);
					error!("{}", report);
					grin_servers::common::types::Error::WalletComm(report)
				})?;

		Ok(response)
	}

	async fn async_finalize_tx(
		&self,
		slate: &VersionedSlate,
	) -> Result<VersionedSlate, mwixnet::WalletError> {
		let params = json!({
			"token": self.http_client.clone().get_token(),
			"slate": slate
		});

		self.http_client
			.clone()
			.async_perform_request("finalize_tx", &params)
			.await
	}

	#[allow(dead_code)]
	async fn async_post_tx(
		&self,
		finalized_slate: &VersionedSlate,
		fluff: bool,
	) -> Result<VersionedSlate, mwixnet::WalletError> {
		let params = json!({
			"token": self.http_client.clone().get_token(),
			"slate": finalized_slate,
			"fluff": fluff
		});

		self.http_client
			.clone()
			.async_perform_request("post_tx", &params)
			.await
	}

	/// Call the wallet API to create a coinbase output for the given block_fees.
	/// Will retry based on default "retry forever with backoff" behavior.
	pub async fn async_create_coinbase(
		&self,
		block_fees: &BlockFees,
	) -> Result<CbData, grin_servers::common::types::Error> {
		let params = json!({
			"block_fees": block_fees
		});
		let response =
			http::async_send_json_request(&self.foreign_api(), &None, "build_coinbase", &params)
				.await
				.map_err(|e| {
					let report = format!("Failed to get coinbase. Is the wallet listening? {}", e);
					error!("{}", report);
					grin_servers::common::types::Error::WalletComm(report)
				})?;

		Ok(response)
	}

	pub async fn async_create_mwixnet_req(
		&self,
		commitment: &Commitment,
		server_keys: &[MwixnetServerPublicKey],
	) -> Result<MwixnetReqCreationResult, mwixnet::WalletError> {
		let server_keys = server_keys
			.iter()
			.map(|key| key.to_hex())
			.collect::<Vec<_>>();
		let params = json!({
			"token": self.http_client.get_token(),
			"commitment": commitment.to_hex(),
			"fee_per_hop": "50000000",
			"lock_output": true,
			"server_keys": server_keys,
		});
		self.http_client
			.clone()
			.async_perform_request("create_mwixnet_req", &params)
			.await
	}

	pub fn owner_api(
		&self,
	) -> Arc<Owner<DefaultLCProvider<HTTPNodeClient, ExtKeychain>, HTTPNodeClient, ExtKeychain>> {
		self.owner_api.clone()
	}

	pub fn foreign_api(&self) -> String {
		format!("http://127.0.0.1:{}/v2/foreign", self.api_listen_port)
	}

	pub fn owner_address(&self) -> SocketAddr {
		SocketAddr::new(
			IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
			self.api_listen_port,
		)
	}

	pub fn keychain_mask(&self) -> Option<SecretKey> {
		self.http_client.as_ref().get_token().keychain_mask.clone()
	}

	pub fn get_client(&self) -> Arc<HttpWallet> {
		self.http_client.clone()
	}
}

#[allow(dead_code)]
pub struct GrinWalletManager {
	// base directory for the server instance
	working_dir: String,

	wallets: Vec<Arc<Mutex<IntegrationGrinWallet>>>,
}

impl GrinWalletManager {
	pub fn new(test_dir: &str) -> GrinWalletManager {
		GrinWalletManager {
			working_dir: String::from(test_dir),
			wallets: vec![],
		}
	}

	pub async fn async_new_wallet(
		&mut self,
		node_api_addr: &SocketAddr,
	) -> Arc<Mutex<IntegrationGrinWallet>> {
		let wallet_dir = format!("{}/wallets/{}", self.working_dir, self.wallets.len());
		let wallet = Arc::new(Mutex::new(
			IntegrationGrinWallet::async_new_wallet(
				wallet_dir,
				21000 + self.wallets.len() as u16,
				format!("http://{}", node_api_addr),
			)
			.await,
		));
		self.wallets.push(wallet.clone());
		wallet
	}
}
