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

use crate::common::node::IntegrationGrinNode;
use crate::common::wallet::{GrinWalletManager, IntegrationGrinWallet};

use std::iter;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use grin_core::core::Transaction;
use grin_p2p::tor::ov3::OnionV3Address;
use grin_p2p::tor::{onion_service_status, start_onion_service, stop_onion_service, ServiceStatus};
use grin_util::secp::SecretKey;
use grin_wallet_libwallet::mwixnet::onion as grin_onion;
use grin_wallet_libwallet::mwixnet::onion::crypto::dalek::MwixnetServerIdentityKey;
use grin_wallet_libwallet::mwixnet::{
	MwixnetClient, MwixnetClientImpl, MwixnetResponse, MwixnetServerPublicKey, SwapReq,
};
use mwixnet::config::TorMwixnetConfig;
use mwixnet::mix_client::MixClientImpl;
use mwixnet::{SwapError, SwapServer, SwapStore};

pub struct IntegrationSwapServer {
	onion_pubkey: MwixnetServerPublicKey,
	client: MwixnetClientImpl<TorMwixnetConfig>,
	swap_server: Arc<tokio::sync::Mutex<dyn SwapServer>>,
	_rpc_server: mwixnet::servers::rpc::RpcServer,
	_wallet: Arc<grin_util::Mutex<IntegrationGrinWallet>>,
}

impl IntegrationSwapServer {
	pub async fn async_swap(&self, request: &SwapReq) -> Result<(), SwapError> {
		match self
			.client
			.swap(request)
			.await
			.map_err(|error| SwapError::ClientError(error.to_string()))?
		{
			MwixnetResponse::Accepted => Ok(()),
			MwixnetResponse::Rejected(message) => Err(SwapError::ClientError(message)),
		}
	}

	pub async fn async_execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError> {
		self.swap_server.lock().await.execute_round().await
	}

	pub async fn async_check_reorg(
		&self,
		tx: &Arc<Transaction>,
	) -> Result<Option<Arc<Transaction>>, SwapError> {
		self.swap_server.lock().await.check_reorg(tx).await
	}
}

pub struct IntegrationMixServer {
	server_key: SecretKey,
	onion_pubkey: MwixnetServerPublicKey,
	_rpc_server: mwixnet::servers::rpc::RpcServer,
	_wallet: Arc<grin_util::Mutex<IntegrationGrinWallet>>,
}

async fn start_tor_listener(config: &mwixnet::ServerConfig, addr: &SocketAddr) {
	tokio::task::block_in_place(|| {
		start_onion_service(config.key.clone(), &addr.to_string(), &config.tor)
	})
	.unwrap();
	let address = config.onion_address().to_string();
	tokio::time::timeout(Duration::from_secs(120), async {
		while !matches!(
			onion_service_status(address.clone()),
			ServiceStatus::Running | ServiceStatus::Bootstrapped
		) {
			tokio::time::sleep(Duration::from_millis(500)).await;
		}
	})
	.await
	.expect("Tor listener did not become ready");
}

#[allow(clippy::await_holding_lock)]
async fn async_new_swap_server(
	data_dir: &str,
	rt_handle: &tokio::runtime::Handle,
	wallets: &mut GrinWalletManager,
	server_key: &SecretKey,
	node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
	next_server: Option<&IntegrationMixServer>,
) -> IntegrationSwapServer {
	let wallet = wallets.async_new_wallet(&node.lock().api_address()).await;

	let mut tor = TorMwixnetConfig::default();
	let mut tor_dir = PathBuf::from(data_dir);
	tor_dir.pop();
	tor.data_file_dir = tor_dir.display().to_string();

	let server_config = mwixnet::ServerConfig {
		key: server_key.clone(),
		interval_s: 15,
		addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		grin_node_url: node.lock().api_address().to_string(),
		grin_node_foreign_api_secret_path: None,
		wallet_owner_url: wallet.lock().owner_address().to_string(),
		wallet_owner_secret_path: None,
		collect_fees: true,
		data_dir: data_dir.to_string(),
		prev_server: None,
		next_server: next_server.map(|s| MwixnetServerIdentityKey::from_secret(&s.server_key)),
		tor,
	};

	// Open SwapStore
	let store = SwapStore::new(data_dir).unwrap();

	let (swap_server, rpc_server) = mwixnet::swap_listen(
		rt_handle,
		&server_config,
		match next_server {
			Some(s) => Some(Arc::new(MixClientImpl::new(
				server_config.clone(),
				MwixnetServerIdentityKey::from_secret(&s.server_key),
			))),
			None => None,
		},
		Some(wallet.lock().get_client()),
		node.lock().to_client(),
		store,
	)
	.unwrap();

	start_tor_listener(&server_config, rpc_server.address()).await;

	IntegrationSwapServer {
		onion_pubkey: server_config.onion_pubkey(),
		client: MwixnetClientImpl::new(server_config.tor.clone(), server_config.onion_address()),
		swap_server,
		_rpc_server: rpc_server,
		_wallet: wallet,
	}
}

#[allow(clippy::await_holding_lock)]
#[allow(clippy::too_many_arguments)]
async fn async_new_mix_server(
	data_dir: &str,
	rt_handle: &tokio::runtime::Handle,
	wallets: &mut GrinWalletManager,
	server_key: &SecretKey,
	node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
	prev_server: MwixnetServerIdentityKey,
	next_server: Option<&IntegrationMixServer>,
) -> IntegrationMixServer {
	let wallet = wallets.async_new_wallet(&node.lock().api_address()).await;

	let mut tor = TorMwixnetConfig::default();
	let mut tor_dir = PathBuf::from(data_dir);
	tor_dir.pop();
	tor_dir.pop();
	tor.data_file_dir = tor_dir.display().to_string();

	let server_config = mwixnet::ServerConfig {
		key: server_key.clone(),
		interval_s: 15,
		addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		grin_node_url: node.lock().api_address().to_string(),
		grin_node_foreign_api_secret_path: None,
		wallet_owner_url: wallet.lock().owner_address().to_string(),
		wallet_owner_secret_path: None,
		collect_fees: true,
		data_dir: data_dir.to_string(),
		prev_server: Some(prev_server),
		next_server: next_server.map(|s| MwixnetServerIdentityKey::from_secret(&s.server_key)),
		tor,
	};

	let (_, rpc_server) = mwixnet::mix_listen(
		rt_handle,
		server_config.clone(),
		match next_server {
			Some(s) => Some(Arc::new(MixClientImpl::new(
				server_config.clone(),
				MwixnetServerIdentityKey::from_secret(&s.server_key),
			))),
			None => None,
		},
		Some(wallet.lock().get_client()),
		node.lock().to_client(),
	)
	.unwrap();

	start_tor_listener(&server_config, rpc_server.address()).await;

	IntegrationMixServer {
		server_key: server_key.clone(),
		onion_pubkey: server_config.onion_pubkey(),
		_rpc_server: rpc_server,
		_wallet: wallet,
	}
}

pub struct Servers {
	pub swapper: IntegrationSwapServer,

	pub mixers: Vec<IntegrationMixServer>,
}

impl Servers {
	pub async fn async_setup(
		test_dir: &str,
		rt_handle: &tokio::runtime::Handle,
		wallets: &mut GrinWalletManager,
		node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
		num_mixers: usize,
	) -> Servers {
		// Pre-generate all server keys
		let server_keys: Vec<SecretKey> =
			iter::repeat_with(|| grin_onion::crypto::secp::random_secret(false))
				.take(num_mixers + 1)
				.collect();

		// Build mixers in reverse order
		let mut mixers = Vec::new();
		for i in (0..num_mixers).rev() {
			let mix_server = async_new_mix_server(
				format!("{}/mixers/{}", test_dir, i).as_str(),
				rt_handle,
				wallets,
				&server_keys[i + 1],
				node,
				MwixnetServerIdentityKey::from_secret(&server_keys[i]),
				mixers.last(),
			)
			.await;
			println!(
				"Mixer {}: identity_key={}, prev_server={}, next_server={}",
				i,
				MwixnetServerIdentityKey::from_secret(&server_keys[i + 1]).to_hex(),
				MwixnetServerIdentityKey::from_secret(&server_keys[i]).to_hex(),
				match mixers.last() {
					Some(s) => MwixnetServerIdentityKey::from_secret(&s.server_key).to_hex(),
					None => "NONE".to_string(),
				},
			);
			mixers.push(mix_server);
		}
		mixers.reverse();

		let swapper = async_new_swap_server(
			format!("{}/swapper", test_dir).as_str(),
			rt_handle,
			wallets,
			&server_keys[0],
			node,
			mixers.first(),
		)
		.await;
		println!(
			"Swapper: identity_key={}",
			MwixnetServerIdentityKey::from_secret(&server_keys[0]).to_hex()
		);

		Servers { swapper, mixers }
	}

	pub fn get_server_keys(&self) -> Vec<MwixnetServerPublicKey> {
		let mut server_keys = vec![self.swapper.onion_pubkey];
		for mixer in &self.mixers {
			server_keys.push(mixer.onion_pubkey);
		}
		server_keys
	}

	pub fn stop_all(&mut self) {
		let swapper_address: OnionV3Address = self.swapper.client.server_url().clone();
		stop_onion_service(swapper_address.to_string()).expect("stop swap Tor service");

		self.mixers.iter_mut().for_each(|mixer| {
			let mixer_address: OnionV3Address =
				OnionV3Address::from_private(&mixer.server_key.0).unwrap();
			stop_onion_service(mixer_address.to_string()).expect("stop mixer Tor service");
		});
	}
}
