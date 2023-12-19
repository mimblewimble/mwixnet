use crate::common::node::IntegrationGrinNode;
use crate::common::wallet::{GrinWalletManager, IntegrationGrinWallet};
use grin_core::core::Transaction;
use grin_onion::crypto::comsig::ComSignature;
use grin_onion::crypto::dalek::DalekPublicKey;
use grin_onion::onion::Onion;
use grin_wallet_impls::tor::process::TorProcess;
use mwixnet::client::MixClientImpl;
use mwixnet::{tor, SwapError, SwapServer, SwapStore};
use secp256k1zkp::SecretKey;
use std::iter;
use std::net::TcpListener;
use std::sync::Arc;
use x25519_dalek::{PublicKey as xPublicKey, StaticSecret};

pub struct IntegrationSwapServer {
	server_key: SecretKey,
	tor_process: TorProcess,
	swap_server: Arc<tokio::sync::Mutex<dyn SwapServer>>,
	rpc_server: jsonrpc_http_server::Server,
	_wallet: Arc<grin_util::Mutex<IntegrationGrinWallet>>,
}

impl IntegrationSwapServer {
	pub async fn async_swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError> {
		self.swap_server.lock().await.swap(&onion, &comsig).await
	}

	pub async fn async_execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError> {
		self.swap_server.lock().await.execute_round().await
	}
}

pub struct IntegrationMixServer {
	server_key: SecretKey,
	tor_process: TorProcess,
	rpc_server: jsonrpc_http_server::Server,
	_wallet: Arc<grin_util::Mutex<IntegrationGrinWallet>>,
}

async fn async_new_swap_server(
	data_dir: &str,
	rt_handle: &tokio::runtime::Handle,
	wallets: &mut GrinWalletManager,
	server_key: &SecretKey,
	node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
	next_server: Option<&IntegrationMixServer>,
) -> IntegrationSwapServer {
	let wallet = wallets.async_new_wallet(&node.lock().api_address()).await;

	let server_config = mwixnet::ServerConfig {
		key: server_key.clone(),
		interval_s: 15,
		addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		socks_proxy_addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		grin_node_url: node.lock().api_address(),
		grin_node_secret_path: None,
		wallet_owner_url: wallet.lock().owner_address(),
		wallet_owner_secret_path: None,
		prev_server: None,
		next_server: match next_server {
			Some(s) => Some(DalekPublicKey::from_secret(&s.server_key)),
			None => None,
		},
	};

	// Open SwapStore
	let store = SwapStore::new(format!("{}/db", data_dir).as_str()).unwrap();
	let tor_process = tor::init_tor_listener(&data_dir, &server_config).unwrap();

	let (swap_server, rpc_server) = mwixnet::swap_listen(
		rt_handle,
		&server_config,
		match next_server {
			Some(s) => Some(Arc::new(MixClientImpl::new(
				server_config.clone(),
				DalekPublicKey::from_secret(&s.server_key),
			))),
			None => None,
		},
		wallet.lock().get_client(),
		node.lock().to_client(),
		store,
	)
	.unwrap();

	IntegrationSwapServer {
		server_key: server_key.clone(),
		tor_process,
		swap_server,
		rpc_server,
		_wallet: wallet,
	}
}

async fn async_new_mix_server(
	data_dir: &str,
	rt_handle: &tokio::runtime::Handle,
	wallets: &mut GrinWalletManager,
	server_key: &SecretKey,
	node: &Arc<grin_util::Mutex<IntegrationGrinNode>>,
	prev_server: DalekPublicKey,
	next_server: Option<&IntegrationMixServer>,
) -> IntegrationMixServer {
	let wallet = wallets.async_new_wallet(&node.lock().api_address()).await;
	let server_config = mwixnet::ServerConfig {
		key: server_key.clone(),
		interval_s: 15,
		addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		socks_proxy_addr: TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap(),
		grin_node_url: node.lock().api_address(),
		grin_node_secret_path: None,
		wallet_owner_url: wallet.lock().owner_address(),
		wallet_owner_secret_path: None,
		prev_server: Some(prev_server),
		next_server: match next_server {
			Some(s) => Some(DalekPublicKey::from_secret(&s.server_key)),
			None => None,
		},
	};

	let tor_process = tor::init_tor_listener(&data_dir, &server_config).unwrap();

	let (_, rpc_server) = mwixnet::mix_listen(
		rt_handle,
		server_config.clone(),
		match next_server {
			Some(s) => Some(Arc::new(MixClientImpl::new(
				server_config.clone(),
				DalekPublicKey::from_secret(&s.server_key),
			))),
			None => None,
		},
		wallet.lock().get_client(),
		node.lock().to_client(),
	)
	.unwrap();

	IntegrationMixServer {
		server_key: server_key.clone(),
		tor_process,
		rpc_server,
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
			iter::repeat_with(|| grin_onion::crypto::secp::random_secret())
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
				&node,
				DalekPublicKey::from_secret(&server_keys[i]),
				mixers.last(),
			)
			.await;
			println!(
				"Mixer {}: server_key={}, prev_server={}, next_server={}",
				i,
				DalekPublicKey::from_secret(&server_keys[i + 1]).to_hex(),
				DalekPublicKey::from_secret(&server_keys[i]).to_hex(),
				match mixers.last() {
					Some(s) => DalekPublicKey::from_secret(&s.server_key).to_hex(),
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
			&node,
			mixers.first(),
		)
		.await;
		println!(
			"Swapper: server_key={}",
			DalekPublicKey::from_secret(&server_keys[0]).to_hex()
		);

		Servers { swapper, mixers }
	}

	pub fn get_pub_keys(&self) -> Vec<xPublicKey> {
		let mut pub_keys = vec![xPublicKey::from(&StaticSecret::from(
			self.swapper.server_key.0.clone(),
		))];
		for mixer in &self.mixers {
			pub_keys.push(xPublicKey::from(&StaticSecret::from(
				mixer.server_key.0.clone(),
			)))
		}
		pub_keys
	}

	pub fn stop_all(&mut self) {
		self.swapper.rpc_server.close_handle().close();
		self.swapper.tor_process.kill().unwrap();

		self.mixers.iter_mut().for_each(|mixer| {
			mixer.rpc_server.close_handle().close();
			mixer.tor_process.kill().unwrap();
		});
	}
}
