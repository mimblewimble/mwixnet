extern crate grin_wallet_api as apiwallet;
extern crate grin_wallet_config as wallet_config;
extern crate grin_wallet_controller as wallet_controller;
extern crate grin_wallet_impls as wallet;
extern crate grin_wallet_libwallet as libwallet;

use futures::channel::oneshot;

use grin_core as core;

use grin_p2p as p2p;
use grin_servers as servers;

use grin_util::logger::LogEntry;
use grin_util::{Mutex, StopState};
use std::default::Default;
use std::net::SocketAddr;

use mwixnet::{GrinNode, HttpGrinNode};
use std::sync::{mpsc, Arc};
use std::thread;

#[allow(dead_code)]
pub struct IntegrationGrinNode {
	server_config: servers::ServerConfig,
	stop_state: Arc<StopState>,
	server: Option<Arc<servers::Server>>,
}

impl IntegrationGrinNode {
	pub fn start(&mut self) -> Arc<servers::Server> {
		let stop_state_thread = self.stop_state.clone();
		let server_config_thread = self.server_config.clone();

		// Create a channel to communicate between threads
		let (tx, rx) = mpsc::channel();

		// Start the node in a new thread
		thread::spawn(move || {
			let api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>) =
				Box::leak(Box::new(oneshot::channel::<()>()));

			servers::Server::start(
				server_config_thread.clone(),
				None,
				move |serv: servers::Server, _: Option<mpsc::Receiver<LogEntry>>| {
					// Signal that the callback has been called
					tx.send(serv).unwrap();
					// Do other necessary stuff here
				},
				Some(stop_state_thread.clone()),
				api_chan,
			)
			.unwrap();
		});

		// Wait for the signal from the node-running thread
		let server = Arc::new(rx.recv().unwrap());
		self.server = Some(server.clone());

		server
	}

	pub fn stop(&self) {
		self.stop_state.stop();
	}

	pub fn api_address(&self) -> SocketAddr {
		self.server_config.api_http_addr.parse().unwrap()
	}

	pub fn to_client(&self) -> Arc<dyn GrinNode> {
		Arc::new(HttpGrinNode::new(&self.api_address(), &None))
	}
}

#[allow(dead_code)]
pub struct GrinNodeManager {
	// base directory for the server instance
	working_dir: String,

	nodes: Vec<Arc<Mutex<IntegrationGrinNode>>>,
}

impl GrinNodeManager {
	pub fn new(test_dir: &str) -> GrinNodeManager {
		GrinNodeManager {
			working_dir: String::from(test_dir),
			nodes: vec![],
		}
	}

	pub fn new_node(&mut self) -> Arc<Mutex<IntegrationGrinNode>> {
		let server_config = servers::ServerConfig {
			api_http_addr: format!("127.0.0.1:{}", 20000 + self.nodes.len()),
			api_secret_path: None,
			db_root: format!("{}/nodes/{}", self.working_dir, self.nodes.len()),
			p2p_config: p2p::P2PConfig {
				port: 13414,
				seeding_type: p2p::Seeding::None,
				..p2p::P2PConfig::default()
			},
			chain_type: core::global::ChainTypes::AutomatedTesting,
			skip_sync_wait: Some(true),
			stratum_mining_config: None,
			..Default::default()
		};
		let node = Arc::new(Mutex::new(IntegrationGrinNode {
			server_config,
			stop_state: Arc::new(StopState::new()),
			server: None,
		}));
		self.nodes.push(node.clone());
		node
	}

	pub fn stop_all(&self) {
		for node in &self.nodes {
			node.lock().stop();
		}
	}
}
