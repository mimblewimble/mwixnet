use crate::config::ServerConfig;
use crate::crypto::dalek::{self, DalekSignature};
use crate::node::GrinNode;
use crate::onion::Onion;
use crate::servers::mix::{MixError, MixServer, MixServerImpl};
use crate::wallet::Wallet;

use crate::client::MixClient;
use grin_util::StopState;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core::{self as jsonrpc, IoHandler};
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
pub struct MixReq {
	onions: Vec<Onion>,
	#[serde(with = "dalek::dalek_sig_serde")]
	sig: DalekSignature,
}

impl MixReq {
	pub fn new(onions: Vec<Onion>, sig: DalekSignature) -> Self {
		MixReq { onions, sig }
	}
}

#[rpc(server)]
pub trait MixAPI {
	#[rpc(name = "mix")]
	fn mix(&self, mix: MixReq) -> jsonrpc::Result<jsonrpc::Value>;
}

#[derive(Clone)]
struct RPCMixServer {
	server_config: ServerConfig,
	server: Arc<Mutex<dyn MixServer>>,
}

impl RPCMixServer {
	/// Spin up an instance of the JSON-RPC HTTP server.
	fn start_http(&self) -> jsonrpc_http_server::Server {
		let mut io = IoHandler::new();
		io.extend_with(RPCMixServer::to_delegate(self.clone()));

		ServerBuilder::new(io)
			.cors(DomainsValidation::Disabled)
			.request_middleware(|request: hyper::Request<hyper::Body>| {
				if request.uri() == "/v1" {
					request.into()
				} else {
					jsonrpc_http_server::Response::bad_request("Only v1 supported").into()
				}
			})
			.start_http(&self.server_config.addr)
			.expect("Unable to start RPC server")
	}
}

impl From<MixError> for jsonrpc::Error {
	fn from(e: MixError) -> Self {
		jsonrpc::Error::invalid_params(e.to_string())
	}
}

impl MixAPI for RPCMixServer {
	fn mix(&self, mix: MixReq) -> jsonrpc::Result<jsonrpc::Value> {
		self.server
			.lock()
			.unwrap()
			.mix_outputs(&mix.onions, &mix.sig)?;
		Ok(jsonrpc::Value::String("success".into()))
	}
}

/// Spin up the JSON-RPC web server
pub fn listen(
	server_config: ServerConfig,
	next_server: Option<Arc<dyn MixClient>>,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
	stop_state: Arc<StopState>,
) -> Result<(), Box<dyn std::error::Error>> {
	let server = MixServerImpl::new(
		server_config.clone(),
		next_server,
		wallet.clone(),
		node.clone(),
	);
	let server = Arc::new(Mutex::new(server));

	let rpc_server = RPCMixServer {
		server_config: server_config.clone(),
		server: server.clone(),
	};

	let http_server = rpc_server.start_http();

	let close_handle = http_server.close_handle();
	let round_handle = spawn(move || loop {
		if stop_state.is_stopped() {
			close_handle.close();
			break;
		}

		sleep(Duration::from_millis(100));
	});

	http_server.wait();
	round_handle.join().unwrap();

	Ok(())
}
