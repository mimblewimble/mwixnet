use crate::client::MixClient;
use crate::config::ServerConfig;
use crate::node::GrinNode;
use crate::servers::mix::{MixError, MixServer, MixServerImpl};
use crate::wallet::Wallet;

use crate::tx::TxComponents;
use futures::FutureExt;
use grin_onion::crypto::dalek::{self, DalekSignature};
use grin_onion::onion::Onion;
use jsonrpc_core::BoxFuture;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core::{self as jsonrpc, IoHandler};
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct MixReq {
	onions: Vec<Onion>,
	#[serde(with = "dalek::dalek_sig_serde")]
	sig: DalekSignature,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MixResp {
	pub indices: Vec<usize>,
	pub components: TxComponents,
}

impl MixReq {
	pub fn new(onions: Vec<Onion>, sig: DalekSignature) -> Self {
		MixReq { onions, sig }
	}
}

#[rpc(server)]
pub trait MixAPI {
	#[rpc(name = "mix")]
	fn mix(&self, mix: MixReq) -> BoxFuture<jsonrpc::Result<MixResp>>;
}

#[derive(Clone)]
struct RPCMixServer {
	server_config: ServerConfig,
	server: Arc<tokio::sync::Mutex<dyn MixServer>>,
}

impl RPCMixServer {
	/// Spin up an instance of the JSON-RPC HTTP server.
	fn start_http(&self, runtime_handle: tokio::runtime::Handle) -> jsonrpc_http_server::Server {
		let mut io = IoHandler::new();
		io.extend_with(RPCMixServer::to_delegate(self.clone()));

		ServerBuilder::new(io)
			.event_loop_executor(runtime_handle)
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
	fn mix(&self, mix: MixReq) -> BoxFuture<jsonrpc::Result<MixResp>> {
		let server = self.server.clone();
		async move {
			let response = server
				.lock()
				.await
				.mix_outputs(&mix.onions, &mix.sig)
				.await?;
			Ok(response)
		}
		.boxed()
	}
}

/// Spin up the JSON-RPC web server
pub fn listen(
	rt_handle: &tokio::runtime::Handle,
	server_config: ServerConfig,
	next_server: Option<Arc<dyn MixClient>>,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
) -> Result<
	(
		Arc<tokio::sync::Mutex<dyn MixServer>>,
		jsonrpc_http_server::Server,
	),
	Box<dyn std::error::Error>,
> {
	let server = MixServerImpl::new(
		server_config.clone(),
		next_server,
		wallet.clone(),
		node.clone(),
	);
	let server = Arc::new(tokio::sync::Mutex::new(server));

	let rpc_server = RPCMixServer {
		server_config: server_config.clone(),
		server: server.clone(),
	};

	let http_server = rpc_server.start_http(rt_handle.clone());

	Ok((server, http_server))
}
