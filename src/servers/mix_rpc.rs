use std::sync::Arc;
use std::time::Instant;

use futures::FutureExt;
use jsonrpc_core::{self, BoxFuture, IoHandler, Value};
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};

use grin_onion::crypto::dalek::{self, DalekSignature};
use grin_onion::onion::Onion;
use grin_wallet_libwallet::mwixnet::onion as grin_onion;

use crate::config::{PublicRoute, ServerConfig, ServerInfo};
use crate::mix_client::MixClient;
use crate::node::GrinNode;
use crate::servers::mix::{MixError, MixServer, MixServerImpl};
use crate::servers::rpc::RpcServer;
use crate::tx::TxComponents;
use crate::wallet::Wallet;

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
	#[rpc(name = "get_server_info")]
	fn get_server_info(&self) -> jsonrpc_core::Result<ServerInfo>;

	#[rpc(name = "get_route")]
	fn get_route(&self) -> jsonrpc_core::Result<PublicRoute>;

	#[rpc(name = "health")]
	fn health(&self) -> jsonrpc_core::Result<Value>;

	#[rpc(name = "mix")]
	fn mix(&self, mix: MixReq) -> BoxFuture<jsonrpc_core::Result<MixResp>>;
}

#[derive(Clone)]
struct RPCMixServer {
	started_at: Instant,
	server_config: ServerConfig,
	server: Arc<tokio::sync::Mutex<dyn MixServer>>,
}

impl RPCMixServer {
	/// Spin up an instance of the JSON-RPC HTTP server.
	fn start_http(&self, runtime: tokio::runtime::Handle) -> Result<RpcServer, grin_api::Error> {
		let mut io = IoHandler::new();
		io.extend_with(RPCMixServer::to_delegate(self.clone()));

		RpcServer::start(self.server_config.addr, io, runtime)
	}
}

impl From<MixError> for jsonrpc_core::Error {
	fn from(e: MixError) -> Self {
		jsonrpc_core::Error::invalid_params(e.to_string())
	}
}

impl MixAPI for RPCMixServer {
	fn get_server_info(&self) -> jsonrpc_core::Result<ServerInfo> {
		Ok(self
			.server_config
			.server_info(self.started_at.elapsed().as_secs()))
	}

	fn get_route(&self) -> jsonrpc_core::Result<PublicRoute> {
		Ok(self.server_config.public_route())
	}

	fn health(&self) -> jsonrpc_core::Result<Value> {
		Ok(Value::String("ok".into()))
	}

	fn mix(&self, mix: MixReq) -> BoxFuture<jsonrpc_core::Result<MixResp>> {
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
	wallet: Option<Arc<dyn Wallet>>,
	node: Arc<dyn GrinNode>,
) -> Result<(Arc<tokio::sync::Mutex<dyn MixServer>>, RpcServer), Box<dyn std::error::Error>> {
	let server = MixServerImpl::new(server_config.clone(), next_server, wallet, node.clone());
	let server = Arc::new(tokio::sync::Mutex::new(server));

	let rpc_server = RPCMixServer {
		started_at: std::time::Instant::now(),
		server_config: server_config.clone(),
		server: server.clone(),
	};

	let http_server = rpc_server.start_http(rt_handle.clone())?;

	Ok((server, http_server))
}
