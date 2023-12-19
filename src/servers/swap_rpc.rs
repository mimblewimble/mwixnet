use crate::client::MixClient;
use crate::config::ServerConfig;
use crate::node::GrinNode;
use crate::servers::swap::{SwapError, SwapServer, SwapServerImpl};
use crate::store::SwapStore;
use crate::wallet::Wallet;

use futures::FutureExt;
use grin_onion::crypto::comsig::{self, ComSignature};
use grin_onion::onion::Onion;
use jsonrpc_core::Value;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct SwapReq {
	onion: Onion,
	#[serde(with = "comsig::comsig_serde")]
	comsig: ComSignature,
}

#[rpc(server)]
pub trait SwapAPI {
	#[rpc(name = "swap")]
	fn swap(&self, swap: SwapReq) -> BoxFuture<jsonrpc_core::Result<Value>>;
}

#[derive(Clone)]
struct RPCSwapServer {
	server_config: ServerConfig,
	server: Arc<tokio::sync::Mutex<dyn SwapServer>>,
}

impl RPCSwapServer {
	/// Spin up an instance of the JSON-RPC HTTP server.
	fn start_http(&self, runtime_handle: tokio::runtime::Handle) -> jsonrpc_http_server::Server {
		let mut io = IoHandler::new();
		io.extend_with(RPCSwapServer::to_delegate(self.clone()));

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

impl From<SwapError> for Error {
	fn from(e: SwapError) -> Self {
		match e {
			SwapError::UnknownError(_) => Error {
				message: e.to_string(),
				code: ErrorCode::InternalError,
				data: None,
			},
			_ => Error::invalid_params(e.to_string()),
		}
	}
}

impl SwapAPI for RPCSwapServer {
	fn swap(&self, swap: SwapReq) -> BoxFuture<jsonrpc_core::Result<Value>> {
		let server = self.server.clone();
		async move {
			server.lock().await.swap(&swap.onion, &swap.comsig).await?;
			Ok(Value::String("success".into()))
		}
		.boxed()
	}
}

/// Spin up the JSON-RPC web server
pub fn listen(
	rt_handle: &tokio::runtime::Handle,
	server_config: &ServerConfig,
	next_server: Option<Arc<dyn MixClient>>,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
	store: SwapStore,
) -> std::result::Result<
	(
		Arc<tokio::sync::Mutex<dyn SwapServer>>,
		jsonrpc_http_server::Server,
	),
	Box<dyn std::error::Error>,
> {
	let server = SwapServerImpl::new(
		server_config.clone(),
		next_server,
		wallet.clone(),
		node.clone(),
		store,
	);
	let server = Arc::new(tokio::sync::Mutex::new(server));

	let rpc_server = RPCSwapServer {
		server_config: server_config.clone(),
		server: server.clone(),
	};

	let http_server = rpc_server.start_http(rt_handle.clone());

	Ok((server, http_server))
}

#[cfg(test)]
mod tests {
	use crate::config::ServerConfig;
	use crate::servers::swap::mock::MockSwapServer;
	use crate::servers::swap::{SwapError, SwapServer};
	use crate::servers::swap_rpc::{RPCSwapServer, SwapReq};

	use grin_onion::create_onion;
	use grin_onion::crypto::comsig::ComSignature;
	use grin_onion::crypto::secp;
	use std::net::TcpListener;
	use std::sync::Arc;

	use hyper::{Body, Client, Request, Response};
	use tokio::sync::Mutex;

	async fn body_to_string(req: Response<Body>) -> String {
		let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
		String::from_utf8(body_bytes.to_vec()).unwrap()
	}

	/// Spin up a temporary web service, query the API, then cleanup and return response
	async fn async_make_request(
		server: Arc<tokio::sync::Mutex<dyn SwapServer>>,
		req: String,
		runtime_handle: &tokio::runtime::Handle,
	) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
		let server_config = ServerConfig {
			key: secp::random_secret(),
			interval_s: 1,
			addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			socks_proxy_addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			grin_node_url: "127.0.0.1:3413".parse()?,
			grin_node_secret_path: None,
			wallet_owner_url: "127.0.0.1:3420".parse()?,
			wallet_owner_secret_path: None,
			prev_server: None,
			next_server: None,
		};

		let rpc_server = RPCSwapServer {
			server_config: server_config.clone(),
			server: server.clone(),
		};

		// Start the JSON-RPC server
		let http_server = rpc_server.start_http(runtime_handle.clone());

		let uri = format!("http://{}/v1", server_config.addr);

		let request = Request::post(uri)
			.header("Content-Type", "application/json")
			.body(Body::from(req))
			.unwrap();

		let response = Client::new().request(request).await?;

		let response_str: String = body_to_string(response).await;

		// Execute one round
		server.lock().await.execute_round().await?;

		// Stop the server
		http_server.close();

		Ok(response_str)
	}

	// todo: Test all error types

	/// Demonstrates a successful swap response
	#[test]
	fn swap_success() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let mut rt = tokio::runtime::Builder::new()
			.threaded_scheduler()
			.enable_all()
			.build()?;
		let commitment = secp::commit(1234, &secp::random_secret())?;
		let onion = create_onion(&commitment, &vec![])?;
		let comsig = ComSignature::sign(1234, &secp::random_secret(), &onion.serialize()?)?;
		let swap = SwapReq {
			onion: onion.clone(),
			comsig,
		};

		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, req, &rt_handle))?;
		let expected = "{\"jsonrpc\":\"2.0\",\"result\":\"success\",\"id\":\"1\"}\n";
		assert_eq!(response, expected);

		Ok(())
	}

	#[test]
	fn swap_bad_request() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let mut rt = tokio::runtime::Builder::new()
			.threaded_scheduler()
			.enable_all()
			.build()?;
		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(MockSwapServer::new()));

		let params = "{ \"param\": \"Not a valid Swap request\" }";
		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			params
		);
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, req, &rt_handle))?;
		let expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `onion`.\"},\"id\":\"1\"}\n";
		assert_eq!(response, expected);
		Ok(())
	}

	/// Returns "Commitment not found" when there's no matching output in the UTXO set.
	#[test]
	fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let mut rt = tokio::runtime::Builder::new()
			.threaded_scheduler()
			.enable_all()
			.build()?;

		let commitment = secp::commit(1234, &secp::random_secret())?;
		let onion = create_onion(&commitment, &vec![])?;
		let comsig = ComSignature::sign(1234, &secp::random_secret(), &onion.serialize()?)?;
		let swap = SwapReq {
			onion: onion.clone(),
			comsig,
		};

		let mut server = MockSwapServer::new();
		server.set_response(
			&onion,
			SwapError::CoinNotFound {
				commit: commitment.clone(),
			},
		);
		let server: Arc<Mutex<dyn SwapServer>> = Arc::new(Mutex::new(server));

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		let rt_handle = rt.handle().clone();
		let response = rt.block_on(async_make_request(server, req, &rt_handle))?;
		let expected = format!(
            "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32602,\"message\":\"Output {:?} does not exist, or is already spent.\"}},\"id\":\"1\"}}\n",
            commitment
        );
		assert_eq!(response, expected);
		Ok(())
	}
}
