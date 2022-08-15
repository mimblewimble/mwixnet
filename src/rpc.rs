use crate::config::ServerConfig;
use crate::node::GrinNode;
use crate::onion::Onion;
use crate::secp::{self, ComSignature};
use crate::server::{Server, ServerImpl, SwapError};
use crate::wallet::Wallet;

use grin_util::StopState;
use jsonrpc_core::{Result, Value};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, spawn};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
pub struct SwapReq {
	onion: Onion,
	#[serde(with = "secp::comsig_serde")]
	comsig: ComSignature,
}

#[rpc(server)]
pub trait API {
	#[rpc(name = "swap")]
	fn swap(&self, swap: SwapReq) -> Result<Value>;

	// milestone 3: Used by mwixnet coinswap servers to communicate with each other
	// fn derive_outputs(&self, entries: Vec<Onion>) -> Result<Value>;
	// fn derive_kernel(&self, tx: Tx) -> Result<Value>;
}

#[derive(Clone)]
struct RPCServer {
	server_config: ServerConfig,
	server: Arc<Mutex<dyn Server>>,
}

impl RPCServer {
	/// Spin up an instance of the JSON-RPC HTTP server.
	fn start_http(&self) -> jsonrpc_http_server::Server {
		let mut io = IoHandler::new();
		io.extend_with(RPCServer::to_delegate(self.clone()));

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

impl API for RPCServer {
	/// Implements the 'swap' API
	fn swap(&self, swap: SwapReq) -> Result<Value> {
		self.server
			.lock()
			.unwrap()
			.swap(&swap.onion, &swap.comsig)?;
		Ok(Value::String("success".into()))
	}
}

/// Spin up the JSON-RPC web server
pub fn listen(
	server_config: ServerConfig,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
	stop_state: Arc<StopState>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
	let server = ServerImpl::new(server_config.clone(), wallet.clone(), node.clone());
	let server = Arc::new(Mutex::new(server));

	let rpc_server = RPCServer {
		server_config: server_config.clone(),
		server: server.clone(),
	};

	let http_server = rpc_server.start_http();
	println!("Server listening on {}", server_config.addr);

	let close_handle = http_server.close_handle();
	let round_handle = spawn(move || {
		let mut secs = 0;
		loop {
			if stop_state.is_stopped() {
				close_handle.close();
				break;
			}

			sleep(Duration::from_secs(1));
			secs = (secs + 1) % server_config.interval_s;

			if secs == 0 {
				let _ = server.lock().unwrap().execute_round();
			}
		}
	});

	http_server.wait();
	round_handle.join().unwrap();

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::config::ServerConfig;
	use crate::onion::test_util;
	use crate::rpc::{RPCServer, SwapReq};
	use crate::secp::{self, ComSignature};
	use crate::server::mock::MockServer;
	use crate::server::{Server, SwapError};

	use std::net::TcpListener;
	use std::sync::{Arc, Mutex};

	use hyper::{Body, Client, Request, Response};
	use tokio::runtime::Runtime;

	async fn body_to_string(req: Response<Body>) -> String {
		let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
		String::from_utf8(body_bytes.to_vec()).unwrap()
	}

	/// Spin up a temporary web service, query the API, then cleanup and return response
	fn make_request(
		server: Arc<Mutex<dyn Server>>,
		req: String,
	) -> Result<String, Box<dyn std::error::Error>> {
		let server_config = ServerConfig {
			key: secp::random_secret(),
			interval_s: 1,
			addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			grin_node_url: "127.0.0.1:3413".parse()?,
			grin_node_secret_path: None,
			wallet_owner_url: "127.0.0.1:3420".parse()?,
			wallet_owner_secret_path: None,
		};

		let rpc_server = RPCServer {
			server_config: server_config.clone(),
			server: server.clone(),
		};

		// Start the JSON-RPC server
		let http_server = rpc_server.start_http();

		let uri = format!("http://{}/v1", server_config.addr);

		let threaded_rt = Runtime::new()?;
		let do_request = async move {
			let request = Request::post(uri)
				.header("Content-Type", "application/json")
				.body(Body::from(req))
				.unwrap();

			Client::new().request(request).await
		};

		let response = threaded_rt.block_on(do_request)?;
		let response_str: String = threaded_rt.block_on(body_to_string(response));

		// Wait for shutdown
		threaded_rt.shutdown_background();

		// Execute one round
		server.lock().unwrap().execute_round()?;

		// Stop the server
		http_server.close();

		Ok(response_str)
	}

	// todo: Test all error types

	/// Demonstrates a successful swap response
	#[test]
	fn swap_success() -> Result<(), Box<dyn std::error::Error>> {
		let commitment = secp::commit(1234, &secp::random_secret())?;
		let onion = test_util::create_onion(&commitment, &vec![])?;
		let comsig = ComSignature::sign(1234, &secp::random_secret(), &onion.serialize()?)?;
		let swap = SwapReq {
			onion: onion.clone(),
			comsig,
		};

		let server: Arc<Mutex<dyn Server>> = Arc::new(Mutex::new(MockServer::new()));

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		println!("Request: {}", req);
		let response = make_request(server, req)?;
		let expected = "{\"jsonrpc\":\"2.0\",\"result\":\"success\",\"id\":\"1\"}\n";
		assert_eq!(response, expected);

		Ok(())
	}

	#[test]
	fn swap_bad_request() -> Result<(), Box<dyn std::error::Error>> {
		let server: Arc<Mutex<dyn Server>> = Arc::new(Mutex::new(MockServer::new()));

		let params = "{ \"param\": \"Not a valid Swap request\" }";
		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			params
		);
		let response = make_request(server, req)?;
		let expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `onion`.\"},\"id\":\"1\"}\n";
		assert_eq!(response, expected);
		Ok(())
	}

	/// Returns "Commitment not found" when there's no matching output in the UTXO set.
	#[test]
	fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error>> {
		let commitment = secp::commit(1234, &secp::random_secret())?;
		let onion = test_util::create_onion(&commitment, &vec![])?;
		let comsig = ComSignature::sign(1234, &secp::random_secret(), &onion.serialize()?)?;
		let swap = SwapReq {
			onion: onion.clone(),
			comsig,
		};

		let mut server = MockServer::new();
		server.set_response(
			&onion,
			SwapError::CoinNotFound {
				commit: commitment.clone(),
			},
		);
		let server: Arc<Mutex<dyn Server>> = Arc::new(Mutex::new(server));

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		let response = make_request(server, req)?;
		let expected = format!(
			"{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32602,\"message\":\"Output {:?} does not exist, or is already spent.\"}},\"id\":\"1\"}}\n",
			commitment
		);
		assert_eq!(response, expected);
		Ok(())
	}
}
