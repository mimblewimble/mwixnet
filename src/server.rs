use crate::config::ServerConfig;
use crate::node::{self, GrinNode};
use crate::onion::Onion;
use crate::secp::{self, ComSignature, Commitment, RangeProof, Secp256k1, SecretKey};
use crate::wallet::{self, Wallet};

use grin_core::core::{Input, Output, OutputFeatures, TransactionBody};
use grin_core::global::DEFAULT_ACCEPT_FEE_BASE;
use grin_util::StopState;
use itertools::Itertools;
use jsonrpc_core::{Result, Value};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq)]
struct Submission {
	excess: SecretKey,
	output_commit: Commitment,
	rangeproof: Option<RangeProof>,
	input: Input,
	fee: u64,
	onion: Onion,
}

#[derive(Serialize, Deserialize)]
pub struct SwapReq {
	onion: Onion,
	#[serde(with = "secp::comsig_serde")]
	comsig: ComSignature,
}

lazy_static! {
	static ref SERVER_STATE: Mutex<HashMap<Commitment, Submission>> = Mutex::new(HashMap::new());
}

#[rpc(server)]
pub trait Server {
	#[rpc(name = "swap")]
	fn swap(&self, swap: SwapReq) -> Result<Value>;

	// milestone 3: Used by mwixnet coinswap servers to communicate with each other
	// fn derive_outputs(&self, entries: Vec<Onion>) -> Result<Value>;
	// fn derive_kernel(&self, tx: Tx) -> Result<Value>;
}

#[derive(Clone)]
struct ServerImpl {
	server_config: ServerConfig,
	stop_state: Arc<StopState>,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
}

impl ServerImpl {
	fn new(
		server_config: ServerConfig,
		stop_state: Arc<StopState>,
		wallet: Arc<dyn Wallet>,
		node: Arc<dyn GrinNode>,
	) -> Self {
		ServerImpl {
			server_config,
			stop_state,
			wallet,
			node,
		}
	}

	/// The fee base to use. For now, just using the default.
	fn get_fee_base(&self) -> u64 {
		DEFAULT_ACCEPT_FEE_BASE
	}

	/// Minimum fee to perform a swap.
	/// Requires enough fee for the mwixnet server's kernel, 1 input and its output to swap.
	fn get_minimum_swap_fee(&self) -> u64 {
		TransactionBody::weight_by_iok(1, 1, 1) * self.get_fee_base()
	}

	/// Iterate through all saved submissions, filter out any inputs that are no longer spendable,
	/// and assemble the coinswap transaction, posting the transaction to the configured node.
	///
	/// Currently only a single mix node is used. Milestone 3 will include support for multiple mix nodes.
	fn execute_round(&self) -> crate::error::Result<()> {
		let mut locked_state = SERVER_STATE.lock().unwrap();
		let next_block_height = self.node.get_chain_height()? + 1;

		let spendable: Vec<Submission> = locked_state
			.values()
			.into_iter()
			.unique_by(|s| s.output_commit)
			.filter(|s| {
				node::is_spendable(&self.node, &s.input.commit, next_block_height).unwrap_or(false)
			})
			.filter(|s| !node::is_unspent(&self.node, &s.output_commit).unwrap_or(true))
			.cloned()
			.collect();

		if spendable.len() == 0 {
			return Ok(());
		}

		let total_fee: u64 = spendable.iter().enumerate().map(|(_, s)| s.fee).sum();

		let inputs: Vec<Input> = spendable.iter().enumerate().map(|(_, s)| s.input).collect();

		let outputs: Vec<Output> = spendable
			.iter()
			.enumerate()
			.map(|(_, s)| {
				Output::new(
					OutputFeatures::Plain,
					s.output_commit,
					s.rangeproof.unwrap(),
				)
			})
			.collect();

		let excesses: Vec<SecretKey> = spendable
			.iter()
			.enumerate()
			.map(|(_, s)| s.excess.clone())
			.collect();

		let tx = wallet::assemble_tx(
			&self.wallet,
			&inputs,
			&outputs,
			self.get_fee_base(),
			total_fee,
			&excesses,
		)?;

		self.node.post_tx(&tx)?;
		locked_state.clear();

		Ok(())
	}
}

impl Server for ServerImpl {
	/// Implements the 'swap' API
	fn swap(&self, swap: SwapReq) -> Result<Value> {
		// milestone 3: check that enc_payloads length matches number of configured servers
		if swap.onion.enc_payloads.len() != 1 {
			return Err(Error::invalid_params(
				"Multi server not supported until milestone 3",
			));
		}

		// Verify commitment signature to ensure caller owns the output
		let serialized_onion = swap.onion.serialize().map_err(|e| Error {
			message: e.to_string(),
			code: ErrorCode::InternalError,
			data: None,
		})?;
		let _ = swap
			.comsig
			.verify(&swap.onion.commit, &serialized_onion)
			.map_err(|_| Error::invalid_params("ComSignature invalid"))?;

		// Verify that commitment is unspent
		let input = node::build_input(&self.node, &swap.onion.commit).map_err(|e| Error {
			message: e.to_string(),
			code: ErrorCode::InternalError,
			data: None,
		})?;
		let input = input.ok_or(Error::invalid_params("Commitment not found"))?;

		let peeled = swap
			.onion
			.peel_layer(&self.server_config.key)
			.map_err(|e| Error::invalid_params(e.message()))?;

		// Verify the fee meets the minimum
		let fee: u64 = peeled.0.fee.into();
		if fee < self.get_minimum_swap_fee() {
			return Err(Error::invalid_params("Fee does not meet minimum"));
		}

		// Calculate final output commitment
		let output_commit =
			secp::add_excess(&swap.onion.commit, &peeled.0.excess).map_err(|e| Error {
				message: e.to_string(),
				code: ErrorCode::InternalError,
				data: None,
			})?;
		let output_commit = secp::sub_value(&output_commit, fee).map_err(|e| Error {
			message: e.to_string(),
			code: ErrorCode::InternalError,
			data: None,
		})?;

		// Verify the bullet proof and build the final output
		if let Some(r) = peeled.0.rangeproof {
			let secp = Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
			secp.verify_bullet_proof(output_commit, r, None)
				.map_err(|_| Error::invalid_params("RangeProof invalid"))?;
		} else {
			// milestone 3: only the last hop will have a rangeproof
			return Err(Error::invalid_params("Rangeproof expected"));
		}

		let mut locked = SERVER_STATE.lock().unwrap();
		if locked.contains_key(&swap.onion.commit) {
			return Err(Error::invalid_params("swap already called for coin"));
		}

		locked.insert(
			swap.onion.commit,
			Submission {
				excess: peeled.0.excess,
				output_commit,
				rangeproof: peeled.0.rangeproof,
				input,
				fee,
				onion: peeled.1,
			},
		);
		Ok(Value::String("success".into()))
	}
}

/// Spin up the JSON-RPC web server
pub fn listen(
	server_config: &ServerConfig,
	wallet: Arc<dyn Wallet>,
	node: Arc<dyn GrinNode>,
	stop_state: &Arc<StopState>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
	let server_impl = Arc::new(ServerImpl::new(
		server_config.clone(),
		stop_state.clone(),
		wallet.clone(),
		node.clone(),
	));

	let mut io = IoHandler::new();
	io.extend_with(ServerImpl::to_delegate(server_impl.as_ref().clone()));

	let server = ServerBuilder::new(io)
		.cors(DomainsValidation::Disabled)
		.request_middleware(|request: hyper::Request<hyper::Body>| {
			if request.uri() == "/v1" {
				request.into()
			} else {
				jsonrpc_http_server::Response::bad_request("Only v1 supported").into()
			}
		})
		.start_http(&server_config.addr)
		.expect("Unable to start RPC server");
	println!("Server listening on {}", server_config.addr);

	let close_handle = server.close_handle();

	let config = server_config.clone();
	let round_handle = std::thread::spawn(move || {
		let mut secs = 0;
		loop {
			if server_impl.as_ref().stop_state.is_stopped() {
				close_handle.close();
				break;
			}

			std::thread::sleep(std::time::Duration::from_secs(1));
			secs = (secs + 1) % config.interval_s;

			if secs == 0 {
				let _ = server_impl.as_ref().execute_round();
				secs = 0;
			}
		}
	});

	server.wait();
	round_handle.join().unwrap();

	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::config::ServerConfig;
	use crate::node::{GrinNode, MockGrinNode};
	use crate::onion::test_util::{self, Hop};
	use crate::secp::{self, ComSignature, PublicKey, Secp256k1};
	use crate::server::{self, SwapReq};
	use crate::types::Payload;
	use crate::wallet::{MockWallet, Wallet};

	use grin_core::core::{Committed, FeeFields, Transaction};
	use grin_util::StopState;
	use std::net::TcpListener;
	use std::sync::Arc;
	use std::thread;
	use std::time::Duration;

	use hyper::{Body, Client, Request, Response};
	use tokio::runtime;

	async fn body_to_string(req: Response<Body>) -> String {
		let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
		String::from_utf8(body_bytes.to_vec()).unwrap()
	}

	/// Spin up a temporary web service, query the API, then cleanup and return response
	fn make_request(
		server_key: secp::SecretKey,
		wallet: Arc<dyn Wallet>,
		node: Arc<dyn GrinNode>,
		req: String,
	) -> Result<String, Box<dyn std::error::Error>> {
		let server_config = ServerConfig {
			key: server_key,
			interval_s: 1,
			addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			grin_node_url: "127.0.0.1:3413".parse()?,
			grin_node_secret_path: None,
			wallet_owner_url: "127.0.0.1:3420".parse()?,
			wallet_owner_secret_path: None,
		};

		let threaded_rt = runtime::Runtime::new()?;
		let (shutdown_sender, shutdown_receiver) = futures::channel::oneshot::channel();
		let uri = format!("http://{}/v1", server_config.addr);

		let stop_state = Arc::new(StopState::new());
		let stop_state_clone = stop_state.clone();

		// Spawn the server task
		threaded_rt.spawn(async move {
			server::listen(&server_config, wallet, node, &stop_state).unwrap()
		});

		threaded_rt.spawn(async move {
			futures::executor::block_on(shutdown_receiver).unwrap();
			stop_state_clone.stop();
		});

		// Wait for listener
		thread::sleep(Duration::from_millis(500));

		let do_request = async move {
			let request = Request::post(uri)
				.header("Content-Type", "application/json")
				.body(Body::from(req))
				.unwrap();

			Client::new().request(request).await
		};

		let response = threaded_rt.block_on(do_request)?;
		let response_str: String = threaded_rt.block_on(body_to_string(response));

		// Wait for at least one round to execute
		thread::sleep(Duration::from_millis(1500));

		shutdown_sender.send(()).ok();

		// Wait for shutdown
		thread::sleep(Duration::from_millis(500));
		threaded_rt.shutdown_background();

		Ok(response_str)
	}

	/// Single hop to demonstrate request validation and onion unwrapping.
	#[test]
	fn swap_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
		let secp = Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
		let server_key = secp::random_secret();

		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let commitment = secp::commit(value, &blind)?;
		let hop_excess = secp::random_secret();
		let nonce = secp::random_secret();

		let mut final_blind = blind.clone();
		final_blind.add_assign(&secp, &hop_excess).unwrap();
		let proof = secp.bullet_proof(
			value - fee,
			final_blind.clone(),
			nonce.clone(),
			nonce.clone(),
			None,
			None,
		);

		let hop = Hop {
			pubkey: PublicKey::from_secret_key(&secp, &server_key)?,
			payload: Payload {
				excess: hop_excess,
				fee: FeeFields::from(fee as u32),
				rangeproof: Some(proof),
			},
		};
		let hops: Vec<Hop> = vec![hop];
		let session_key = secp::random_secret();
		let onion_packet = test_util::create_onion(&commitment, &session_key, &hops)?;
		let comsig = ComSignature::sign(value, &blind, &onion_packet.serialize()?)?;
		let swap = SwapReq {
			onion: onion_packet,
			comsig,
		};

		let wallet = MockWallet {};
		let mut mut_node = MockGrinNode::new();
		mut_node.add_default_utxo(&commitment);
		let node = Arc::new(mut_node);

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		println!("Request: {}", req);
		let response = make_request(server_key, Arc::new(wallet), node.clone(), req)?;
		let expected = "{\"jsonrpc\":\"2.0\",\"result\":\"success\",\"id\":\"1\"}\n";
		assert_eq!(response, expected);

		// check that the transaction was posted
		let posted_txns = node.get_posted_txns();
		assert_eq!(posted_txns.len(), 1);
		let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
		let input_commit = posted_txn.inputs_committed().into_iter().next().unwrap();
		assert_eq!(input_commit, commitment);

		Ok(())
	}

	/// Returns "Commitment not found" when there's no matching output in the UTXO set.
	#[test]
	fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error>> {
		let secp = Secp256k1::new();
		let server_key = secp::random_secret();

		let value: u64 = 200_000_000;
		let fee: u64 = 50_000_000;
		let blind = secp::random_secret();
		let commitment = secp::commit(value, &blind)?;

		let hop = Hop {
			pubkey: PublicKey::from_secret_key(&secp, &server_key)?,
			payload: Payload {
				excess: secp::random_secret(),
				fee: FeeFields::from(fee as u32),
				rangeproof: None,
			},
		};
		let hops: Vec<Hop> = vec![hop];
		let session_key = secp::random_secret();
		let onion_packet = test_util::create_onion(&commitment, &session_key, &hops)?;
		let comsig = ComSignature::sign(value, &blind, &onion_packet.serialize()?)?;
		let swap = SwapReq {
			onion: onion_packet,
			comsig,
		};

		let wallet = MockWallet {};
		let node = MockGrinNode::new();

		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			serde_json::json!(swap)
		);
		let response = make_request(server_key, Arc::new(wallet), Arc::new(node), req)?;
		let expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Commitment not found\"},\"id\":\"1\"}\n";
		assert_eq!(response, expected);
		Ok(())
	}

	// TODO: Test bulletproof verification and test minimum fee

	#[test]
	fn swap_bad_request() -> Result<(), Box<dyn std::error::Error>> {
		let wallet = MockWallet {};
		let node = MockGrinNode::new();

		let params = "{ \"param\": \"Not a valid Swap request\" }";
		let req = format!(
			"{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}",
			params
		);
		let response = make_request(secp::random_secret(), Arc::new(wallet), Arc::new(node), req)?;
		let expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `onion`.\"},\"id\":\"1\"}\n";
		assert_eq!(response, expected);
		Ok(())
	}
}
