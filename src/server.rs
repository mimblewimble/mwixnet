use crate::config::ServerConfig;
use crate::node::GrinNode;
use crate::onion;
use crate::secp::{self, ComSignature, SecretKey};
use crate::ser;
use crate::types::Onion;
use crate::wallet::Wallet;

use grin_core::core::{Input, Output, OutputFeatures, TransactionBody};
use grin_core::global::DEFAULT_ACCEPT_FEE_BASE;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::*;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_core::{Result, Value};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq)]
pub struct Submission {
    pub excess: SecretKey,
    pub output: Option<Output>,
    pub input: Input,
    pub fee: u64,
    pub onion: Onion,
}

#[derive(Serialize, Deserialize)]
pub struct SwapReq {
    pub onion: Onion,
    #[serde(with = "ser::vec_serde")]
    pub msg: Vec<u8>,
    #[serde(with = "secp::comsig_serde")]
    pub comsig: ComSignature,
}

lazy_static! {
    static ref SERVER_STATE: Mutex<Vec<Submission>> = Mutex::new(Vec::new());
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
pub struct ServerImpl {
    server_config: ServerConfig,

    wallet: Wallet,

    node: GrinNode,
}

impl ServerImpl {
    pub fn new(server_config: ServerConfig, wallet: Wallet, node: GrinNode) -> Self {
        ServerImpl { server_config, wallet, node }
    }

    /// The fee base to use. For now, just using the default.
    fn get_fee_base(&self) -> u64 {
        DEFAULT_ACCEPT_FEE_BASE
    }

    /// Minimum fee to perform a swap.
    /// Requires enough fee for the mwixnet server's kernel, 1 input and its output to swap.
    pub fn get_minimum_swap_fee(&self) -> u64 {
        TransactionBody::weight_by_iok(1, 1, 1) * self.get_fee_base()
    }

    /// Iterate through all saved submissions, filter out any inputs that are no longer spendable,
    /// and assemble the coinswap transaction, posting the transaction to the configured node.
    /// 
    /// Currently only a single mix node is used. Milestone 3 will include support for multiple mix nodes.
    pub fn execute_round(&self) -> crate::error::Result<()> {
        let locked_state = SERVER_STATE.lock().unwrap();
        let next_block_height = self.node.get_chain_height()? + 1;

        let spendable : Vec<Submission> = locked_state
            .iter()
            .filter(|s| self.node.is_spendable(&s.input.commit, next_block_height).unwrap_or(false))
            .cloned()
            .collect();

        let total_fee : u64 = spendable
            .iter()
            .enumerate()
            .map(|(_, s)| s.fee)
            .sum();
        
        let inputs : Vec<Input> = spendable
            .iter()
            .enumerate()
            .map(|(_, s)| s.input)
            .collect();
        
        let outputs : Vec<Output> = spendable
            .iter()
            .enumerate()
            .filter_map(|(_, s)| s.output)
            .collect();
        
        let excesses : Vec<SecretKey> = spendable
            .iter()
            .enumerate()
            .map(|(_, s)| s.excess.clone())
            .collect();
        
		let excess_sum = secp::add_blinds(&excesses)?;

        let tx = self.wallet.assemble_tx(&inputs, &outputs, total_fee, &excess_sum)?;
        
        self.node.post_tx(&tx)?;
        
        Ok(())
    }
}

impl Server for ServerImpl {
    /// Implements the 'swap' API
    fn swap(&self, swap: SwapReq) -> Result<Value> {
        // Verify commitment signature to ensure caller owns the output
        let _ = swap.comsig.verify(&swap.onion.commit, &swap.msg)
            .map_err(|_| jsonrpc_core::Error::invalid_params("ComSignature invalid"))?;

        // Verify that commitment is unspent
        let input = self.node.build_input(&swap.onion.commit)
            .map_err(|_| jsonrpc_core::Error::internal_error())?;
        let input = input.ok_or(jsonrpc_core::Error::invalid_params("Commitment not found"))?;
    
        let peeled = onion::peel_layer(&swap.onion, &self.server_config.key)
            .map_err(|e| jsonrpc_core::Error::invalid_params(e.message()))?;

        let fee: u64 = peeled.0.fee.into();
        if fee < self.get_minimum_swap_fee() {
            return Err(jsonrpc_core::Error::invalid_params("Fee does not meet minimum"));
        }

        let output_commit = secp::add_excess(&swap.onion.commit, &peeled.0.excess)
            .map_err(|_| jsonrpc_core::Error::internal_error())?;
        let output = match peeled.0.rangeproof {
            Some(r) => Some(Output::new(OutputFeatures::Plain, output_commit, r)),
            None => None
        };
        SERVER_STATE.lock().unwrap().push(Submission{
            excess: peeled.0.excess,
            output: output,
            input: input,
            fee: fee,
            onion: peeled.1
        });
        Ok(Value::String("success".into()))
    }
}

/// Spin up the JSON-RPC web server
pub fn listen<F>(server_config: &ServerConfig, wallet: &Wallet, shutdown_signal: F) -> std::result::Result<(), Box<dyn std::error::Error>>
where
    F: futures::future::Future<Output = ()> + Send + 'static,
{
    let server_impl = Arc::new(ServerImpl::new(server_config.clone(), wallet.clone(), GrinNode::new(&server_config)));

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

    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30)); // todo: Graceful shutdown
            let _ = server_impl.as_ref().execute_round();
        }
    });

    let close_handle = server.close_handle();
    std::thread::spawn(move || {
        futures::executor::block_on(shutdown_signal);
        close_handle.close();
    });
    server.wait();

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{config, onion, secp, server, types, wallet};
    use grin_core::core::FeeFields;
    use std::net::TcpListener;
    use std::time::Duration;
    use std::thread;

    use hyper::{Body, Client, Request, Response};
    use tokio::runtime;

    async fn body_to_string(req: Response<Body>) -> String {
        let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    /// Spin up a temporary web service, query the API, then cleanup and return response
    fn make_request(server_key: secp::SecretKey, req: String) -> Result<String, Box<dyn std::error::Error>> {
        let server_config = config::ServerConfig { 
            key: server_key,
            addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
            grin_node_url: "127.0.0.1:3413".parse()?,
            wallet_owner_url: "127.0.0.1:3420".parse()?
        };

        let threaded_rt = runtime::Runtime::new()?;
        let (shutdown_sender, shutdown_receiver) = futures::channel::oneshot::channel();
        let uri = format!("http://{}/v1", server_config.addr);

        let wallet = wallet::Wallet::open_wallet(&server_config.wallet_owner_url, &grin_util::ZeroingString::from("wallet_pass"))?;

        // Spawn the server task
        threaded_rt.spawn(async move {
            server::listen(&server_config, &wallet, async { shutdown_receiver.await.ok(); }).unwrap()
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

        shutdown_sender.send(()).ok();

        // Wait for shutdown
        thread::sleep(Duration::from_millis(500));
        threaded_rt.shutdown_background();

        Ok(response_str)
    }

    /// Single hop to demonstrate request validation and onion unwrapping.
    /// UTXO creation and bulletproof generation reserved for milestones 2 & 3.
    #[test]
    fn swap_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let server_key = secp::random_secret();
        
        let secp = secp::Secp256k1::new();
        let value: u64 = 100;
        let fee: u64= 10;
        let blind = secp::random_secret();
        let commitment = secp::commit(value, &blind)?;
        let session_key = secp::random_secret();

        let hop = types::Hop {
            pubkey: secp::PublicKey::from_secret_key(&secp, &server_key)?,
            payload: types::Payload{
                excess: secp::random_secret(),
                fee: FeeFields::from(fee as u32),
                rangeproof: None,
            }
        };
        let hops: Vec<types::Hop> = vec![hop];
        let onion_packet = onion::create_onion(&commitment, &session_key, &hops)?;
        let msg : Vec<u8> = vec![0u8, 1u8, 2u8, 3u8];
        let comsig = secp::ComSignature::sign(value, &blind, &msg)?;
        let swap = server::SwapReq{
            onion: onion_packet,
            msg: msg,
            comsig: comsig,
        };

        let req = format!("{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}", serde_json::json!(swap));
        let response = make_request(server_key, req)?;
        let expected = "{\"jsonrpc\":\"2.0\",\"result\":\"success\",\"id\":\"1\"}\n";
        assert_eq!(response, expected);
        Ok(())
    }

    #[test]
    fn swap_bad_request() -> Result<(), Box<dyn std::error::Error>> {
        let params = "{ \"param\": \"Not a valid Swap request\" }";
        let req = format!("{{\"jsonrpc\": \"2.0\", \"method\": \"swap\", \"params\": [{}], \"id\": \"1\"}}", params);
        let response = make_request(secp::random_secret(), req)?;
        let expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `onion`.\"},\"id\":\"1\"}\n";
        assert_eq!(response, expected);
        Ok(())
    }

    // milestone 2 - add tests to cover invalid comsig's & inputs not in utxo set
}