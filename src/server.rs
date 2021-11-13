use crate::onion;
use crate::secp::{self, Commitment, ComSignature, SecretKey};
use crate::ser;
use crate::types::Onion;

use jsonrpc_derive::rpc;
use jsonrpc_http_server::*;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_core::{Result, Value};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub struct ServerConfig {
    pub key: SecretKey,
    pub addr: SocketAddr,
    pub is_first: bool,
}

pub struct Submission {
    pub excess: SecretKey,
    pub input_commit: Commitment,
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

    // milestone 3:
    // fn derive_outputs(&self, entries: Vec<Onion>) -> Result<Value>;
    // fn derive_kernel(&self, tx: Tx) -> Result<Value>;
}

pub struct ServerImpl {
    server_key: SecretKey,
}

impl ServerImpl {
    pub fn new(server_key: SecretKey) -> Self {
        ServerImpl { server_key }
    }
}

impl Server for ServerImpl {
    fn swap(&self, swap: SwapReq) -> Result<Value> {
        // milestone 2 - check that commitment is unspent
    
        // Verify commitment signature to ensure caller owns the output
        let _ = swap.comsig.verify(&swap.onion.commit, &swap.msg)
            .map_err(|_| jsonrpc_core::Error::invalid_params("ComSignature invalid"))?;
    
        let peeled = onion::peel_layer(&swap.onion, &self.server_key)
            .map_err(|e| jsonrpc_core::Error::invalid_params(e.message()))?;
        SERVER_STATE.lock().unwrap().push(Submission{
            excess: peeled.0.excess,
            input_commit: swap.onion.commit,
            onion: peeled.1
        });
        Ok(Value::String("success".into()))
    }
    
}

/// Spin up the JSON-RPC web server
pub fn listen<F>(server_config: &ServerConfig, shutdown_signal: F) -> std::result::Result<(), Box<dyn std::error::Error>>
where
    F: futures::future::Future<Output = ()> + Send + 'static,
{
    let mut io = IoHandler::new();
    io.extend_with(ServerImpl::to_delegate(ServerImpl::new(server_config.key.clone())));

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
    use crate::{onion, secp, server, types};
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
        let server_config = server::ServerConfig { 
            key: server_key,
            addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
            is_first: true
        };

        let threaded_rt = runtime::Runtime::new()?;
        let (shutdown_sender, shutdown_receiver) = futures::channel::oneshot::channel();
        let uri = format!("http://{}/v1", server_config.addr);

        // Spawn the server task
        threaded_rt.spawn(async move {
            server::listen(&server_config, async { shutdown_receiver.await.ok(); }).unwrap()
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
        let server_key = secp::insecure_rand_secret()?;
        
        let secp = secp::Secp256k1::new();
        let value: u64 = 100;
        let blind = secp::insecure_rand_secret()?;
        let commitment = secp::commit(value, &blind)?;
        let session_key = secp::insecure_rand_secret()?;

        let hop = types::Hop {
            pubkey: secp::PublicKey::from_secret_key(&secp, &server_key)?,
            payload: types::Payload{
                excess: secp::insecure_rand_secret()?,
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
        let response = make_request(secp::insecure_rand_secret()?, req)?;
        let expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: missing field `onion`.\"},\"id\":\"1\"}\n";
        assert_eq!(response, expected);
        Ok(())
    }

    // milestone 2 - add tests to cover invalid comsig's & inputs not in utxo set
}