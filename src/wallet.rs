use crate::error::Result;
use crate::secp::{self, SecretKey};

use grin_api::client;
use grin_api::json_rpc::{build_request, Request, Response};
use grin_core::core::{FeeFields, Input, Inputs, KernelFeatures, Output, Transaction, TxKernel};
use grin_keychain::BlindingFactor;
use grin_util::ZeroingString;
use grin_wallet_api::Token;
use serde_json::json;
use std::net::SocketAddr;

const ENDPOINT: &str = "/v3/owner";

#[derive(Clone)]
pub struct HTTPWalletClient {
    wallet_owner_url: SocketAddr,
}

impl HTTPWalletClient {
    /// Create a new client that will communicate with the given grin node
    pub fn new(wallet_owner_url: &SocketAddr) -> HTTPWalletClient {
        HTTPWalletClient {
            wallet_owner_url: wallet_owner_url.to_owned(),
        }
    }

    fn send_json_request<D: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<D> {
        let url = format!("http://{}{}", self.wallet_owner_url, ENDPOINT);
        let req = build_request(method, params);
        let res = client::post::<Request, Response>(url.as_str(), None, &req)?;
        let parsed = res.clone().into_result()?;
        Ok(parsed)
    }
}

#[derive(Clone)]
pub struct Wallet {
    pub client: HTTPWalletClient,

    pub token: Token,
}

impl Wallet {
    pub fn open_wallet(wallet_owner_url: &SocketAddr, wallet_pass: &ZeroingString) -> Result<Wallet> {
        let client = HTTPWalletClient::new(&wallet_owner_url);

        let open_wallet_params = json!({
            "name": null,
            "password": wallet_pass.to_string()
        });
        let token: Token = client.send_json_request("open_wallet", &open_wallet_params)?;

        Ok(Wallet { 
            client: client,
            token: token,
        })
    }

    /// Builds and verifies a <code>Transaction</code> using the provided components.
    pub fn assemble_tx(&self, inputs: &Vec<Input>, outputs: &Vec<Output>, total_fee: u64, total_excess: &SecretKey) -> Result<Transaction> {
        // generate random transaction offset
        let offset = secp::random_secret();

        // build and verify kernel
        let kern_excess = secp::sub_blinds(&total_excess, &offset)?;
        let kern = Wallet::build_kernel(total_fee, &kern_excess)?;

        // assemble the transaction
        let tx = Transaction::new(Inputs::from(inputs.as_slice()), &outputs, &[kern])
            .with_offset(BlindingFactor::from_secret_key(offset));
        Ok(tx)
    }

    /// Builds and verifies a <code>TxKernel</code> from the provided fee and excess.
    fn build_kernel(total_fee: u64, kern_excess: &SecretKey) -> Result<TxKernel> {
        let mut kernel = TxKernel::with_features(KernelFeatures::Plain {
            fee: FeeFields::new(0, total_fee).unwrap(),
        });
        let msg = kernel.msg_to_sign()?;
        kernel.excess = secp::commit(0, &kern_excess)?;
        kernel.excess_sig = secp::sign(&kern_excess, &msg)?;
        kernel.verify()?;

        Ok(kernel)
    }
}