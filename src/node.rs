use crate::config::ServerConfig;
use crate::error::{ErrorKind, Result};
use crate::secp::Commitment;

use grin_api::client;
use grin_api::json_rpc::{build_request, Request, Response};
use grin_api::{BlockPrintable, LocatedTxKernel, OutputPrintable, OutputType, Tip};
use grin_core::consensus::COINBASE_MATURITY;
use grin_core::core::{Input, OutputFeatures, Transaction};
use grin_util::ToHex;

use serde_json::json;
use std::net::SocketAddr;

const ENDPOINT: &str = "/v2/foreign";

#[derive(Clone)]
pub struct HTTPNodeClient {
    node_url: SocketAddr,
    node_api_secret: Option<String>,
}

impl HTTPNodeClient {
    /// Create a new client that will communicate with the given grin node
    pub fn new(node_url: &SocketAddr, node_api_secret: Option<String>) -> HTTPNodeClient {
        HTTPNodeClient {
            node_url: node_url.to_owned(),
            node_api_secret: node_api_secret,
        }
    }

    fn send_json_request<D: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<D> {
        let url = format!("http://{}{}", self.node_url, ENDPOINT);
        let req = build_request(method, params);
        let res =
            client::post::<Request, Response>(url.as_str(), self.node_api_secret.clone(), &req)?;
        let parsed = res.clone().into_result()?;
        Ok(parsed)
    }
}

#[derive(Clone)]
pub struct GrinNode {
    client: HTTPNodeClient,
}

impl GrinNode {
    pub fn new(server_config: &ServerConfig) -> GrinNode {
        GrinNode { 
            client: HTTPNodeClient::new(&server_config.grin_node_url, None),
        }
    }

    // Checks whether a commitment is spendable at the block height provided
    pub fn is_spendable(&self, output_commit: &Commitment, next_block_height: u64) -> Result<bool> {
        let output = self.get_output(&output_commit)?;
        if let Some(out) = output {
            let is_coinbase = match out.output_type {
                OutputType::Coinbase => true,
                OutputType::Transaction => false,
            };

            if is_coinbase {
                if let Some(block_height) = out.block_height {
                    if block_height + COINBASE_MATURITY < next_block_height {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            }

            return Ok(true);
        }

        Ok(false)
    }

    /// Builds an input for an unspent output commitment
    pub fn build_input(&self, output_commit: &Commitment) -> Result<Option<Input>> {
        let output = self.get_output(&output_commit)?;

        if let Some(out) = output {
            let features = match out.output_type {
                OutputType::Coinbase => OutputFeatures::Coinbase,
                OutputType::Transaction => OutputFeatures::Plain,
            };

            let input = Input::new(features, out.commit);
            return Ok(Some(input));
        }

        Ok(None)
    }

    fn get_output(&self, output_commit: &Commitment) -> Result<Option<OutputPrintable>> {
        let commits : Vec<String> = vec![output_commit.to_hex()];
        let start_height : Option<u64> = None;
        let end_height : Option<u64> = None;
        let include_proof : Option<bool> = Some(false);
        let include_merkle_proof : Option<bool> = Some(false);

        let params = json!([Some(commits), start_height, end_height, include_proof, include_merkle_proof]);
        let outputs = self.client.send_json_request::<Vec<OutputPrintable>>("get_outputs", &params)?;
        if outputs.is_empty() {
            return Ok(None);
        }

        Ok(Some(outputs[0].clone()))
    }

    /// Gets the height of the chain tip
    pub fn get_chain_height(&self) -> Result<u64> {
        let params = json!([]);
        let tip_json = self.client.send_json_request::<serde_json::Value>("get_tip", &params)?;

        let tip: Result<Tip> = serde_json::from_value(tip_json["Ok"].clone())
            .map_err(|_| ErrorKind::SerdeJsonError.into());
        
        Ok(tip?.height)
    }

    /// Posts a transaction to the grin node
    pub fn post_tx(&self, tx: &Transaction) -> Result<()> {
        let params = json!([tx, true]);
        self.client.send_json_request::<serde_json::Value>("push_transaction", &params)?;
        Ok(())
    }

    // milestone 3: needed to handle chain reorgs
    pub fn chain_has_kernel(
        &self,
        kernel_excess: &Commitment,
        start_height: Option<u64>,
        end_height: Option<u64>,
    ) -> Result<bool> {
        let params = json!([kernel_excess, start_height, end_height]);
        let located_kernel_json = self.client.send_json_request::<serde_json::Value>("get_kernel", &params)?;

        let located_kernel : Result<LocatedTxKernel> = serde_json::from_value(located_kernel_json["Ok"].clone())
            .map_err(|_| ErrorKind::SerdeJsonError.into());

        Ok(located_kernel.is_ok())
    }

    // milestone 3: needed to handle chain reorgs
    pub fn block_has_kernel(&self, block_hash: &String, kernel_excess: &Commitment) -> Result<bool> {
        let block = self.get_block(None, Some(block_hash.clone()), None)?;

        let found = block.kernels.into_iter()
            .any(|kern| kern.excess == kernel_excess.to_hex());
        Ok(found)
    }

    // milestone 3: needed to handle chain reorgs
    fn get_block(&self,
        height: Option<u64>,
        hash: Option<String>,
        commit: Option<String>,
    ) -> Result<BlockPrintable> {
        let params = json!([height, hash, commit]);
        let block_printable = self.client.send_json_request::<BlockPrintable>("get_block", &params)?;
        Ok(block_printable)
    }
}