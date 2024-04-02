use crate::client::MixClient;
use crate::config::ServerConfig;
use crate::node::{self, GrinNode};
use crate::store::{StoreError, SwapData, SwapStatus, SwapStore, SwapTx};
use crate::tx;
use crate::wallet::Wallet;

use async_trait::async_trait;
use grin_core::core::{Committed, Input, Output, OutputFeatures, Transaction, TransactionBody};
use grin_core::global::DEFAULT_ACCEPT_FEE_BASE;
use grin_onion::crypto::comsig::ComSignature;
use grin_onion::crypto::secp::{Commitment, Secp256k1, SecretKey};
use grin_onion::onion::{Onion, OnionError};
use itertools::Itertools;
use secp256k1zkp::key::ZERO_KEY;
use std::collections::HashSet;
use std::result::Result;
use std::sync::Arc;
use thiserror::Error;

/// Swap error types
#[derive(Clone, Error, Debug, PartialEq)]
pub enum SwapError {
    #[error("Invalid number of payloads provided")]
    InvalidPayloadLength,
    #[error("Commitment Signature is invalid")]
    InvalidComSignature,
    #[error("Rangeproof is invalid")]
    InvalidRangeproof,
    #[error("Rangeproof is required but was not supplied")]
    MissingRangeproof,
    #[error("Output {commit:?} does not exist, or is already spent.")]
    CoinNotFound { commit: Commitment },
    #[error("Output {commit:?} is already in the swap list.")]
    AlreadySwapped { commit: Commitment },
    #[error("Failed to peel onion layer: {0:?}")]
    PeelOnionFailure(OnionError),
    #[error("Fee too low (expected >= {minimum_fee:?}, actual {actual_fee:?})")]
    FeeTooLow { minimum_fee: u64, actual_fee: u64 },
    #[error("Error saving swap to data store: {0}")]
    StoreError(StoreError),
    #[error("Error building transaction: {0}")]
    TxError(String),
    #[error("Node communication error: {0}")]
    NodeError(String),
    #[error("Client communication error: {0:?}")]
    ClientError(String),
    #[error("{0}")]
    UnknownError(String),
}

impl From<StoreError> for SwapError {
    fn from(e: StoreError) -> SwapError {
        SwapError::StoreError(e)
    }
}

impl From<tx::TxError> for SwapError {
    fn from(e: tx::TxError) -> SwapError {
        SwapError::TxError(e.to_string())
    }
}

impl From<node::NodeError> for SwapError {
    fn from(e: node::NodeError) -> SwapError {
        SwapError::NodeError(e.to_string())
    }
}

/// A public MWixnet server - the "Swap Server"
#[async_trait]
pub trait SwapServer: Send + Sync {
    /// Submit a new output to be swapped.
    async fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError>;

    /// Iterate through all saved submissions, filter out any inputs that are no longer spendable,
    /// and assemble the coinswap transaction, posting the transaction to the configured node.
    async fn execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError>;

    /// Verify the previous swap transaction is in the active chain or mempool.
    /// If it's not, rebroacast the transaction if it's still valid.
    /// If the transaction is no longer valid, perform the swap again.
    async fn check_reorg(&self, tx: Arc<Transaction>) -> Result<Option<Arc<Transaction>>, SwapError>;
}

/// The standard MWixnet server implementation
#[derive(Clone)]
pub struct SwapServerImpl {
    server_config: ServerConfig,
    next_server: Option<Arc<dyn MixClient>>,
    wallet: Arc<dyn Wallet>,
    node: Arc<dyn GrinNode>,
    store: Arc<tokio::sync::Mutex<SwapStore>>,
}

impl SwapServerImpl {
    /// Create a new MWixnet server
    pub fn new(
        server_config: ServerConfig,
        next_server: Option<Arc<dyn MixClient>>,
        wallet: Arc<dyn Wallet>,
        node: Arc<dyn GrinNode>,
        store: SwapStore,
    ) -> Self {
        SwapServerImpl {
            server_config,
            next_server,
            wallet,
            node,
            store: Arc::new(tokio::sync::Mutex::new(store)),
        }
    }

    /// The fee base to use. For now, just using the default.
    fn get_fee_base(&self) -> u64 {
        DEFAULT_ACCEPT_FEE_BASE
    }

    /// Minimum fee to perform a swap.
    /// Requires enough fee for the swap server's kernel, 1 input and its output to swap.
    fn get_minimum_swap_fee(&self) -> u64 {
        TransactionBody::weight_by_iok(1, 1, 1) * self.get_fee_base()
    }

    async fn async_is_spendable(&self, next_block_height: u64, swap: &SwapData) -> bool {
        if let SwapStatus::Unprocessed = swap.status {
            if node::async_is_spendable(&self.node, &swap.input.commit, next_block_height)
                .await
                .unwrap_or(false)
            {
                if !node::async_is_unspent(&self.node, &swap.output_commit)
                    .await
                    .unwrap_or(true)
                {
                    return true;
                }
            }
        }

        false
    }

    async fn async_execute_round(&self, store: &SwapStore, mut swaps: Vec<SwapData>) -> Result<Option<Arc<Transaction>>, SwapError> {
        swaps.sort_by(|a, b| a.output_commit.partial_cmp(&b.output_commit).unwrap());

        if swaps.len() == 0 {
            return Ok(None);
        }

        let (filtered, failed, offset, outputs, kernels) = if let Some(client) = &self.next_server {
            // Call next mix server
            let onions = swaps.iter().map(|s| s.onion.clone()).collect();
            let mixed = client
                .mix_outputs(&onions)
                .await
                .map_err(|e| SwapError::ClientError(e.to_string()))?;

            // Filter out failed entries
            let kept_indices = HashSet::<_>::from_iter(mixed.indices.clone());
            let filtered = swaps
                .iter()
                .enumerate()
                .filter(|(i, _)| kept_indices.contains(i))
                .map(|(_, j)| j.clone())
                .collect();

            let failed = swaps
                .iter()
                .enumerate()
                .filter(|(i, _)| !kept_indices.contains(i))
                .map(|(_, j)| j.clone())
                .collect();

            (
                filtered,
                failed,
                mixed.components.offset,
                mixed.components.outputs,
                mixed.components.kernels,
            )
        } else {
            // Build plain outputs for each swap entry
            let outputs: Vec<Output> = swaps
                .iter()
                .map(|s| {
                    Output::new(
                        OutputFeatures::Plain,
                        s.output_commit,
                        s.rangeproof.unwrap(),
                    )
                })
                .collect();

            (swaps, Vec::new(), ZERO_KEY, outputs, Vec::new())
        };

        let fees_paid: u64 = filtered.iter().map(|s| s.fee).sum();
        let inputs: Vec<Input> = filtered.iter().map(|s| s.input).collect();
        let output_excesses: Vec<SecretKey> = filtered.iter().map(|s| s.excess.clone()).collect();

        let tx = tx::async_assemble_tx(
            &self.wallet,
            &inputs,
            &outputs,
            &kernels,
            self.get_fee_base(),
            fees_paid,
            &offset,
            &output_excesses,
        )
            .await?;

        let chain_tip = self.node.async_get_chain_tip().await?;
        self.node.async_post_tx(&tx).await?;

        store.save_swap_tx(&SwapTx { tx: tx.clone(), chain_tip })?;

        // Update status to in process
        let kernel_commit = tx.kernels().first().unwrap().excess;
        for mut swap in filtered {
            swap.status = SwapStatus::InProcess { kernel_commit };
            store.save_swap(&swap, true)?;
        }

        // Update status of failed swaps
        for mut swap in failed {
            swap.status = SwapStatus::Failed;
            store.save_swap(&swap, true)?;
        }

        Ok(Some(Arc::new(tx)))
    }
}

#[async_trait]
impl SwapServer for SwapServerImpl {
    async fn swap(&self, onion: &Onion, comsig: &ComSignature) -> Result<(), SwapError> {
        // Verify that more than 1 payload exists when there's a next server,
        // or that exactly 1 payload exists when this is the final server
        if self.server_config.next_server.is_some() && onion.enc_payloads.len() <= 1
            || self.server_config.next_server.is_none() && onion.enc_payloads.len() != 1
        {
            return Err(SwapError::InvalidPayloadLength);
        }

        // Verify commitment signature to ensure caller owns the output
        let serialized_onion = onion
            .serialize()
            .map_err(|e| SwapError::UnknownError(e.to_string()))?;
        let _ = comsig
            .verify(&onion.commit, &serialized_onion)
            .map_err(|_| SwapError::InvalidComSignature)?;

        // Verify that commitment is unspent
        let input = node::async_build_input(&self.node, &onion.commit)
            .await
            .map_err(|e| SwapError::UnknownError(e.to_string()))?;
        let input = input.ok_or(SwapError::CoinNotFound {
            commit: onion.commit.clone(),
        })?;

        // Peel off top layer of encryption
        let peeled = onion
            .peel_layer(&self.server_config.key)
            .map_err(|e| SwapError::PeelOnionFailure(e))?;

        // Verify the fee meets the minimum
        let fee: u64 = peeled.payload.fee.into();
        if fee < self.get_minimum_swap_fee() {
            return Err(SwapError::FeeTooLow {
                minimum_fee: self.get_minimum_swap_fee(),
                actual_fee: fee,
            });
        }

        // Verify the rangeproof
        if let Some(r) = peeled.payload.rangeproof {
            let secp = Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
            secp.verify_bullet_proof(peeled.onion.commit, r, None)
                .map_err(|_| SwapError::InvalidRangeproof)?;
        } else if peeled.onion.enc_payloads.is_empty() {
            // A rangeproof is required in the last payload
            return Err(SwapError::MissingRangeproof);
        }

        let locked = self.store.lock().await;

        locked
            .save_swap(
                &SwapData {
                    excess: peeled.payload.excess,
                    output_commit: peeled.onion.commit,
                    rangeproof: peeled.payload.rangeproof,
                    input,
                    fee: fee as u64,
                    onion: peeled.onion,
                    status: SwapStatus::Unprocessed,
                },
                false,
            )
            .map_err(|e| match e {
                StoreError::AlreadyExists(_) => SwapError::AlreadySwapped {
                    commit: onion.commit.clone(),
                },
                _ => SwapError::StoreError(e),
            })?;
        Ok(())
    }

    async fn execute_round(&self) -> Result<Option<Arc<Transaction>>, SwapError> {
        let next_block_height = self.node.async_get_chain_tip().await?.0 + 1;

        let locked_store = self.store.lock().await;
        let swaps: Vec<SwapData> = locked_store
            .swaps_iter()?
            .unique_by(|s| s.output_commit)
            .collect();
        let mut spendable: Vec<SwapData> = vec![];
        for swap in &swaps {
            if self.async_is_spendable(next_block_height, &swap).await {
                spendable.push(swap.clone());
            }
        }

        self.async_execute_round(&locked_store, swaps).await
    }

    async fn check_reorg(&self, tx: Arc<Transaction>) -> Result<Option<Arc<Transaction>>, SwapError> {
        let excess = tx.kernels().first().unwrap().excess;
        if let Ok(swap_tx) = self.store.lock().await.get_swap_tx(&excess) {
            // If kernel is in active chain, return tx
            if self.node.async_get_kernel(&excess, Some(swap_tx.chain_tip.0), None).await?.is_some() {
                return Ok(Some(tx));
            }

            // If transaction is still valid, rebroadcast and return tx
            if node::async_is_tx_valid(&self.node, &tx).await? {
                self.node.async_post_tx(&tx).await?;
                return Ok(Some(tx));
            }

            // Collect all swaps based on tx's inputs, and execute_round with those swaps
            let next_block_height = self.node.async_get_chain_tip().await?.0 + 1;
            let locked_store = self.store.lock().await;
            let mut swaps = Vec::new();
            for input_commit in &tx.inputs_committed() {
                if let Ok(swap) = locked_store.get_swap(&input_commit) {
                    if self.async_is_spendable(next_block_height, &swap).await {
                        swaps.push(swap);
                    }
                }
            }

            self.async_execute_round(&locked_store, swaps).await
        } else {
            Err(SwapError::UnknownError("Swap transaction not found".to_string())) // TODO: Create SwapError enum value
        }
    }
}

#[cfg(test)]
pub mod mock {
    use super::{SwapError, SwapServer};

    use async_trait::async_trait;
    use grin_core::core::Transaction;
    use grin_onion::crypto::comsig::ComSignature;
    use grin_onion::onion::Onion;
    use std::collections::HashMap;
    use std::sync::Arc;

    pub struct MockSwapServer {
        errors: HashMap<Onion, SwapError>,
    }

    impl MockSwapServer {
        pub fn new() -> MockSwapServer {
            MockSwapServer {
                errors: HashMap::new(),
            }
        }

        pub fn set_response(&mut self, onion: &Onion, e: SwapError) {
            self.errors.insert(onion.clone(), e);
        }
    }

    #[async_trait]
    impl SwapServer for MockSwapServer {
        async fn swap(&self, onion: &Onion, _comsig: &ComSignature) -> Result<(), SwapError> {
            if let Some(e) = self.errors.get(&onion) {
                return Err(e.clone());
            }

            Ok(())
        }

        async fn execute_round(&self) -> Result<Option<std::sync::Arc<Transaction>>, SwapError> {
            Ok(None)
        }

        async fn check_reorg(&self, tx: Arc<Transaction>) -> Result<Option<Arc<Transaction>>, SwapError> {
            Ok(Some(tx))
        }
    }
}

#[cfg(test)]
pub mod test_util {
    use crate::client::MixClient;
    use crate::config;
    use crate::node::GrinNode;
    use crate::servers::swap::SwapServerImpl;
    use crate::store::SwapStore;
    use crate::wallet::mock::MockWallet;

    use grin_onion::crypto::dalek::DalekPublicKey;
    use grin_onion::crypto::secp::SecretKey;
    use std::sync::Arc;

    pub fn new_swapper(
        test_dir: &str,
        server_key: &SecretKey,
        next_server: Option<(&DalekPublicKey, &Arc<dyn MixClient>)>,
        node: Arc<dyn GrinNode>,
    ) -> (Arc<SwapServerImpl>, Arc<MockWallet>) {
        let config =
            config::test_util::local_config(&server_key, &None, &next_server.map(|n| n.0.clone()))
                .unwrap();

        let wallet = Arc::new(MockWallet::new());
        let store = SwapStore::new(test_dir).unwrap();
        let swap_server = Arc::new(SwapServerImpl::new(
            config,
            next_server.map(|n| n.1.clone()),
            wallet.clone(),
            node,
            store,
        ));

        (swap_server, wallet)
    }
}

#[cfg(test)]
mod tests {
    use crate::client::{self, MixClient};
    use crate::node::mock::MockGrinNode;
    use crate::servers::mix_rpc::MixResp;
    use crate::servers::swap::{SwapError, SwapServer};
    use crate::store::{SwapData, SwapStatus};
    use crate::tx;
    use crate::tx::TxComponents;

    use ::function_name::named;
    use grin_core::core::{Committed, Input, Output, OutputFeatures, Transaction, Weighting};
    use grin_onion::crypto::comsig::ComSignature;
    use grin_onion::crypto::secp;
    use grin_onion::onion::Onion;
    use grin_onion::test_util as onion_test_util;
    use grin_onion::{create_onion, new_hop, Hop};
    use secp256k1zkp::key::ZERO_KEY;
    use std::sync::Arc;
    use x25519_dalek::PublicKey as xPublicKey;

    macro_rules! assert_error_type {
		($result:expr, $error_type:pat) => {
			assert!($result.is_err());
			assert!(if let $error_type = $result.unwrap_err() {
				true
			} else {
				false
			});
		};
	}

    macro_rules! init_test {
		() => {{
			grin_core::global::set_local_chain_type(
				grin_core::global::ChainTypes::AutomatedTesting,
			);
			let test_dir = concat!("./target/tmp/.", function_name!());
			let _ = std::fs::remove_dir_all(test_dir);
			test_dir
		}};
	}

    /// Standalone swap server to demonstrate request validation and onion unwrapping.
    #[tokio::test]
    #[named]
    async fn swap_standalone() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let (output_commit, proof) = onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
        let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

        let onion = create_onion(&input_commit, &vec![hop.clone()])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        server.swap(&onion, &comsig).await?;

        // Make sure entry is added to server.
        let expected = SwapData {
            excess: hop_excess.clone(),
            output_commit: output_commit.clone(),
            rangeproof: Some(proof),
            input: Input::new(OutputFeatures::Plain, input_commit.clone()),
            fee: fee as u64,
            onion: Onion {
                ephemeral_pubkey: xPublicKey::from([0u8; 32]),
                commit: output_commit.clone(),
                enc_payloads: vec![],
            },
            status: SwapStatus::Unprocessed,
        };

        {
            let store = server.store.lock().await;
            assert_eq!(1, store.swaps_iter().unwrap().count());
            assert!(store.swap_exists(&input_commit).unwrap());
            assert_eq!(expected, store.get_swap(&input_commit).unwrap());
        }

        let tx = server.execute_round().await?;
        assert!(tx.is_some());

        {
            // check that status was updated
            let store = server.store.lock().await;
            assert!(match store.get_swap(&input_commit)?.status {
                SwapStatus::InProcess { kernel_commit } =>
                    kernel_commit == tx.unwrap().kernels().first().unwrap().excess,
                _ => false,
            });
        }

        // check that the transaction was posted
        let posted_txns = node.get_posted_txns();
        assert_eq!(posted_txns.len(), 1);
        let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
        assert!(posted_txn.inputs_committed().contains(&input_commit));
        assert!(posted_txn.outputs_committed().contains(&output_commit));
        // todo: check that outputs also contain the commitment generated by our wallet

        posted_txn.validate(Weighting::AsTransaction)?;

        Ok(())
    }

    /// Multi-server test to verify proper MixClient communication.
    #[tokio::test]
    #[named]
    async fn swap_multiserver() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let test_dir = init_test!();

        // Setup input
        let value: u64 = 200_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;
        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));

        // Swapper data
        let swap_fee: u32 = 50_000_000;
        let (swap_sk, _swap_pk) = onion_test_util::rand_keypair();
        let swap_hop_excess = secp::random_secret();
        let swap_hop = new_hop(&swap_sk, &swap_hop_excess, swap_fee, None);

        // Mixer data
        let mixer_fee: u32 = 30_000_000;
        let (mixer_sk, mixer_pk) = onion_test_util::rand_keypair();
        let mixer_hop_excess = secp::random_secret();
        let (output_commit, proof) = onion_test_util::proof(
            value,
            swap_fee + mixer_fee,
            &blind,
            &vec![&swap_hop_excess, &mixer_hop_excess],
        );
        let mixer_hop = new_hop(&mixer_sk, &mixer_hop_excess, mixer_fee, Some(proof));

        // Create onion
        let onion = create_onion(&input_commit, &vec![swap_hop, mixer_hop])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        // Mock mixer
        let mixer_onion = onion.peel_layer(&swap_sk)?.onion;
        let mut mock_mixer = client::mock::MockMixClient::new();
        let mixer_response = TxComponents {
            offset: ZERO_KEY,
            outputs: vec![Output::new(
                OutputFeatures::Plain,
                output_commit.clone(),
                proof.clone(),
            )],
            kernels: vec![tx::build_kernel(&mixer_hop_excess, mixer_fee as u64)?],
        };
        mock_mixer.set_response(
            &vec![mixer_onion.clone()],
            MixResp {
                indices: vec![0 as usize],
                components: mixer_response,
            },
        );

        let mixer: Arc<dyn MixClient> = Arc::new(mock_mixer);
        let (swapper, _) = super::test_util::new_swapper(
            &test_dir,
            &swap_sk,
            Some((&mixer_pk, &mixer)),
            node.clone(),
        );
        swapper.swap(&onion, &comsig).await?;

        let tx = swapper.execute_round().await?;
        assert!(tx.is_some());

        // check that the transaction was posted
        let posted_txns = node.get_posted_txns();
        assert_eq!(posted_txns.len(), 1);
        let posted_txn: Transaction = posted_txns.into_iter().next().unwrap();
        assert!(posted_txn.inputs_committed().contains(&input_commit));
        assert!(posted_txn.outputs_committed().contains(&output_commit));
        // todo: check that outputs also contain the commitment generated by our wallet

        posted_txn.validate(Weighting::AsTransaction)?;

        Ok(())
    }

    /// Returns InvalidPayloadLength when too many payloads are provided.
    #[tokio::test]
    #[named]
    async fn swap_too_many_payloads() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let (_output_commit, proof) =
            onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
        let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

        let hops: Vec<Hop> = vec![hop.clone(), hop.clone()]; // Multiple payloads
        let onion = create_onion(&input_commit, &hops)?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        let result = server.swap(&onion, &comsig).await;
        assert_eq!(Err(SwapError::InvalidPayloadLength), result);

        // Make sure no entry is added to the store
        assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

        Ok(())
    }

    /// Returns InvalidComSignature when ComSignature fails to verify.
    #[tokio::test]
    #[named]
    async fn swap_invalid_com_signature() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let (_output_commit, proof) =
            onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
        let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

        let onion = create_onion(&input_commit, &vec![hop])?;

        let wrong_blind = secp::random_secret();
        let comsig = ComSignature::sign(value, &wrong_blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        let result = server.swap(&onion, &comsig).await;
        assert_eq!(Err(SwapError::InvalidComSignature), result);

        // Make sure no entry is added to the store
        assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

        Ok(())
    }

    /// Returns InvalidRangeProof when the rangeproof fails to verify for the commitment.
    #[tokio::test]
    #[named]
    async fn swap_invalid_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let wrong_value = value + 10_000_000;
        let (_output_commit, proof) =
            onion_test_util::proof(wrong_value, fee, &blind, &vec![&hop_excess]);
        let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

        let onion = create_onion(&input_commit, &vec![hop])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        let result = server.swap(&onion, &comsig).await;
        assert_eq!(Err(SwapError::InvalidRangeproof), result);

        // Make sure no entry is added to the store
        assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

        Ok(())
    }

    /// Returns MissingRangeproof when no rangeproof is provided.
    #[tokio::test]
    #[named]
    async fn swap_missing_rangeproof() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let hop = new_hop(&server_key, &hop_excess, fee, None);

        let onion = create_onion(&input_commit, &vec![hop])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        let result = server.swap(&onion, &comsig).await;
        assert_eq!(Err(SwapError::MissingRangeproof), result);

        // Make sure no entry is added to the store
        assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

        Ok(())
    }

    /// Returns CoinNotFound when there's no matching output in the UTXO set.
    #[tokio::test]
    #[named]
    async fn swap_utxo_missing() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let (_output_commit, proof) =
            onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
        let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

        let onion = create_onion(&input_commit, &vec![hop])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new());
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        let result = server.swap(&onion, &comsig).await;
        assert_eq!(
            Err(SwapError::CoinNotFound {
                commit: input_commit.clone()
            }),
            result
        );

        // Make sure no entry is added to the store
        assert_eq!(0, server.store.lock().await.swaps_iter().unwrap().count());

        Ok(())
    }

    /// Returns AlreadySwapped when trying to swap the same commitment multiple times.
    #[tokio::test]
    #[named]
    async fn swap_already_swapped() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let (_output_commit, proof) =
            onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
        let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

        let onion = create_onion(&input_commit, &vec![hop])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        server.swap(&onion, &comsig).await?;

        // Call swap a second time
        let result = server.swap(&onion, &comsig).await;
        assert_eq!(
            Err(SwapError::AlreadySwapped {
                commit: input_commit.clone()
            }),
            result
        );

        Ok(())
    }

    /// Returns PeelOnionFailure when a failure occurs trying to decrypt the onion payload.
    #[tokio::test]
    #[named]
    async fn swap_peel_onion_failure() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 50_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let (_output_commit, proof) =
            onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);

        let wrong_server_key = secp::random_secret();
        let hop = new_hop(&wrong_server_key, &hop_excess, fee, Some(proof));

        let onion = create_onion(&input_commit, &vec![hop])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        let result = server.swap(&onion, &comsig).await;

        assert!(result.is_err());
        assert_error_type!(result, SwapError::PeelOnionFailure(_));

        Ok(())
    }

    /// Returns FeeTooLow when the minimum fee is not met.
    #[tokio::test]
    #[named]
    async fn swap_fee_too_low() -> Result<(), Box<dyn std::error::Error>> {
        let test_dir = init_test!();

        let value: u64 = 200_000_000;
        let fee: u32 = 1_000_000;
        let blind = secp::random_secret();
        let input_commit = secp::commit(value, &blind)?;

        let server_key = secp::random_secret();
        let hop_excess = secp::random_secret();
        let (_output_commit, proof) =
            onion_test_util::proof(value, fee, &blind, &vec![&hop_excess]);
        let hop = new_hop(&server_key, &hop_excess, fee, Some(proof));

        let onion = create_onion(&input_commit, &vec![hop])?;
        let comsig = ComSignature::sign(value, &blind, &onion.serialize()?)?;

        let node: Arc<MockGrinNode> = Arc::new(MockGrinNode::new_with_utxos(&vec![&input_commit]));
        let (server, _) = super::test_util::new_swapper(&test_dir, &server_key, None, node.clone());
        let result = server.swap(&onion, &comsig).await;
        assert_eq!(
            Err(SwapError::FeeTooLow {
                minimum_fee: 12_500_000,
                actual_fee: fee as u64,
            }),
            result
        );

        Ok(())
    }
}
