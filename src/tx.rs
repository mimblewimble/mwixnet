use crate::wallet::Wallet;

use grin_core::core::{
	FeeFields, Input, Inputs, KernelFeatures, Output, Transaction, TransactionBody, TxKernel,
};
use grin_keychain::BlindingFactor;
use grin_onion::crypto::secp;
use secp256k1zkp::{ContextFlag, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// Error types for interacting with wallets
#[derive(Error, Debug)]
pub enum TxError {
	#[error("Error computing transactions's offset: {0:?}")]
	OffsetError(secp256k1zkp::Error),
	#[error("Error building kernel's fee fields: {0:?}")]
	KernelFeeError(grin_core::core::transaction::Error),
	#[error("Error computing kernel's excess: {0:?}")]
	KernelExcessError(secp256k1zkp::Error),
	#[error("Error computing kernel's signature message: {0:?}")]
	KernelSigMessageError(grin_core::core::transaction::Error),
	#[error("Error signing kernel: {0:?}")]
	KernelSigError(secp256k1zkp::Error),
	#[error("Built kernel failed to verify: {0:?}")]
	KernelVerifyError(grin_core::core::transaction::Error),
	#[error("Output blinding factor is invalid: {0:?}")]
	OutputBlindError(secp256k1zkp::Error),
	#[error("Wallet error: {0:?}")]
	WalletError(crate::wallet::WalletError),
}

/// A collection of transaction components
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TxComponents {
	/// Transaction offset
	pub offset: SecretKey,
	/// Transaction kernels
	pub kernels: Vec<TxKernel>,
	/// Transaction outputs
	pub outputs: Vec<Output>,
}

/// Builds and verifies the finalized swap 'Transaction' using the provided components.
pub async fn async_assemble_tx(
	wallet: &Arc<dyn Wallet>,
	inputs: &Vec<Input>,
	outputs: &Vec<Output>,
	kernels: &Vec<TxKernel>,
	fee_base: u64,
	fees_paid: u64,
	prev_offset: &SecretKey,
	output_excesses: &Vec<SecretKey>,
) -> Result<Transaction, TxError> {
	// calculate minimum fee required for the kernel
	let min_kernel_fee =
		TransactionBody::weight_by_iok(inputs.len() as u64, outputs.len() as u64, 1) * fee_base;

	let components = async_add_kernel_and_collect_fees(
		&wallet,
		&outputs,
		&kernels,
		fee_base,
		min_kernel_fee,
		fees_paid,
		&prev_offset,
		&output_excesses,
	)
	.await?;

	// assemble the transaction
	let tx = Transaction::new(
		Inputs::from(inputs.as_slice()),
		&components.outputs,
		&components.kernels,
	)
	.with_offset(BlindingFactor::from_secret_key(components.offset));
	Ok(tx)
}

/// Adds a kernel and output to a collection of transaction components to consume fees and offset excesses.
pub async fn async_assemble_components(
	wallet: &Arc<dyn Wallet>,
	components: &TxComponents,
	output_excesses: &Vec<SecretKey>,
	fee_base: u64,
	fees_paid: u64,
) -> Result<TxComponents, TxError> {
	// calculate minimum fee required for the kernel
	let min_kernel_fee = TransactionBody::weight_by_iok(0, 0, 1) * fee_base;

	async_add_kernel_and_collect_fees(
		&wallet,
		&components.outputs,
		&components.kernels,
		fee_base,
		min_kernel_fee,
		fees_paid,
		&components.offset,
		&output_excesses,
	)
	.await
}

async fn async_add_kernel_and_collect_fees(
	wallet: &Arc<dyn Wallet>,
	outputs: &Vec<Output>,
	kernels: &Vec<TxKernel>,
	fee_base: u64,
	min_kernel_fee: u64,
	fees_paid: u64,
	prev_offset: &SecretKey,
	output_excesses: &Vec<SecretKey>,
) -> Result<TxComponents, TxError> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let mut txn_outputs = outputs.clone();
	let mut txn_excesses = output_excesses.clone();
	let mut txn_kernels = kernels.clone();
	let mut kernel_fee = fees_paid;

	// calculate fee required if we add our own output
	let fee_to_collect = TransactionBody::weight_by_iok(0, 1, 0) * fee_base;

	// calculate fee to spend the output to ensure there's enough leftover to cover the fees for spending it
	let fee_to_spend = TransactionBody::weight_by_iok(1, 0, 0) * fee_base;

	// collect any leftover fees
	if fees_paid > min_kernel_fee + fee_to_collect + fee_to_spend {
		let amount = fees_paid - (min_kernel_fee + fee_to_collect);
		kernel_fee -= amount;

		let wallet_output = wallet
			.async_build_output(amount)
			.await
			.map_err(TxError::WalletError)?;
		txn_outputs.push(wallet_output.1);

		let output_excess = SecretKey::from_slice(&secp, &wallet_output.0.as_ref())
			.map_err(TxError::OutputBlindError)?;
		txn_excesses.push(output_excess);
	}

	// generate random transaction offset
	let our_offset = secp::random_secret();
	let txn_offset = secp
		.blind_sum(vec![prev_offset.clone(), our_offset.clone()], Vec::new())
		.map_err(TxError::OffsetError)?;

	// calculate kernel excess
	let kern_excess = secp
		.blind_sum(txn_excesses, vec![our_offset.clone()])
		.map_err(TxError::KernelExcessError)?;

	// build and verify kernel
	let kernel = build_kernel(&kern_excess, kernel_fee)?;
	txn_kernels.push(kernel);

	// Sort outputs & kernels by commitment
	txn_kernels.sort_by(|a, b| a.excess.partial_cmp(&b.excess).unwrap());
	txn_outputs.sort_by(|a, b| {
		a.identifier
			.commit
			.partial_cmp(&b.identifier.commit)
			.unwrap()
	});

	Ok(TxComponents {
		offset: txn_offset,
		kernels: txn_kernels,
		outputs: txn_outputs,
	})
}

/// Builds a transaction kernel for the Grin network.
///
/// Transaction kernels are a critical part of the Grin transaction process. Each transaction contains a
/// kernel. It includes features chosen for this transaction, a fee chosen for this transaction, and
/// a proof that the total sum of outputs, transaction fees and block reward equals the total sum of inputs.
/// The `build_kernel` function handles this process, building the kernel and handling any potential errors.
///
/// # Arguments
///
/// * `excess`: A reference to a `SecretKey`. This key is used as an excess value for the transaction.
///    The excess is a kind of cryptographic proof that the total sum of outputs and fees equals the
///    total sum of inputs.
/// * `fee`: An unsigned 64-bit integer representing the transaction fee in nanogrin. This is the fee
///    that will be paid to the miner who mines the block containing this transaction.
///
/// # Returns
///
/// The function returns a `Result` enum with `TxKernel` as the Ok variant and `TxError` as the Err variant.
/// If the kernel is successfully built, it is returned as part of the Ok variant. If there is an error at any point
/// during the process, it is returned as part of the Err variant.
///
/// # Errors
///
/// This function can return several types of errors, all defined in the `TxError` enum. These include:
///
/// * `KernelFeeError`: There was an error building the kernel's fee fields.
/// * `KernelExcessError`: There was an error computing the kernel's excess.
/// * `KernelSigMessageError`: There was an error computing the kernel's signature message.
/// * `KernelSigError`: There was an error signing the kernel.
/// * `KernelVerifyError`: The built kernel failed to verify.
///
/// # Example
///
/// ```rust
/// use secp256k1zkp::key::SecretKey;
/// use secp256k1zkp::rand::thread_rng;
/// use grin_onion::crypto::secp;
///
/// let secret_key = secp::random_secret();
/// let fee = 10; // 10 nanogrin
/// let kernel = mwixnet::tx::build_kernel(&secret_key, fee);
/// ```
pub fn build_kernel(excess: &SecretKey, fee: u64) -> Result<TxKernel, TxError> {
	let mut kernel = TxKernel::with_features(KernelFeatures::Plain {
		fee: FeeFields::new(0, fee).map_err(TxError::KernelFeeError)?,
	});
	let msg = kernel
		.msg_to_sign()
		.map_err(TxError::KernelSigMessageError)?;
	kernel.excess = secp::commit(0, &excess).map_err(TxError::KernelExcessError)?;
	kernel.excess_sig = secp::sign(&excess, &msg).map_err(TxError::KernelSigError)?;
	kernel.verify().map_err(TxError::KernelVerifyError)?;

	Ok(kernel)
}
