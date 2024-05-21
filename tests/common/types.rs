use grin_core::libtx::secp_ser;
use grin_keychain::Identifier;
use serde_derive::{Deserialize, Serialize};

/// Fees in block to use for coinbase amount calculation
/// (Duplicated from Grin wallet project)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockFees {
	/// fees
	#[serde(with = "secp_ser::string_or_u64")]
	pub fees: u64,
	/// height
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// key id
	pub key_id: Option<Identifier>,
}

impl BlockFees {
	/// return key id
	pub fn key_id(&self) -> Option<Identifier> {
		self.key_id.clone()
	}
}
