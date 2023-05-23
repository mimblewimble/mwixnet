pub use secp256k1zkp::aggsig;
pub use secp256k1zkp::constants::{
	AGG_SIGNATURE_SIZE, COMPRESSED_PUBLIC_KEY_SIZE, MAX_PROOF_SIZE, PEDERSEN_COMMITMENT_SIZE,
	SECRET_KEY_SIZE,
};
pub use secp256k1zkp::ecdh::SharedSecret;
pub use secp256k1zkp::key::{PublicKey, SecretKey, ZERO_KEY};
pub use secp256k1zkp::pedersen::{Commitment, RangeProof};
pub use secp256k1zkp::{ContextFlag, Message, Secp256k1, Signature};

use grin_core::ser::{self, Reader};
use secp256k1zkp::rand::thread_rng;

/// Generate a random SecretKey.
pub fn random_secret() -> SecretKey {
	let secp = Secp256k1::new();
	SecretKey::new(&secp, &mut thread_rng())
}

/// Deserialize a SecretKey from a Reader
pub fn read_secret_key<R: Reader>(reader: &mut R) -> Result<SecretKey, ser::Error> {
	let buf = reader.read_fixed_bytes(SECRET_KEY_SIZE)?;
	let secp = Secp256k1::with_caps(ContextFlag::None);
	let pk = SecretKey::from_slice(&secp, &buf).map_err(|_| ser::Error::CorruptedData)?;
	Ok(pk)
}

/// Build a Pedersen Commitment using the provided value and blinding factor
pub fn commit(value: u64, blind: &SecretKey) -> Result<Commitment, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let commit = secp.commit(value, blind.clone())?;
	Ok(commit)
}

/// Add a blinding factor to an existing Commitment
pub fn add_excess(
	commitment: &Commitment,
	excess: &SecretKey,
) -> Result<Commitment, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let excess_commit: Commitment = secp.commit(0, excess.clone())?;

	let commits = vec![commitment.clone(), excess_commit.clone()];
	let sum = secp.commit_sum(commits, Vec::new())?;
	Ok(sum)
}

/// Subtracts a value (v*H) from an existing commitment
pub fn sub_value(commitment: &Commitment, value: u64) -> Result<Commitment, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Commit);
	let neg_commit: Commitment = secp.commit(value, ZERO_KEY)?;
	let sum = secp.commit_sum(vec![commitment.clone()], vec![neg_commit.clone()])?;
	Ok(sum)
}

/// Signs the message with the provided SecretKey
pub fn sign(sk: &SecretKey, msg: &Message) -> Result<Signature, secp256k1zkp::Error> {
	let secp = Secp256k1::with_caps(ContextFlag::Full);
	let pubkey = PublicKey::from_secret_key(&secp, &sk)?;
	let sig = aggsig::sign_single(&secp, &msg, &sk, None, None, None, Some(&pubkey), None)?;
	Ok(sig)
}

#[cfg(test)]
pub mod test_util {
	use crate::crypto::secp::{self, Commitment, RangeProof, Secp256k1, SecretKey};
	use grin_core::core::hash::Hash;
	use grin_util::ToHex;
	use rand::RngCore;

	pub fn rand_commit() -> Commitment {
		secp::commit(rand::thread_rng().next_u64(), &secp::random_secret()).unwrap()
	}

	pub fn rand_hash() -> Hash {
		Hash::from_hex(secp::random_secret().to_hex().as_str()).unwrap()
	}

	pub fn rand_proof() -> RangeProof {
		let secp = Secp256k1::new();
		secp.bullet_proof(
			rand::thread_rng().next_u64(),
			secp::random_secret(),
			secp::random_secret(),
			secp::random_secret(),
			None,
			None,
		)
	}

	pub fn proof(
		value: u64,
		fee: u32,
		input_blind: &SecretKey,
		hop_excesses: &Vec<&SecretKey>,
	) -> (Commitment, RangeProof) {
		let secp = Secp256k1::new();

		let mut blind = input_blind.clone();
		for hop_excess in hop_excesses {
			blind.add_assign(&secp, &hop_excess).unwrap();
		}

		let out_value = value - (fee as u64);

		let rp = secp.bullet_proof(
			out_value,
			blind.clone(),
			secp::random_secret(),
			secp::random_secret(),
			None,
			None,
		);

		(secp::commit(out_value, &blind).unwrap(), rp)
	}
}
