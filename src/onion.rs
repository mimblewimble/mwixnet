use crate::crypto::secp::{self, Commitment, RangeProof, SecretKey};
use crate::onion::OnionError::{InvalidKeyLength, SerializationError};
use crate::util::{read_optional, vec_to_array, write_optional};

use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use grin_core::core::FeeFields;
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use grin_util::{self, ToHex};
use hmac::digest::InvalidLength;
use hmac::{Hmac, Mac};
use serde::ser::SerializeStruct;
use serde::Deserialize;
use sha2::Sha256;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::result::Result;
use thiserror::Error;
use x25519_dalek::{PublicKey as xPublicKey, SharedSecret, StaticSecret};

type HmacSha256 = Hmac<Sha256>;
type RawBytes = Vec<u8>;

const CURRENT_ONION_VERSION: u8 = 0;

/// A data packet with layers of encryption
#[derive(Clone, Debug)]
pub struct Onion {
	/// The onion originator's portion of the shared secret
	pub ephemeral_pubkey: xPublicKey,
	/// The pedersen commitment before adjusting the excess and subtracting the fee
	pub commit: Commitment,
	/// The encrypted payloads which represent the layers of the onion
	pub enc_payloads: Vec<RawBytes>,
}

impl PartialEq for Onion {
	fn eq(&self, other: &Onion) -> bool {
		*self.ephemeral_pubkey.as_bytes() == *other.ephemeral_pubkey.as_bytes()
			&& self.commit == other.commit
			&& self.enc_payloads == other.enc_payloads
	}
}

impl Eq for Onion {}

impl Hash for Onion {
	fn hash<H: Hasher>(&self, state: &mut H) {
		state.write(self.ephemeral_pubkey.as_bytes());
		state.write(self.commit.as_ref());
		state.write_usize(self.enc_payloads.len());
		for p in &self.enc_payloads {
			state.write(p.as_slice());
		}
	}
}

/// A single, decrypted/peeled layer of an Onion.
#[derive(Debug, Clone)]
pub struct Payload {
	pub next_ephemeral_pk: xPublicKey,
	pub excess: SecretKey,
	pub fee: FeeFields,
	pub rangeproof: Option<RangeProof>,
}

impl Payload {
	pub fn deserialize(bytes: &Vec<u8>) -> Result<Payload, ser::Error> {
		let payload: Payload = ser::deserialize_default(&mut &bytes[..])?;
		Ok(payload)
	}

	#[cfg(test)]
	pub fn serialize(&self) -> Result<Vec<u8>, ser::Error> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &self)?;
		Ok(vec)
	}
}

impl Readable for Payload {
	fn read<R: Reader>(reader: &mut R) -> Result<Payload, ser::Error> {
		let version = reader.read_u8()?;
		if version != CURRENT_ONION_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}

		let next_ephemeral_pk =
			xPublicKey::from(vec_to_array::<32>(&reader.read_fixed_bytes(32)?)?);
		let excess = secp::read_secret_key(reader)?;
		let fee = FeeFields::try_from(reader.read_u64()?).map_err(|_| ser::Error::CorruptedData)?;
		let rangeproof = read_optional(reader)?;
		Ok(Payload {
			next_ephemeral_pk,
			excess,
			fee,
			rangeproof,
		})
	}
}

impl Writeable for Payload {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(CURRENT_ONION_VERSION)?;
		writer.write_fixed_bytes(&self.next_ephemeral_pk.as_bytes())?;
		writer.write_fixed_bytes(&self.excess)?;
		writer.write_u64(self.fee.into())?;
		write_optional(writer, &self.rangeproof)?;
		Ok(())
	}
}

/// An onion with a layer decrypted
#[derive(Clone, Debug)]
pub struct PeeledOnion {
	/// The payload from the peeled layer
	pub payload: Payload,
	/// The onion remaining after a layer was peeled
	pub onion: Onion,
}

impl Onion {
	pub fn serialize(&self) -> Result<Vec<u8>, ser::Error> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &self)?;
		Ok(vec)
	}

	/// Peel a single layer off of the Onion, returning the peeled Onion and decrypted Payload
	pub fn peel_layer(&self, server_key: &SecretKey) -> Result<PeeledOnion, OnionError> {
		let shared_secret = StaticSecret::from(server_key.0).diffie_hellman(&self.ephemeral_pubkey);
		let mut cipher = new_stream_cipher(&shared_secret)?;

		let mut decrypted_bytes = self.enc_payloads[0].clone();
		cipher.apply_keystream(&mut decrypted_bytes);
		let decrypted_payload = Payload::deserialize(&decrypted_bytes)
			.map_err(|e| OnionError::DeserializationError(e))?;

		let enc_payloads: Vec<RawBytes> = self
			.enc_payloads
			.iter()
			.enumerate()
			.filter(|&(i, _)| i != 0)
			.map(|(_, enc_payload)| {
				let mut p = enc_payload.clone();
				cipher.apply_keystream(&mut p);
				p
			})
			.collect();

		let mut commitment = self.commit.clone();
		commitment = secp::add_excess(&commitment, &decrypted_payload.excess)
			.map_err(|e| OnionError::CalcCommitError(e))?;
		commitment = secp::sub_value(&commitment, decrypted_payload.fee.into())
			.map_err(|e| OnionError::CalcCommitError(e))?;

		let peeled_onion = Onion {
			ephemeral_pubkey: decrypted_payload.next_ephemeral_pk,
			commit: commitment.clone(),
			enc_payloads,
		};
		Ok(PeeledOnion {
			payload: decrypted_payload,
			onion: peeled_onion,
		})
	}
}

fn new_stream_cipher(shared_secret: &SharedSecret) -> Result<ChaCha20, OnionError> {
	let mut mu_hmac = HmacSha256::new_from_slice(b"MWIXNET")?;
	mu_hmac.update(shared_secret.as_bytes());
	let mukey = mu_hmac.finalize().into_bytes();

	let key = Key::from_slice(&mukey[0..32]);
	let nonce = Nonce::from_slice(b"NONCE1234567");

	Ok(ChaCha20::new(&key, &nonce))
}

impl Writeable for Onion {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(self.ephemeral_pubkey.as_bytes())?;
		writer.write_fixed_bytes(&self.commit)?;
		writer.write_u64(self.enc_payloads.len() as u64)?;
		for p in &self.enc_payloads {
			writer.write_u64(p.len() as u64)?;
			p.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for Onion {
	fn read<R: Reader>(reader: &mut R) -> Result<Onion, ser::Error> {
		let pubkey_bytes: [u8; 32] = vec_to_array(&reader.read_fixed_bytes(32)?)?;
		let ephemeral_pubkey = xPublicKey::from(pubkey_bytes);
		let commit = Commitment::read(reader)?;
		let mut enc_payloads: Vec<RawBytes> = Vec::new();
		let len = reader.read_u64()?;
		for _ in 0..len {
			let size = reader.read_u64()?;
			let bytes = reader.read_fixed_bytes(size as usize)?;
			enc_payloads.push(bytes);
		}
		Ok(Onion {
			ephemeral_pubkey,
			commit,
			enc_payloads,
		})
	}
}

impl serde::ser::Serialize for Onion {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::ser::Serializer,
	{
		let mut state = serializer.serialize_struct("Onion", 3)?;

		state.serialize_field("pubkey", &self.ephemeral_pubkey.as_bytes().to_hex())?;
		state.serialize_field("commit", &self.commit.to_hex())?;

		let hex_payloads: Vec<String> = self.enc_payloads.iter().map(|v| v.to_hex()).collect();
		state.serialize_field("data", &hex_payloads)?;
		state.end()
	}
}

impl<'de> serde::de::Deserialize<'de> for Onion {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::de::Deserializer<'de>,
	{
		#[derive(Deserialize)]
		#[serde(field_identifier, rename_all = "snake_case")]
		enum Field {
			Pubkey,
			Commit,
			Data,
		}

		struct OnionVisitor;

		impl<'de> serde::de::Visitor<'de> for OnionVisitor {
			type Value = Onion;

			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str("an Onion")
			}

			fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
			where
				A: serde::de::MapAccess<'de>,
			{
				let mut pubkey = None;
				let mut commit = None;
				let mut data = None;

				while let Some(key) = map.next_key()? {
					match key {
						Field::Pubkey => {
							let val: String = map.next_value()?;
							let vec =
								grin_util::from_hex(&val).map_err(serde::de::Error::custom)?;
							pubkey =
								Some(xPublicKey::from(vec_to_array::<32>(&vec).map_err(
									|_| serde::de::Error::custom("Invalid length pubkey"),
								)?));
						}
						Field::Commit => {
							let val: String = map.next_value()?;
							let vec =
								grin_util::from_hex(&val).map_err(serde::de::Error::custom)?;
							commit = Some(Commitment::from_vec(vec));
						}
						Field::Data => {
							let val: Vec<String> = map.next_value()?;
							let mut vec: Vec<Vec<u8>> = Vec::new();
							for hex in val {
								vec.push(
									grin_util::from_hex(&hex).map_err(serde::de::Error::custom)?,
								);
							}
							data = Some(vec);
						}
					}
				}

				Ok(Onion {
					ephemeral_pubkey: pubkey.unwrap(),
					commit: commit.unwrap(),
					enc_payloads: data.unwrap(),
				})
			}
		}

		const FIELDS: &[&str] = &["pubkey", "commit", "data"];
		deserializer.deserialize_struct("Onion", &FIELDS, OnionVisitor)
	}
}

/// Error types for creating and peeling Onions
#[derive(Clone, Error, Debug, PartialEq)]
pub enum OnionError {
	#[error("Invalid key length for MAC initialization")]
	InvalidKeyLength,
	#[error("Serialization error occurred: {0:?}")]
	SerializationError(ser::Error),
	#[error("Deserialization error occurred: {0:?}")]
	DeserializationError(ser::Error),
	#[error("Error calculating blinding factor: {0:?}")]
	CalcBlindError(secp256k1zkp::Error),
	#[error("Error calculating ephemeral pubkey: {0:?}")]
	CalcPubKeyError(secp256k1zkp::Error),
	#[error("Error calculating commitment: {0:?}")]
	CalcCommitError(secp256k1zkp::Error),
}

impl From<InvalidLength> for OnionError {
	fn from(_err: InvalidLength) -> OnionError {
		InvalidKeyLength
	}
}

impl From<ser::Error> for OnionError {
	fn from(err: ser::Error) -> OnionError {
		SerializationError(err)
	}
}

#[cfg(test)]
pub mod test_util {
	use super::{Onion, OnionError, Payload, RawBytes};
	use crate::crypto::secp::test_util::{rand_commit, rand_proof};
	use crate::crypto::secp::{random_secret, Commitment, SecretKey};

	use chacha20::cipher::StreamCipher;
	use grin_core::core::FeeFields;
	use rand::{thread_rng, RngCore};
	use secp256k1zkp::pedersen::RangeProof;
	use x25519_dalek::PublicKey as xPublicKey;
	use x25519_dalek::{SharedSecret, StaticSecret};

	#[derive(Clone)]
	pub struct Hop {
		pub server_pubkey: xPublicKey,
		pub excess: SecretKey,
		pub fee: FeeFields,
		pub rangeproof: Option<RangeProof>,
	}

	pub fn new_hop(
		server_key: &SecretKey,
		hop_excess: &SecretKey,
		fee: u32,
		proof: Option<RangeProof>,
	) -> Hop {
		Hop {
			server_pubkey: xPublicKey::from(&StaticSecret::from(server_key.0.clone())),
			excess: hop_excess.clone(),
			fee: FeeFields::from(fee as u32),
			rangeproof: proof,
		}
	}

	/// Create an Onion for the Commitment, encrypting the payload for each hop
	pub fn create_onion(commitment: &Commitment, hops: &Vec<Hop>) -> Result<Onion, OnionError> {
		if hops.is_empty() {
			return Ok(Onion {
				ephemeral_pubkey: xPublicKey::from([0u8; 32]),
				commit: commitment.clone(),
				enc_payloads: vec![],
			});
		}

		let mut shared_secrets: Vec<SharedSecret> = Vec::new();
		let mut enc_payloads: Vec<RawBytes> = Vec::new();
		let mut ephemeral_sk = StaticSecret::from(random_secret().0);
		let onion_ephemeral_pk = xPublicKey::from(&ephemeral_sk);
		for i in 0..hops.len() {
			let hop = &hops[i];
			let shared_secret = ephemeral_sk.diffie_hellman(&hop.server_pubkey);
			shared_secrets.push(shared_secret);

			ephemeral_sk = StaticSecret::from(random_secret().0);
			let next_ephemeral_pk = if i < (hops.len() - 1) {
				xPublicKey::from(&ephemeral_sk)
			} else {
				xPublicKey::from([0u8; 32])
			};

			let payload = Payload {
				next_ephemeral_pk,
				excess: hop.excess.clone(),
				fee: hop.fee.clone(),
				rangeproof: hop.rangeproof.clone(),
			};
			enc_payloads.push(payload.serialize()?);
		}

		for i in (0..shared_secrets.len()).rev() {
			let mut cipher = super::new_stream_cipher(&shared_secrets[i])?;
			for j in i..shared_secrets.len() {
				cipher.apply_keystream(&mut enc_payloads[j]);
			}
		}

		let onion = Onion {
			ephemeral_pubkey: onion_ephemeral_pk,
			commit: commitment.clone(),
			enc_payloads,
		};
		Ok(onion)
	}

	pub fn rand_onion() -> Onion {
		let commit = rand_commit();
		let mut hops = Vec::new();
		let k = (thread_rng().next_u64() % 5) + 1;
		for i in 0..k {
			let rangeproof = if i == (k - 1) {
				Some(rand_proof())
			} else {
				None
			};
			let hop = new_hop(
				&random_secret(),
				&random_secret(),
				thread_rng().next_u32(),
				rangeproof,
			);
			hops.push(hop);
		}

		create_onion(&commit, &hops).unwrap()
	}
}

#[cfg(test)]
pub mod tests {
	use super::test_util::{new_hop, Hop};
	use super::*;
	use crate::crypto::secp::random_secret;

	use grin_core::core::FeeFields;

	/// Test end-to-end Onion creation and unwrapping logic.
	#[test]
	fn onion() {
		let total_fee: u64 = 10;
		let fee_per_hop: u32 = 2;
		let in_value: u64 = 1000;
		let out_value: u64 = in_value - total_fee;
		let blind = random_secret();
		let commitment = secp::commit(in_value, &blind).unwrap();

		let mut hops: Vec<Hop> = Vec::new();
		let mut keys: Vec<SecretKey> = Vec::new();
		let mut final_commit = secp::commit(out_value, &blind).unwrap();
		let mut final_blind = blind.clone();
		for i in 0..5 {
			keys.push(random_secret());

			let excess = random_secret();

			let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
			final_blind.add_assign(&secp, &excess).unwrap();
			final_commit = secp::add_excess(&final_commit, &excess).unwrap();
			let proof = if i == 4 {
				let n1 = random_secret();
				let rp = secp.bullet_proof(
					out_value,
					final_blind.clone(),
					n1.clone(),
					n1.clone(),
					None,
					None,
				);
				assert!(secp.verify_bullet_proof(final_commit, rp, None).is_ok());
				Some(rp)
			} else {
				None
			};

			let hop = new_hop(&keys[i], &excess, fee_per_hop, proof);
			hops.push(hop);
		}

		let mut onion_packet = test_util::create_onion(&commitment, &hops).unwrap();

		let mut payload = Payload {
			next_ephemeral_pk: onion_packet.ephemeral_pubkey.clone(),
			excess: random_secret(),
			fee: FeeFields::from(fee_per_hop as u32),
			rangeproof: None,
		};
		for i in 0..5 {
			let peeled = onion_packet.peel_layer(&keys[i]).unwrap();
			payload = peeled.payload;
			onion_packet = peeled.onion;
		}

		assert!(payload.rangeproof.is_some());
		assert_eq!(payload.rangeproof.unwrap(), hops[4].rangeproof.unwrap());
		assert_eq!(secp::commit(out_value, &final_blind).unwrap(), final_commit);
		assert_eq!(payload.fee, FeeFields::from(fee_per_hop as u32));
	}
}
