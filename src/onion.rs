use crate::error::Result;
use crate::secp::{self, Commitment, PublicKey, Secp256k1, SecretKey, SharedSecret};
use crate::types::Payload;

use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use grin_core::ser::{self, ProtocolVersion, Writeable, Writer};
use grin_util::{self, ToHex};
use hmac::{Hmac, Mac};
use serde::ser::SerializeStruct;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;
type RawBytes = Vec<u8>;

/// A data packet with layers of encryption
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Onion {
	/// The onion originator's portion of the shared secret
	pub ephemeral_pubkey: PublicKey,
	/// The pedersen commitment before adjusting the excess and subtracting the fee
	pub commit: Commitment,
	/// The encrypted payloads which represent the layers of the onion
	pub enc_payloads: Vec<RawBytes>,
}

impl Onion {
	pub fn serialize(&self) -> Result<Vec<u8>> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &self)?;
		Ok(vec)
	}

	/// Peel a single layer off of the Onion, returning the peeled Onion and decrypted Payload
	pub fn peel_layer(&self, secret_key: &SecretKey) -> Result<(Payload, Onion)> {
		let secp = Secp256k1::new();

		let shared_secret = SharedSecret::new(&secp, &self.ephemeral_pubkey, &secret_key);
		let mut cipher = new_stream_cipher(&shared_secret)?;

		let mut decrypted_bytes = self.enc_payloads[0].clone();
		cipher.apply_keystream(&mut decrypted_bytes);
		let decrypted_payload = Payload::deserialize(&decrypted_bytes)?;

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

		let blinding_factor = calc_blinding_factor(&shared_secret, &self.ephemeral_pubkey)?;

		let mut ephemeral_pubkey = self.ephemeral_pubkey.clone();
		ephemeral_pubkey.mul_assign(&secp, &blinding_factor)?;

		let mut commitment = self.commit.clone();
		commitment = secp::add_excess(&commitment, &decrypted_payload.excess)?;
		commitment = secp::sub_value(&commitment, decrypted_payload.fee.into())?;

		let peeled_onion = Onion {
			ephemeral_pubkey,
			commit: commitment.clone(),
			enc_payloads,
		};
		Ok((decrypted_payload, peeled_onion))
	}
}

fn calc_blinding_factor(
	shared_secret: &SharedSecret,
	ephemeral_pubkey: &PublicKey,
) -> Result<SecretKey> {
	let serialized_pubkey = ser::ser_vec(&ephemeral_pubkey, ProtocolVersion::local())?;

	let mut hasher = Sha256::default();
	hasher.update(&serialized_pubkey);
	hasher.update(&shared_secret[0..32]);

	let secp = Secp256k1::new();
	let blind = SecretKey::from_slice(&secp, &hasher.finalize())?;
	Ok(blind)
}

fn new_stream_cipher(shared_secret: &SharedSecret) -> Result<ChaCha20> {
	let mut mu_hmac = HmacSha256::new_from_slice(b"MWIXNET")?;
	mu_hmac.update(&shared_secret[0..32]);
	let mukey = mu_hmac.finalize().into_bytes();

	let key = Key::from_slice(&mukey[0..32]);
	let nonce = Nonce::from_slice(b"NONCE1234567");

	Ok(ChaCha20::new(&key, &nonce))
}

impl Writeable for Onion {
	fn write<W: Writer>(&self, writer: &mut W) -> std::result::Result<(), ser::Error> {
		self.ephemeral_pubkey.write(writer)?;
		writer.write_fixed_bytes(&self.commit)?;
		writer.write_u64(self.enc_payloads.len() as u64)?;
		for p in &self.enc_payloads {
			writer.write_u64(p.len() as u64)?;
			p.write(writer)?;
		}
		Ok(())
	}
}

impl serde::ser::Serialize for Onion {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
	where
		S: serde::ser::Serializer,
	{
		let mut state = serializer.serialize_struct("Onion", 3)?;

		let secp = Secp256k1::new();
		state.serialize_field(
			"pubkey",
			&self.ephemeral_pubkey.serialize_vec(&secp, true).to_hex(),
		)?;
		state.serialize_field("commit", &self.commit.to_hex())?;

		let hex_payloads: Vec<String> = self.enc_payloads.iter().map(|v| v.to_hex()).collect();
		state.serialize_field("data", &hex_payloads)?;
		state.end()
	}
}

impl<'de> serde::de::Deserialize<'de> for Onion {
	fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
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

			fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
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
							let secp = Secp256k1::new();
							pubkey = Some(
								PublicKey::from_slice(&secp, &vec[..])
									.map_err(serde::de::Error::custom)?,
							);
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

#[cfg(test)]
pub mod test_util {
	use super::{Onion, RawBytes};
	use crate::error::Result;
	use crate::secp::{Commitment, PublicKey, Secp256k1, SecretKey, SharedSecret};
	use crate::types::Payload;

	use chacha20::cipher::StreamCipher;

	pub struct Hop {
		pub pubkey: PublicKey,
		pub payload: Payload,
	}

	/// Create an Onion for the Commitment, encrypting the payload for each hop
	pub fn create_onion(
		commitment: &Commitment,
		session_key: &SecretKey,
		hops: &Vec<Hop>,
	) -> Result<Onion> {
		let secp = Secp256k1::new();
		let mut ephemeral_key = session_key.clone();

		let mut shared_secrets: Vec<SharedSecret> = Vec::new();
		let mut enc_payloads: Vec<RawBytes> = Vec::new();
		for hop in hops {
			let shared_secret = SharedSecret::new(&secp, &hop.pubkey, &ephemeral_key);

			let ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_key)?;
			let blinding_factor = super::calc_blinding_factor(&shared_secret, &ephemeral_pubkey)?;

			shared_secrets.push(shared_secret);
			enc_payloads.push(hop.payload.serialize()?);
			ephemeral_key.mul_assign(&secp, &blinding_factor)?;
		}

		for i in (0..shared_secrets.len()).rev() {
			let mut cipher = super::new_stream_cipher(&shared_secrets[i])?;
			for j in i..shared_secrets.len() {
				cipher.apply_keystream(&mut enc_payloads[j]);
			}
		}

		let onion = Onion {
			ephemeral_pubkey: PublicKey::from_secret_key(&secp, session_key)?,
			commit: commitment.clone(),
			enc_payloads,
		};
		Ok(onion)
	}

	/// Calculates the expected next ephemeral pubkey after peeling a layer off of the Onion.
	pub fn next_ephemeral_pubkey(onion: &Onion, server_key: &SecretKey) -> Result<PublicKey> {
		let secp = Secp256k1::new();
		let mut ephemeral_pubkey = onion.ephemeral_pubkey.clone();
		let shared_secret = SharedSecret::new(&secp, &ephemeral_pubkey, &server_key);
		let blinding_factor = super::calc_blinding_factor(&shared_secret, &ephemeral_pubkey)?;
		ephemeral_pubkey.mul_assign(&secp, &blinding_factor)?;
		Ok(ephemeral_pubkey)
	}
}

#[cfg(test)]
pub mod tests {
	use super::test_util::{self, Hop};
	use crate::secp;
	use crate::types::Payload;

	use grin_core::core::FeeFields;

	/// Test end-to-end Onion creation and unwrapping logic.
	#[test]
	fn onion() {
		let total_fee: u64 = 10;
		let fee_per_hop: u64 = 2;
		let in_value: u64 = 1000;
		let out_value: u64 = in_value - total_fee;
		let blind = secp::random_secret();
		let commitment = secp::commit(in_value, &blind).unwrap();

		let session_key = secp::random_secret();
		let mut hops: Vec<Hop> = Vec::new();

		let mut keys: Vec<secp::SecretKey> = Vec::new();
		let mut final_commit = secp::commit(out_value, &blind).unwrap();
		let mut final_blind = blind.clone();
		for i in 0..5 {
			keys.push(secp::random_secret());

			let excess = secp::random_secret();

			let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
			final_blind.add_assign(&secp, &excess).unwrap();
			final_commit = secp::add_excess(&final_commit, &excess).unwrap();
			let proof = if i == 4 {
				let n1 = secp::random_secret();
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

			hops.push(Hop {
				pubkey: secp::PublicKey::from_secret_key(&secp, &keys[i]).unwrap(),
				payload: Payload {
					excess,
					fee: FeeFields::from(fee_per_hop as u32),
					rangeproof: proof,
				},
			});
		}

		let mut onion_packet = test_util::create_onion(&commitment, &session_key, &hops).unwrap();

		let mut payload = Payload {
			excess: secp::random_secret(),
			fee: FeeFields::from(fee_per_hop as u32),
			rangeproof: None,
		};
		for i in 0..5 {
			let peeled = onion_packet.peel_layer(&keys[i]).unwrap();
			payload = peeled.0;
			onion_packet = peeled.1;
		}

		assert!(payload.rangeproof.is_some());
		assert_eq!(
			payload.rangeproof.unwrap(),
			hops[4].payload.rangeproof.unwrap()
		);
		assert_eq!(secp::commit(out_value, &final_blind).unwrap(), final_commit);
		assert_eq!(payload.fee, FeeFields::from(fee_per_hop as u32));
	}
}
