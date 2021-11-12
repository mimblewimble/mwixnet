pub use secp256k1zkp::{ContextFlag, Message, Secp256k1, Signature};
pub use secp256k1zkp::ecdh::SharedSecret;
pub use secp256k1zkp::pedersen::{Commitment, RangeProof};
pub use secp256k1zkp::key::{PublicKey, SecretKey};
pub use secp256k1zkp::constants::{AGG_SIGNATURE_SIZE, COMPRESSED_PUBLIC_KEY_SIZE, MAX_PROOF_SIZE, PEDERSEN_COMMITMENT_SIZE, SECRET_KEY_SIZE};

use crate::ser::{Readable, Reader, Writeable, Writer};
use crate::error::{ErrorKind, Result};

use rand::RngCore;
use std::cmp;

/// A generalized Schnorr signature with a pedersen commitment value & blinding factors as the keys
pub const COM_SIGNATURE_SIZE : usize = 96;

pub struct ComSignature(pub [u8; COM_SIGNATURE_SIZE]);
impl ComSignature {
    /// Builds a ComSignature from a byte vector. If the vector is too short, it will be
    /// completed by zeroes. If it's too long, it will be truncated.
    pub fn from_vec(v: Vec<u8>) -> ComSignature {
        let mut h = [0; COM_SIGNATURE_SIZE];
        for i in 0..cmp::min(v.len(), COM_SIGNATURE_SIZE) {
            h[i] = v[i];
        }
        ComSignature(h)
    }

    #[allow(dead_code)]
    pub fn sign(_value: u64, _blind: &SecretKey, _msg: &Vec<u8>) -> Result<ComSignature> {
        // milestone 2 - todo
        let mut h = [0u8; COM_SIGNATURE_SIZE];
        for i in 0..COM_SIGNATURE_SIZE {
            h[i] = i as u8;
        }
        Ok(ComSignature(h))
    }

    pub fn verify(self, _commit: &Commitment, _msg: &Vec<u8>) -> Result<()> {
        // milestone 2 - todo
        Ok(())
    }
}

impl AsRef<[u8]> for ComSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Serializes a ComSignature to and from hex
pub mod comsig_serde {
    use super::ComSignature;
    use serde::{Deserialize, Serializer};
    use grin_util::ToHex;

    /// Serializes a ComSignature as a hex string
    pub fn serialize<S>(comsig: &ComSignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&comsig.to_hex())
    }

    /// Creates a ComSignature from a hex string
    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<ComSignature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer)
            .and_then(|string| grin_util::from_hex(&string).map_err(Error::custom))
            .and_then(|bytes: Vec<u8>| Ok(ComSignature::from_vec(bytes.to_vec())))
    }
}

/// Compute a PublicKey from a SecretKey
pub fn to_public_key(secret_key: &SecretKey) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, secret_key)?;
    Ok(pubkey)
}

/// Generate a random SecretKey. Not for production use
pub fn insecure_rand_secret() -> Result<SecretKey> {
    let secp = Secp256k1::new();
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let secret = SecretKey::from_slice(&secp, &seed)?;
    Ok(secret)
}

/// Build a Pedersen Commitment using the provided value and blinding factor
pub fn commit(value: u64, blind: &SecretKey) -> Result<Commitment> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let commit = secp.commit(value, blind.clone())?;
    Ok(commit)
}

/// Add a blinding factor to an existing Commitment
pub fn add_excess(commitment: &Commitment, excess: &SecretKey) -> Result<Commitment> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let excess_commit : Commitment = secp.commit(0, excess.clone())?;

    let commits = vec![commitment.clone(), excess_commit.clone()];
    let sum = secp.commit_sum(commits, Vec::new())?;
    Ok(sum)
}

/// secp256k1-zkp object serialization

impl Readable for Commitment {
    fn read<R: Reader>(reader: &mut R) -> Result<Commitment> {
        let a = reader.read_fixed_bytes(PEDERSEN_COMMITMENT_SIZE)?;
        let mut c = [0; PEDERSEN_COMMITMENT_SIZE];
        c[..PEDERSEN_COMMITMENT_SIZE].clone_from_slice(&a[..PEDERSEN_COMMITMENT_SIZE]);
        Ok(Commitment(c))
    }
}

impl Writeable for Commitment {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        writer.write_fixed_bytes(self)
    }
}

impl Readable for RangeProof {
    fn read<R: Reader>(reader: &mut R) -> Result<RangeProof> {
        let len = reader.read_u64()?;
        let max_len = cmp::min(len as usize, MAX_PROOF_SIZE);
        let p = reader.read_fixed_bytes(max_len)?;
        let mut proof = [0; MAX_PROOF_SIZE];
        proof[..p.len()].clone_from_slice(&p[..]);
        Ok(RangeProof {
            plen: proof.len(),
            proof,
        })
    }
}

impl Writeable for RangeProof {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        writer.write_bytes(self)
    }
}

impl Readable for Signature {
    fn read<R: Reader>(reader: &mut R) -> Result<Signature> {
        let a = reader.read_fixed_bytes(AGG_SIGNATURE_SIZE)?;
        let mut c = [0; AGG_SIGNATURE_SIZE];
        c[..AGG_SIGNATURE_SIZE].clone_from_slice(&a[..AGG_SIGNATURE_SIZE]);
        Ok(Signature::from_raw_data(&c).unwrap())
    }
}

impl Writeable for Signature {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        writer.write_fixed_bytes(self)
    }
}

impl Readable for PublicKey {
    // Read the public key in compressed form
    fn read<R: Reader>(reader: &mut R) -> Result<Self> {
        let buf = reader.read_fixed_bytes(COMPRESSED_PUBLIC_KEY_SIZE)?;
        let secp = Secp256k1::with_caps(ContextFlag::None);
        let pk = PublicKey::from_slice(&secp, &buf).map_err(|_| ErrorKind::CorruptedData)?;
        Ok(pk)
    }
}

impl Writeable for PublicKey {
    // Write the public key in compressed form
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        let secp = Secp256k1::with_caps(ContextFlag::None);
        writer.write_fixed_bytes(self.serialize_vec(&secp, true))?;
        Ok(())
    }
}

impl Readable for SecretKey {
    fn read<R: Reader>(reader: &mut R) -> Result<Self> {
        let buf = reader.read_fixed_bytes(SECRET_KEY_SIZE)?;
        let secp = Secp256k1::with_caps(ContextFlag::None);
        let pk = SecretKey::from_slice(&secp, &buf).map_err(|_| ErrorKind::CorruptedData)?;
        Ok(pk)
    }
}

impl Writeable for SecretKey {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        writer.write_fixed_bytes(self.0)?;
        Ok(())
    }
}