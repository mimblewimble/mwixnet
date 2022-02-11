pub use secp256k1zkp::{ContextFlag, Message, Secp256k1, Signature};
pub use secp256k1zkp::aggsig;
pub use secp256k1zkp::ecdh::SharedSecret;
pub use secp256k1zkp::pedersen::{Commitment, RangeProof};
pub use secp256k1zkp::key::{PublicKey, SecretKey, ZERO_KEY};
pub use secp256k1zkp::constants::{AGG_SIGNATURE_SIZE, COMPRESSED_PUBLIC_KEY_SIZE, MAX_PROOF_SIZE, PEDERSEN_COMMITMENT_SIZE, SECRET_KEY_SIZE};

use crate::ser::{self, Readable, Reader, Writeable, Writer};
use crate::error::{Error, ErrorKind, Result};

use blake2::blake2b::Blake2b;
use byteorder::{BigEndian, ByteOrder};
use secp256k1zkp::rand::thread_rng;
use std::cmp;

/// A generalized Schnorr signature with a pedersen commitment value & blinding factors as the keys
pub struct ComSignature {
    pub pub_nonce: Commitment,
    pub s: SecretKey,
    pub t: SecretKey,
}

impl ComSignature {
    pub fn new(pub_nonce: &Commitment, s: &SecretKey, t: &SecretKey) -> ComSignature {
        ComSignature {
            pub_nonce: pub_nonce.clone(),
            s: s.clone(),
            t: t.clone(),
        }
    }

    #[allow(dead_code)]
    pub fn sign(amount: u64, blind: &SecretKey, msg: &Vec<u8>) -> Result<ComSignature> {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

		let mut amt_bytes = [0; 32];
		BigEndian::write_u64(&mut amt_bytes[24..31], amount);
        let k_amt = SecretKey::from_slice(&secp, &amt_bytes)?;
        
        let k_1 = SecretKey::new(&secp, &mut thread_rng());
        let k_2 = SecretKey::new(&secp, &mut thread_rng());

        let commitment = secp.commit(amount, blind.clone())?;
        let nonce_commitment = secp.commit_blind(k_1.clone(), k_2.clone())?;

        let e = ComSignature::calc_challenge(&secp, &commitment, &nonce_commitment, &msg)?;

        // s = k_1 + (e * amount)
        let mut s = k_amt.clone();
        s.mul_assign(&secp, &e)?;
        s.add_assign(&secp, &k_1)?;

        // t = k_2 + (e * blind)
        let mut t = blind.clone();
        t.mul_assign(&secp, &e)?;
        t.add_assign(&secp, &k_2)?;

        Ok(ComSignature::new(&nonce_commitment, &s, &t))
    }

    #[allow(non_snake_case)]
    pub fn verify(&self, commit: &Commitment, msg: &Vec<u8>) -> Result<()> {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);

        let S1 = secp.commit_blind(self.s.clone(), self.t.clone())?;

        let mut Ce = commit.to_pubkey(&secp)?;
        let e = ComSignature::calc_challenge(&secp, &commit, &self.pub_nonce, &msg)?;
        Ce.mul_assign(&secp, &e)?;

        let commits = vec![Commitment::from_pubkey(&secp, &Ce)?, self.pub_nonce.clone()];
        let S2 = secp.commit_sum(commits, Vec::new())?;

        if S1 == S2 {
            return Err(Error::new(ErrorKind::InvalidSigError));
        }

        Ok(())
    }

    fn calc_challenge(secp: &Secp256k1, commit: &Commitment, nonce_commit: &Commitment, msg: &Vec<u8>) -> Result<SecretKey> {
        let mut challenge_hasher = Blake2b::new(32);
        challenge_hasher.update(&commit.0);
        challenge_hasher.update(&nonce_commit.0);
        challenge_hasher.update(msg);

		let mut challenge = [0; 32];
		challenge.copy_from_slice(challenge_hasher.finalize().as_bytes());

        Ok(SecretKey::from_slice(&secp, &challenge)?)
    }
}

/// Serializes a ComSignature to and from hex
pub mod comsig_serde {
    use super::ComSignature;
    use super::ser::{self, BinReader, Readable};
    use serde::{Deserialize, Serializer};
    use std::io::Cursor;
    use grin_util::ToHex;

    /// Serializes a ComSignature as a hex string
    pub fn serialize<S>(comsig: &ComSignature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;
        let bytes = ser::ser_vec(&comsig).map_err(Error::custom)?;
        serializer.serialize_str(&bytes.to_hex())
    }

    /// Creates a ComSignature from a hex string
    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<ComSignature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = String::deserialize(deserializer)
            .and_then(|string| grin_util::from_hex(&string).map_err(Error::custom))?;
        
        let mut cursor = Cursor::new(&bytes);
        let mut reader = BinReader::new(&mut cursor);
        ComSignature::read(&mut reader).map_err(Error::custom)
    }
}

/// Compute a PublicKey from a SecretKey
pub fn to_public_key(secret_key: &SecretKey) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, secret_key)?;
    Ok(pubkey)
}

/// Generate a random SecretKey.
pub fn random_secret() -> SecretKey {
    let secp = Secp256k1::new();
    SecretKey::new(&secp, &mut thread_rng())
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

pub fn sub_value(commitment: &Commitment, value: u64) -> Result<Commitment> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let neg_commit : Commitment = secp.commit(value, ZERO_KEY)?;
    let sum = secp.commit_sum(vec![commitment.clone()], vec![neg_commit.clone()])?;
    Ok(sum)
}

pub fn add_blinds(excesses: &Vec<SecretKey>) -> Result<SecretKey> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let sum = secp.blind_sum(excesses.clone(), Vec::new())?;
    Ok(sum)
}

pub fn sub_blinds(minuend: &SecretKey, subtrahend: &SecretKey) -> Result<SecretKey> {
    let secp = Secp256k1::with_caps(ContextFlag::Commit);
    let result = secp.blind_sum(vec![minuend.clone()], vec![subtrahend.clone()])?;
    Ok(result)
}

pub fn sign(sk: &SecretKey, msg: &Message) -> Result<Signature> {
    let secp = Secp256k1::with_caps(ContextFlag::Full);
    let pubkey = PublicKey::from_secret_key(&secp, &sk)?;
    let sig = aggsig::sign_single(&secp, &msg, &sk, None, None, None, Some(&pubkey), None)?;
    Ok(sig)
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

#[allow(non_snake_case)]
impl Readable for ComSignature {
    fn read<R: Reader>(reader: &mut R) -> Result<ComSignature> {
        let R = Commitment::read(reader)?;
        let s = SecretKey::read(reader)?;
        let t = SecretKey::read(reader)?;
        Ok(ComSignature::new(&R, &s, &t))
    }
}

impl Writeable for ComSignature {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        writer.write_fixed_bytes(self.pub_nonce.0)?;
        writer.write_fixed_bytes(self.s.0)?;
        writer.write_fixed_bytes(self.t.0)
    }
}