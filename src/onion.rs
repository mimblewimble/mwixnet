use crate::error::Result;
use crate::secp::{self, Commitment, PublicKey, Secp256k1, SecretKey, SharedSecret};
use crate::types::{Hop, Onion, RawBytes, Payload, deserialize_payload, serialize_payload};
use crate::ser;

use chacha20::{ChaCha20, Key, Nonce};
use chacha20::cipher::{NewCipher, StreamCipher};
use hmac::{Hmac, Mac, NewMac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Create an Onion for the Commitment, encrypting the payload for each hop
pub fn create_onion(commitment: &Commitment, session_key: &SecretKey, hops: &Vec<Hop>) -> Result<Onion> {
    let secp = Secp256k1::new();
    let mut ephemeral_key = session_key.clone();

    let mut shared_secrets: Vec<SharedSecret> = Vec::new();
    let mut enc_payloads: Vec<RawBytes> = Vec::new();
    for hop in hops {
        let shared_secret = SharedSecret::new(&secp, &hop.pubkey, &ephemeral_key);

        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_key)?;
        let blinding_factor = calc_blinding_factor(&shared_secret, &ephemeral_pubkey)?;

        shared_secrets.push(shared_secret);
        enc_payloads.push(serialize_payload(&hop.payload)?);
        ephemeral_key.mul_assign(&secp, &blinding_factor)?;
    }

    for i in (0..shared_secrets.len()).rev() {
        let mut cipher = new_stream_cipher(&shared_secrets[i])?;
        for j in i..shared_secrets.len() {
            cipher.apply_keystream(&mut enc_payloads[j]);
        }
    }

    let onion = Onion{
        ephemeral_pubkey: secp::to_public_key(&session_key)?,
        commit: commitment.clone(),
        enc_payloads: enc_payloads,
    };
    Ok(onion)
}

/// Peel a single layer off of the Onion, returning the peeled Onion and decrypted Payload
pub fn peel_layer(onion: &Onion, secret_key: &SecretKey) -> Result<(Payload, Onion)> {
    let secp = Secp256k1::new();
    
    let shared_secret = SharedSecret::new(&secp, &onion.ephemeral_pubkey, &secret_key);
    let mut cipher = new_stream_cipher(&shared_secret)?;

    let mut decrypted_bytes = onion.enc_payloads[0].clone();
    cipher.apply_keystream(&mut decrypted_bytes);
    let decrypted_payload = deserialize_payload(&decrypted_bytes)?;

    let enc_payloads : Vec<RawBytes> = onion.enc_payloads.iter()
        .enumerate()
        .filter(|&(i, _)| i != 0)
        .map(|(_, enc_payload)| {
            let mut p = enc_payload.clone();
            cipher.apply_keystream(&mut p);
            p
        })
        .collect();

    let blinding_factor = calc_blinding_factor(&shared_secret, &onion.ephemeral_pubkey)?;
    
    let mut ephemeral_pubkey = onion.ephemeral_pubkey.clone();
    ephemeral_pubkey.mul_assign(&secp, &blinding_factor)?;

    let mut commitment = onion.commit.clone();
    commitment = secp::add_excess(&commitment, &decrypted_payload.excess)?;

    let peeled_onion = Onion{
        ephemeral_pubkey: ephemeral_pubkey,
        commit: commitment.clone(),
        enc_payloads: enc_payloads,
    };
    Ok((decrypted_payload, peeled_onion))
}

fn calc_blinding_factor(shared_secret: &SharedSecret, ephemeral_pubkey: &PublicKey) -> Result<SecretKey> {
    let serialized_pubkey = ser::ser_vec(&ephemeral_pubkey)?;

    let mut hasher = Sha256::default();
    hasher.update(&serialized_pubkey);
    hasher.update(&shared_secret[0..32]);
    
    let secp = Secp256k1::new();
    let blind = SecretKey::from_slice(&secp, &hasher.finalize())?;
    Ok(blind)
}

fn new_stream_cipher(shared_secret: &SharedSecret) -> Result<ChaCha20> {
    let mut mu_hmac = HmacSha256::new_from_slice(b"PAYLOAD")?;
    mu_hmac.update(&shared_secret[0..32]);
    let mukey = mu_hmac.finalize().into_bytes();

    let key = Key::from_slice(&mukey[0..32]);
    let nonce = Nonce::from_slice(b"NONCE1234567");
    
    Ok(ChaCha20::new(&key, &nonce))
}

#[cfg(test)]
mod tests {
    use super::super::secp;
    use super::super::types;
    use super::super::onion;

    /// Test end-to-end Onion creation and unwrapping logic.
    #[test]
    fn onion() {
        let value : u64 = 1000;
        let blind = secp::insecure_rand_secret().unwrap(); 
        let commitment = secp::commit(value, &blind).unwrap();
    
        let session_key = secp::insecure_rand_secret().unwrap();
        let mut hops : Vec<types::Hop> = Vec::new();
    
        let mut keys : Vec<secp::SecretKey> = Vec::new();
        let mut final_commit = commitment.clone();
        let mut final_blind = blind.clone();
        for i in 0..5 {
            keys.push(secp::insecure_rand_secret().unwrap());
    
            let excess = secp::insecure_rand_secret().unwrap();
    
            let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
            final_blind.add_assign(&secp, &excess).unwrap();
            final_commit = secp::add_excess(&final_commit, &excess).unwrap();
            let proof = if i == 4 {
                let n1 = secp::insecure_rand_secret().unwrap();
                let rp = secp.bullet_proof(value, final_blind.clone(), n1.clone(), n1.clone(), None, None);
                assert!(secp.verify_bullet_proof(final_commit, rp, None).is_ok());
                Some(rp)
            } else {
                None
            };
    
            hops.push(types::Hop{
                pubkey: secp::PublicKey::from_secret_key(&secp, &keys[i]).unwrap(),
                payload: types::Payload{
                    excess: excess,
                    rangeproof: proof,
                }
            });
        }
    
        let mut onion_packet = onion::create_onion(&commitment, &session_key, &hops).unwrap();
    
        let mut payload = types::Payload{
            excess: secp::insecure_rand_secret().unwrap(),
            rangeproof: None
        };
        for i in 0..5 {
            let peeled = onion::peel_layer(&onion_packet, &keys[i]).unwrap();
            payload = peeled.0;
            onion_packet = peeled.1;
        }
    
        assert!(payload.rangeproof.is_some());
        assert_eq!(payload.rangeproof.unwrap(), hops[4].payload.rangeproof.unwrap());
        assert_eq!(secp::commit(value, &final_blind).unwrap(), final_commit);
    }
}