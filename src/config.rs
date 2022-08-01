use crate::error::{self, Result};
use crate::secp::SecretKey;

use core::num::NonZeroU32;
use grin_util::{file, ToHex, ZeroingString};
use rand::{thread_rng, Rng};
use ring::{aead, pbkdf2};
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::path::PathBuf;

const GRIN_HOME: &str = ".grin";
const CHAIN_NAME: &str = "main";
const NODE_API_SECRET_FILE_NAME: &str = ".api_secret";
const WALLET_OWNER_API_SECRET_FILE_NAME: &str = ".owner_api_secret";

/// The decrypted server config to be passed around and used by the rest of the mwixnet code
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
	/// private key used by the server to decrypt onion packets
	pub key: SecretKey,
	/// interval (in seconds) to wait before each mixing round
	pub interval_s: u32,
	/// socket address the server listener should bind to
	pub addr: SocketAddr,
	/// foreign api address of the grin node
	pub grin_node_url: SocketAddr,
	/// path to file containing api secret for the grin node
	pub grin_node_secret_path: Option<String>,
	/// owner api address of the grin wallet
	pub wallet_owner_url: SocketAddr,
	/// path to file containing secret for the grin wallet's owner api
	pub wallet_owner_secret_path: Option<String>,
}

impl ServerConfig {
	pub fn node_api_secret(&self) -> Option<String> {
		file::get_first_line(self.grin_node_secret_path.clone())
	}

	pub fn wallet_owner_api_secret(&self) -> Option<String> {
		file::get_first_line(self.wallet_owner_secret_path.clone())
	}
}

/// Encrypted server key, for storing on disk and decrypting with a password.
/// Includes a salt used by key derivation and a nonce used when sealing the encrypted data.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct EncryptedServerKey {
	encrypted_key: String,
	salt: String,
	nonce: String,
}

impl EncryptedServerKey {
	/// Generates a random salt for pbkdf2 key derivation and a random nonce for aead sealing.
	/// Then derives an encryption key from the password and salt. Finally, it encrypts and seals
	/// the server key with chacha20-poly1305 using the derived key and random nonce.
	pub fn from_secret_key(
		server_key: &SecretKey,
		password: &ZeroingString,
	) -> Result<EncryptedServerKey> {
		let salt: [u8; 8] = thread_rng().gen();
		let password = password.as_bytes();
		let mut key = [0; 32];
		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			password,
			&mut key,
		);
		let content = server_key.0.to_vec();
		let mut enc_bytes = content;

		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let nonce: [u8; 12] = thread_rng().gen();
		let aad = aead::Aad::from(&[]);
		let _ = sealing_key
			.seal_in_place_append_tag(
				aead::Nonce::assume_unique_for_key(nonce),
				aad,
				&mut enc_bytes,
			)
			.map_err(|e| {
				error::ErrorKind::SaveConfigError(format!(
					"Failure while encrypting server key: {}",
					e
				))
			})?;

		Ok(EncryptedServerKey {
			encrypted_key: enc_bytes.to_hex(),
			salt: salt.to_hex(),
			nonce: nonce.to_hex(),
		})
	}

	/// Decrypt the server secret key using the provided password.
	pub fn decrypt(&self, password: &str) -> Result<SecretKey> {
		let mut encrypted_seed = grin_util::from_hex(&self.encrypted_key.clone())
			.map_err(|_| error::ErrorKind::LoadConfigError("Seed not valid hex".to_string()))?;
		let salt = grin_util::from_hex(&self.salt.clone())
			.map_err(|_| error::ErrorKind::LoadConfigError("Salt not valid hex".to_string()))?;
		let nonce = grin_util::from_hex(&self.nonce.clone())
			.map_err(|_| error::ErrorKind::LoadConfigError("Nonce not valid hex".to_string()))?;
		let password = password.as_bytes();
		let mut key = [0; 32];
		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			password,
			&mut key,
		);

		let mut n = [0u8; 12];
		n.copy_from_slice(&nonce[0..12]);
		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let _ = opening_key
			.open_in_place(
				aead::Nonce::assume_unique_for_key(n),
				aad,
				&mut encrypted_seed,
			)
			.map_err(|e| {
				error::ErrorKind::LoadConfigError(format!("Error decrypting seed: {}", e))
			})?;

		for _ in 0..aead::AES_256_GCM.tag_len() {
			encrypted_seed.pop();
		}

		let secp = secp256k1zkp::Secp256k1::new();
		let decrypted = SecretKey::from_slice(&secp, &encrypted_seed).map_err(|_| {
			error::ErrorKind::LoadConfigError("Decrypted key not valid".to_string())
		})?;
		Ok(decrypted)
	}
}

/// The config attributes saved to disk
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct RawConfig {
	encrypted_key: String,
	salt: String,
	nonce: String,
	interval_s: u32,
	addr: SocketAddr,
	grin_node_url: SocketAddr,
	grin_node_secret_path: Option<String>,
	wallet_owner_url: SocketAddr,
	wallet_owner_secret_path: Option<String>,
}

/// Writes the server config to the config_path given, encrypting the server_key first.
pub fn write_config(
	config_path: &PathBuf,
	server_config: &ServerConfig,
	password: &ZeroingString,
) -> Result<()> {
	let encrypted = EncryptedServerKey::from_secret_key(&server_config.key, &password)?;

	let raw_config = RawConfig {
		encrypted_key: encrypted.encrypted_key,
		salt: encrypted.salt,
		nonce: encrypted.nonce,
		interval_s: server_config.interval_s,
		addr: server_config.addr,
		grin_node_url: server_config.grin_node_url,
		grin_node_secret_path: server_config.grin_node_secret_path.clone(),
		wallet_owner_url: server_config.wallet_owner_url,
		wallet_owner_secret_path: server_config.wallet_owner_secret_path.clone(),
	};
	let encoded: String = toml::to_string(&raw_config).map_err(|e| {
		error::ErrorKind::SaveConfigError(format!("Error while encoding config as toml: {}", e))
	})?;

	let mut file = File::create(config_path)?;
	file.write_all(encoded.as_bytes()).map_err(|e| {
		error::ErrorKind::SaveConfigError(format!("Error while writing config to file: {}", e))
	})?;

	Ok(())
}

/// Reads the server config from the config_path given and decrypts it with the provided password.
pub fn load_config(config_path: &PathBuf, password: &ZeroingString) -> Result<ServerConfig> {
	let contents = std::fs::read_to_string(config_path).map_err(|e| {
		error::ErrorKind::LoadConfigError(format!(
			"Unable to read server config. Perform init-config or pass in config path.\nError: {}",
			e
		))
	})?;
	let raw_config: RawConfig =
		toml::from_str(&contents).map_err(|e| error::ErrorKind::LoadConfigError(e.to_string()))?;

	let encrypted_key = EncryptedServerKey {
		encrypted_key: raw_config.encrypted_key,
		salt: raw_config.salt,
		nonce: raw_config.nonce,
	};
	let secret_key = encrypted_key.decrypt(&password)?;

	Ok(ServerConfig {
		key: secret_key,
		interval_s: raw_config.interval_s,
		addr: raw_config.addr,
		grin_node_url: raw_config.grin_node_url,
		grin_node_secret_path: raw_config.grin_node_secret_path,
		wallet_owner_url: raw_config.wallet_owner_url,
		wallet_owner_secret_path: raw_config.wallet_owner_secret_path,
	})
}

pub fn get_grin_path() -> PathBuf {
	let mut grin_path = match dirs::home_dir() {
		Some(p) => p,
		None => PathBuf::new(),
	};
	grin_path.push(GRIN_HOME);
	grin_path.push(CHAIN_NAME);
	grin_path
}

pub fn node_secret_path() -> PathBuf {
	let mut path = get_grin_path();
	path.push(NODE_API_SECRET_FILE_NAME);
	path
}

pub fn wallet_owner_secret_path() -> PathBuf {
	let mut path = get_grin_path();
	path.push(WALLET_OWNER_API_SECRET_FILE_NAME);
	path
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::secp;

	#[test]
	fn server_key_encrypt() {
		let password = ZeroingString::from("password");
		let server_key = secp::random_secret();
		let mut enc_key = EncryptedServerKey::from_secret_key(&server_key, &password).unwrap();
		let decrypted_key = enc_key.decrypt(&password).unwrap();
		assert_eq!(server_key, decrypted_key);

		// Wrong password
		let decrypted_key = enc_key.decrypt("wrongpass");
		assert!(decrypted_key.is_err());

		// Wrong nonce
		enc_key.nonce = "wrongnonce".to_owned();
		let decrypted_key = enc_key.decrypt(&password);
		assert!(decrypted_key.is_err());
	}
}
