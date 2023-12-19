use grin_onion::crypto::dalek::DalekPublicKey;
use grin_onion::crypto::secp::SecretKey;

use core::num::NonZeroU32;
use grin_core::global::ChainTypes;
use grin_util::{file, ToHex, ZeroingString};
use grin_wallet_util::OnionV3Address;
use rand::{thread_rng, Rng};
use ring::{aead, pbkdf2};
use serde_derive::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::result::Result;
use thiserror::Error;

const GRIN_HOME: &str = ".grin";
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
	/// socket address the tor sender should bind to
	pub socks_proxy_addr: SocketAddr,
	/// foreign api address of the grin node
	pub grin_node_url: SocketAddr,
	/// path to file containing api secret for the grin node
	pub grin_node_secret_path: Option<String>,
	/// owner api address of the grin wallet
	pub wallet_owner_url: SocketAddr,
	/// path to file containing secret for the grin wallet's owner api
	pub wallet_owner_secret_path: Option<String>,
	/// public key of the previous mix/swap server (e.g. N_1 if this is N_2)
	#[serde(with = "grin_onion::crypto::dalek::option_dalek_pubkey_serde", default)]
	pub prev_server: Option<DalekPublicKey>,
	/// public key of the next mix server
	#[serde(with = "grin_onion::crypto::dalek::option_dalek_pubkey_serde", default)]
	pub next_server: Option<DalekPublicKey>,
}

impl ServerConfig {
	pub fn onion_address(&self) -> OnionV3Address {
		OnionV3Address::from_private(&self.key.0).unwrap()
	}

	pub fn server_pubkey(&self) -> DalekPublicKey {
		DalekPublicKey::from_secret(&self.key)
	}

	pub fn node_api_secret(&self) -> Option<String> {
		file::get_first_line(self.grin_node_secret_path.clone())
	}

	pub fn wallet_owner_api_secret(&self) -> Option<String> {
		file::get_first_line(self.wallet_owner_secret_path.clone())
	}
}

/// Error types for saving or loading configs
#[derive(Error, Debug)]
pub enum ConfigError {
	#[error("Error while writing config to file: {0:?}")]
	FileWriteError(std::io::Error),
	#[error("Error while encoding config as toml: {0:?}")]
	EncodingError(toml::ser::Error),
	#[error("Error while decoding toml config: {0:?}")]
	DecodingError(toml::de::Error),
	#[error("{0} not valid hex")]
	InvalidHex(String),
	#[error("Error decrypting seed: {0:?}")]
	DecryptionError(ring::error::Unspecified),
	#[error("Decrypted server key is invalid")]
	InvalidServerKey,
	#[error(
		"Unable to read server config. Perform init-config or pass in config path.\nError: {0:?}"
	)]
	ReadConfigError(std::io::Error),
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
	pub fn from_secret_key(server_key: &SecretKey, password: &ZeroingString) -> EncryptedServerKey {
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
			.unwrap();

		EncryptedServerKey {
			encrypted_key: enc_bytes.to_hex(),
			salt: salt.to_hex(),
			nonce: nonce.to_hex(),
		}
	}

	/// Decrypt the server secret key using the provided password.
	pub fn decrypt(&self, password: &str) -> Result<SecretKey, ConfigError> {
		let mut encrypted_seed = grin_util::from_hex(&self.encrypted_key.clone())
			.map_err(|_| ConfigError::InvalidHex("Seed".to_string()))?;
		let salt = grin_util::from_hex(&self.salt.clone())
			.map_err(|_| ConfigError::InvalidHex("Salt".to_string()))?;
		let nonce = grin_util::from_hex(&self.nonce.clone())
			.map_err(|_| ConfigError::InvalidHex("Nonce".to_string()))?;
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
			.map_err(|e| ConfigError::DecryptionError(e))?;

		for _ in 0..aead::AES_256_GCM.tag_len() {
			encrypted_seed.pop();
		}

		let secp = secp256k1zkp::Secp256k1::new();
		let decrypted = SecretKey::from_slice(&secp, &encrypted_seed)
			.map_err(|_| ConfigError::InvalidServerKey)?;
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
	socks_proxy_addr: SocketAddr,
	grin_node_url: SocketAddr,
	grin_node_secret_path: Option<String>,
	wallet_owner_url: SocketAddr,
	wallet_owner_secret_path: Option<String>,
	#[serde(with = "grin_onion::crypto::dalek::option_dalek_pubkey_serde", default)]
	prev_server: Option<DalekPublicKey>,
	#[serde(with = "grin_onion::crypto::dalek::option_dalek_pubkey_serde", default)]
	next_server: Option<DalekPublicKey>,
}

/// Writes the server config to the config_path given, encrypting the server_key first.
pub fn write_config(
	config_path: &PathBuf,
	server_config: &ServerConfig,
	password: &ZeroingString,
) -> Result<(), ConfigError> {
	let encrypted = EncryptedServerKey::from_secret_key(&server_config.key, &password);

	let raw_config = RawConfig {
		encrypted_key: encrypted.encrypted_key,
		salt: encrypted.salt,
		nonce: encrypted.nonce,
		interval_s: server_config.interval_s,
		addr: server_config.addr,
		socks_proxy_addr: server_config.socks_proxy_addr,
		grin_node_url: server_config.grin_node_url,
		grin_node_secret_path: server_config.grin_node_secret_path.clone(),
		wallet_owner_url: server_config.wallet_owner_url,
		wallet_owner_secret_path: server_config.wallet_owner_secret_path.clone(),
		prev_server: server_config.prev_server.clone(),
		next_server: server_config.next_server.clone(),
	};
	let encoded: String =
		toml::to_string(&raw_config).map_err(|e| ConfigError::EncodingError(e))?;

	let mut file = File::create(config_path).map_err(|e| ConfigError::FileWriteError(e))?;
	file.write_all(encoded.as_bytes())
		.map_err(|e| ConfigError::FileWriteError(e))?;

	Ok(())
}

/// Reads the server config from the config_path given and decrypts it with the provided password.
pub fn load_config(
	config_path: &PathBuf,
	password: &ZeroingString,
) -> Result<ServerConfig, ConfigError> {
	let contents = std::fs::read_to_string(config_path).map_err(ConfigError::ReadConfigError)?;
	let raw_config: RawConfig = toml::from_str(&contents).map_err(ConfigError::DecodingError)?;

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
		socks_proxy_addr: raw_config.socks_proxy_addr,
		grin_node_url: raw_config.grin_node_url,
		grin_node_secret_path: raw_config.grin_node_secret_path,
		wallet_owner_url: raw_config.wallet_owner_url,
		wallet_owner_secret_path: raw_config.wallet_owner_secret_path,
		prev_server: raw_config.prev_server,
		next_server: raw_config.next_server,
	})
}

pub fn get_grin_path(chain_type: &ChainTypes) -> PathBuf {
	let mut grin_path = match dirs::home_dir() {
		Some(p) => p,
		None => PathBuf::new(),
	};
	grin_path.push(GRIN_HOME);
	grin_path.push(chain_type.shortname());
	grin_path
}

pub fn node_secret_path(chain_type: &ChainTypes) -> PathBuf {
	let mut path = get_grin_path(chain_type);
	path.push(NODE_API_SECRET_FILE_NAME);
	path
}

pub fn wallet_owner_secret_path(chain_type: &ChainTypes) -> PathBuf {
	let mut path = get_grin_path(chain_type);
	path.push(WALLET_OWNER_API_SECRET_FILE_NAME);
	path
}

pub fn grin_node_url(chain_type: &ChainTypes) -> SocketAddr {
	if *chain_type == ChainTypes::Testnet {
		"127.0.0.1:13413".parse().unwrap()
	} else {
		"127.0.0.1:3413".parse().unwrap()
	}
}

pub fn wallet_owner_url(_chain_type: &ChainTypes) -> SocketAddr {
	"127.0.0.1:3420".parse().unwrap()
}

#[cfg(test)]
pub mod test_util {
	use crate::config::ServerConfig;
	use grin_onion::crypto::dalek::DalekPublicKey;
	use secp256k1zkp::SecretKey;
	use std::net::TcpListener;

	pub fn local_config(
		server_key: &SecretKey,
		prev_server: &Option<DalekPublicKey>,
		next_server: &Option<DalekPublicKey>,
	) -> Result<ServerConfig, Box<dyn std::error::Error>> {
		let config = ServerConfig {
			key: server_key.clone(),
			interval_s: 1,
			addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			socks_proxy_addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			grin_node_url: "127.0.0.1:3413".parse()?,
			grin_node_secret_path: None,
			wallet_owner_url: "127.0.0.1:3420".parse()?,
			wallet_owner_secret_path: None,
			prev_server: prev_server.clone(),
			next_server: next_server.clone(),
		};
		Ok(config)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use grin_onion::crypto::secp;

	#[test]
	fn server_key_encrypt() {
		let password = ZeroingString::from("password");
		let server_key = secp::random_secret();
		let mut enc_key = EncryptedServerKey::from_secret_key(&server_key, &password);
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
