use core::num::NonZeroU32;
use std::fs::File;
use std::io::prelude::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::result::Result;

use grin_core::global::ChainTypes;
use grin_util::{file, ToHex, ZeroingString};
use grin_wallet_util::OnionV3Address;
use rand::{thread_rng, Rng};
use ring::{aead, pbkdf2};
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

use grin_onion::crypto::dalek::DalekPublicKey;
use grin_onion::crypto::secp::SecretKey;
use grin_wallet_libwallet::mwixnet::{onion as grin_onion, MwixnetServerPublicKey};

const GRIN_HOME: &str = ".grin";
const NODE_FOREIGN_API_SECRET_FILE_NAME: &str = ".foreign_api_secret";
const WALLET_OWNER_API_SECRET_FILE_NAME: &str = ".owner_api_secret";
/// Default minimum Tor circuit build timeout in milliseconds.
pub const DEFAULT_MIN_CIRCUIT_TIMEOUT_MS: i32 = 2_000;
const CONFIG_HEADER: &str = "\
# MWixnet server configuration
# Wallet clients use the ordered X25519 onion keys printed at server startup.
";

fn default_min_circuit_timeout_ms() -> i32 {
	DEFAULT_MIN_CIRCUIT_TIMEOUT_MS
}

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
	pub grin_node_url: String,
	/// path to file containing the secret for the Grin node foreign API
	pub grin_node_foreign_api_secret_path: Option<String>,
	/// owner api address of the grin wallet
	pub wallet_owner_url: String,
	/// path to file containing secret for the grin wallet's owner api
	pub wallet_owner_secret_path: Option<String>,
	/// whether to collect excess hop fees in the server wallet
	pub collect_fees: bool,
	/// minimum Tor circuit build timeout in milliseconds
	#[serde(default = "default_min_circuit_timeout_ms")]
	pub min_circuit_timeout_ms: i32,
	/// Ed25519 identity key of the previous mix/swap server (e.g. N_1 if this is N_2)
	#[serde(with = "grin_onion::crypto::dalek::option_dalek_pubkey_serde", default)]
	pub prev_server: Option<DalekPublicKey>,
	/// Ed25519 identity key of the next mix server
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

	pub fn onion_pubkey(&self) -> MwixnetServerPublicKey {
		MwixnetServerPublicKey::from_secret(&self.key)
	}

	pub fn node_foreign_api_secret(&self) -> Option<String> {
		file::get_first_line(self.grin_node_foreign_api_secret_path.clone())
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
	grin_node_url: String,
	grin_node_foreign_api_secret_path: Option<String>,
	wallet_owner_url: String,
	wallet_owner_secret_path: Option<String>,
	collect_fees: bool,
	#[serde(default = "default_min_circuit_timeout_ms")]
	min_circuit_timeout_ms: i32,
	#[serde(with = "grin_onion::crypto::dalek::option_dalek_pubkey_serde", default)]
	prev_server: Option<DalekPublicKey>,
	#[serde(with = "grin_onion::crypto::dalek::option_dalek_pubkey_serde", default)]
	next_server: Option<DalekPublicKey>,
}

fn config_comment(key: &str) -> Option<&'static str> {
	match key {
		"encrypted_key" => Some("Encrypted server identity and onion secret key."),
		"salt" => Some("Salt used to derive the server-key encryption key."),
		"nonce" => Some("Nonce used to encrypt the server key."),
		"interval_s" => Some("Seconds between mixing rounds."),
		"addr" => Some("Local RPC bind address, also exposed by the Tor onion service."),
		"grin_node_url" => Some("Grin node HTTP(S) URL or address."),
		"grin_node_foreign_api_secret_path" => Some("Path to the Grin node foreign API secret."),
		"wallet_owner_url" => Some("Wallet Owner API address used for fee collection."),
		"wallet_owner_secret_path" => Some("Path to the wallet Owner API secret."),
		"collect_fees" => {
			Some("Collect excess hop fees in the wallet; false pays all hop fees to miners.")
		}
		"min_circuit_timeout_ms" => Some("Minimum Tor circuit build timeout in milliseconds."),
		"prev_server" => {
			Some("Previous server Ed25519 identity key; setting it makes this server a mixer.")
		}
		"next_server" => Some("Next server Ed25519 identity key; leave unset for the final hop."),
		_ => None,
	}
}

fn documented_config(raw_config: &RawConfig) -> Result<String, ConfigError> {
	let config = toml::to_string(raw_config).map_err(ConfigError::EncodingError)?;
	let mut encoded = CONFIG_HEADER.trim_end().to_string();

	for line in config.lines() {
		if let Some((key, _)) = line.split_once('=') {
			if let Some(comment) = config_comment(key.trim()) {
				encoded.push_str("\n\n# ");
				encoded.push_str(comment);
			}
		}
		encoded.push('\n');
		encoded.push_str(line);
	}
	encoded.push('\n');

	if raw_config.prev_server.is_none() {
		encoded.push_str(
			"\n# Previous server Ed25519 identity key; setting it makes this server a mixer.\n",
		);
		encoded.push_str("# prev_server = \"<previous server Ed25519 identity key>\"\n");
	}
	if raw_config.next_server.is_none() {
		encoded.push_str("\n# Next server Ed25519 identity key; leave unset for the final hop.\n");
		encoded.push_str("# next_server = \"<next server Ed25519 identity key>\"\n");
	}

	Ok(encoded)
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
		grin_node_url: server_config.grin_node_url.clone(),
		grin_node_foreign_api_secret_path: server_config.grin_node_foreign_api_secret_path.clone(),
		wallet_owner_url: server_config.wallet_owner_url.clone(),
		wallet_owner_secret_path: server_config.wallet_owner_secret_path.clone(),
		collect_fees: server_config.collect_fees,
		min_circuit_timeout_ms: server_config.min_circuit_timeout_ms,
		prev_server: server_config.prev_server.clone(),
		next_server: server_config.next_server.clone(),
	};
	let encoded = documented_config(&raw_config)?;

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
		grin_node_url: raw_config.grin_node_url,
		grin_node_foreign_api_secret_path: raw_config.grin_node_foreign_api_secret_path,
		wallet_owner_url: raw_config.wallet_owner_url,
		wallet_owner_secret_path: raw_config.wallet_owner_secret_path,
		collect_fees: raw_config.collect_fees,
		min_circuit_timeout_ms: raw_config.min_circuit_timeout_ms,
		prev_server: raw_config.prev_server,
		next_server: raw_config.next_server,
	})
}

pub fn get_grin_path(chain_type: &ChainTypes) -> PathBuf {
	let mut grin_path = dirs::home_dir().unwrap_or_else(|| PathBuf::new());
	grin_path.push(GRIN_HOME);
	grin_path.push(chain_type.shortname());
	grin_path
}

pub fn node_foreign_api_secret_path(chain_type: &ChainTypes) -> PathBuf {
	let mut path = get_grin_path(chain_type);
	path.push(NODE_FOREIGN_API_SECRET_FILE_NAME);
	path
}

pub fn wallet_owner_secret_path(chain_type: &ChainTypes) -> PathBuf {
	let mut path = get_grin_path(chain_type);
	path.push(WALLET_OWNER_API_SECRET_FILE_NAME);
	path
}

pub fn grin_node_url(chain_type: &ChainTypes) -> String {
	if *chain_type == ChainTypes::Testnet {
		"127.0.0.1:13413".into()
	} else {
		"127.0.0.1:3413".into()
	}
}

pub fn wallet_owner_url(_chain_type: &ChainTypes) -> String {
	"127.0.0.1:3420".into()
}

#[cfg(test)]
pub mod test_util {
	use super::grin_onion;
	use std::net::TcpListener;

	use grin_onion::crypto::dalek::DalekPublicKey;
	use secp256k1zkp::SecretKey;

	use crate::config::{ServerConfig, DEFAULT_MIN_CIRCUIT_TIMEOUT_MS};

	pub fn local_config(
		server_key: &SecretKey,
		prev_server: &Option<DalekPublicKey>,
		next_server: &Option<DalekPublicKey>,
	) -> Result<ServerConfig, Box<dyn std::error::Error>> {
		let config = ServerConfig {
			key: server_key.clone(),
			interval_s: 1,
			addr: TcpListener::bind("127.0.0.1:0")?.local_addr()?,
			grin_node_url: "127.0.0.1:3413".parse()?,
			grin_node_foreign_api_secret_path: None,
			wallet_owner_url: "127.0.0.1:3420".parse()?,
			wallet_owner_secret_path: None,
			collect_fees: true,
			min_circuit_timeout_ms: DEFAULT_MIN_CIRCUIT_TIMEOUT_MS,
			prev_server: prev_server.clone(),
			next_server: next_server.clone(),
		};
		Ok(config)
	}
}

#[cfg(test)]
mod tests {
	use super::grin_onion;
	use grin_onion::crypto::secp;

	use super::*;

	#[test]
	fn server_key_encrypt() {
		let password = ZeroingString::from("password");
		let server_key = secp::random_secret(false);
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

	#[test]
	fn onion_pubkey() {
		let server_key = secp::SecretKey::from_slice(
			&secp::Secp256k1::new(),
			&grin_util::from_hex(
				"a129111d283b13bf93957c06bf6605c3417b4b89db4b5cb2e7dab2c15e36e0a4",
			)
			.unwrap(),
		)
		.unwrap();
		let config = test_util::local_config(&server_key, &None, &None).unwrap();

		assert_eq!(
			config.onion_pubkey().to_hex(),
			"96ced236bdf1aca722ef68b818445755e6ed4bacf23e19d7b71c43efc5f0077b"
		);
	}

	#[test]
	fn uses_node_foreign_api_secret_path() {
		let path = node_foreign_api_secret_path(&ChainTypes::Testnet);
		assert_eq!(path.file_name().unwrap(), ".foreign_api_secret");
	}

	#[test]
	fn writes_config_help() {
		let server_key = secp::random_secret(false);
		let config = test_util::local_config(&server_key, &None, &None).unwrap();
		let password = ZeroingString::from("password");
		let path =
			std::env::temp_dir().join(format!("mwixnet-config-{}.toml", thread_rng().gen::<u64>()));

		write_config(&path, &config, &password).unwrap();
		let contents = std::fs::read_to_string(&path).unwrap();
		let loaded = load_config(&path, &password).unwrap();
		std::fs::write(
			&path,
			contents.replace("min_circuit_timeout_ms = 2000\n", ""),
		)
		.unwrap();
		let legacy_loaded = load_config(&path, &password).unwrap();
		std::fs::remove_file(path).unwrap();

		assert!(contents.contains("# Seconds between mixing rounds.\ninterval_s ="));
		assert!(contents.contains("interval_s = 1\n\n# Local RPC bind address"));
		assert!(contents.contains(
			"# Collect excess hop fees in the wallet; false pays all hop fees to miners.\ncollect_fees ="
		));
		assert!(contents.contains(
			"# Minimum Tor circuit build timeout in milliseconds.\nmin_circuit_timeout_ms = 2000"
		));
		assert!(contents.contains(
			"# Previous server Ed25519 identity key; setting it makes this server a mixer.\n# prev_server ="
		));
		assert!(contents.contains(
			"# Next server Ed25519 identity key; leave unset for the final hop.\n# next_server ="
		));
		assert_eq!(loaded, config);
		assert_eq!(
			legacy_loaded.min_circuit_timeout_ms,
			DEFAULT_MIN_CIRCUIT_TIMEOUT_MS
		);
	}
}
