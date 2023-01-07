use crate::config::{self, ServerConfig};

use grin_core::global;
use grin_wallet_impls::tor::config as tor_config;
use grin_wallet_impls::tor::process::TorProcess;
use std::collections::HashMap;
use thiserror::Error;

/// Tor error types
#[derive(Error, Debug)]
pub enum TorError {
	#[error("Error generating config: {0:?}")]
	ConfigError(String),
	#[error("Error starting process: {0:?}")]
	ProcessError(grin_wallet_impls::tor::process::Error),
}

pub fn init_tor_listener(server_config: &ServerConfig) -> Result<TorProcess, TorError> {
	println!("Initializing tor listener");

	let mut tor_dir = config::get_grin_path(&global::get_chain_type());
	tor_dir.push("tor/listener");

	let mut torrc_dir = tor_dir.clone();
	torrc_dir.push("torrc");

	tor_config::output_tor_listener_config(
		tor_dir.to_str().unwrap(),
		server_config.addr.to_string().as_str(),
		&vec![server_config.key.clone()],
		HashMap::new(),
		HashMap::new(),
	)
	.map_err(|e| TorError::ConfigError(e.to_string()))?;

	// Start TOR process
	let mut process = TorProcess::new();
	process
		.torrc_path(torrc_dir.to_str().unwrap())
		.working_dir(tor_dir.to_str().unwrap())
		.timeout(20)
		.completion_percent(100)
		.launch()
		.map_err(TorError::ProcessError)?;

	println!(
		"Server listening at http://{}.onion",
		server_config.onion_address().to_ov3_str()
	);
	Ok(process)
}

pub fn init_tor_sender(server_config: &ServerConfig) -> Result<TorProcess, TorError> {
	println!(
		"Starting TOR Process for send at {:?}",
		server_config.socks_proxy_addr
	);

	let mut tor_dir = config::get_grin_path(&global::get_chain_type());
	tor_dir.push("tor/sender");

	let mut torrc_dir = tor_dir.clone();
	torrc_dir.push("torrc");

	tor_config::output_tor_sender_config(
		tor_dir.to_str().unwrap(),
		&server_config.socks_proxy_addr.to_string(),
		HashMap::new(),
		HashMap::new(),
	)
	.map_err(|e| TorError::ConfigError(e.to_string()))?;

	// Start TOR process
	let mut tor_process = TorProcess::new();
	tor_process
		.torrc_path(torrc_dir.to_str().unwrap())
		.working_dir(tor_dir.to_str().unwrap())
		.timeout(20)
		.completion_percent(100)
		.launch()
		.map_err(TorError::ProcessError)?;
	Ok(tor_process)
}
