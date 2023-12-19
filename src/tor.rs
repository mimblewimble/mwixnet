use crate::config::ServerConfig;

use grin_wallet_impls::tor::config as tor_config;
use grin_wallet_impls::tor::process::TorProcess;
use std::collections::HashMap;
use thiserror::Error;

/// Tor error types
#[derive(Error, Debug)]
pub enum TorError {
	#[error("Error generating config: {0:?}")]
	ConfigError(grin_wallet_impls::Error),
	#[error("Error starting process: {0:?}")]
	ProcessError(grin_wallet_impls::tor::process::Error),
}

pub fn init_tor_listener(
	data_dir: &str,
	server_config: &ServerConfig,
) -> Result<TorProcess, TorError> {
	warn!("Initializing tor listener");

	let tor_dir = format!("{}/tor/listener", &data_dir);
	trace!(
		"Dir: {}, Proxy: {}",
		&tor_dir,
		server_config.socks_proxy_addr.to_string()
	);

	// create data directory if it doesn't exist
	std::fs::create_dir_all(&format!("{}/data", tor_dir)).unwrap();

	let service_dir = tor_config::output_onion_service_config(tor_dir.as_str(), &server_config.key)
		.map_err(|e| TorError::ConfigError(e))?;
	let service_dirs = vec![service_dir.to_string()];

	tor_config::output_torrc(
		tor_dir.as_str(),
		server_config.addr.to_string().as_str(),
		&server_config.socks_proxy_addr.to_string(),
		&service_dirs,
		HashMap::new(),
		HashMap::new(),
	)
	.map_err(|e| TorError::ConfigError(e))?;

	// Start TOR process
	let mut process = TorProcess::new();
	process
		.torrc_path("./torrc")
		.working_dir(tor_dir.as_str())
		.timeout(30)
		.completion_percent(100);

	let mut attempts = 0;
	let max_attempts = 3;
	let mut result;

	loop {
		attempts += 1;
		info!("Launching TorProcess... Attempt {}", attempts);
		result = process.launch();

		if result.is_ok() || attempts >= max_attempts {
			break;
		}
	}

	result.map_err(TorError::ProcessError)?;

	warn!(
		"Server listening at http://{}.onion",
		server_config.onion_address().to_ov3_str()
	);
	Ok(process)
}

pub fn init_tor_sender(
	data_dir: &str,
	server_config: &ServerConfig,
) -> Result<TorProcess, TorError> {
	warn!(
		"Starting TOR Process for send at {:?}",
		server_config.socks_proxy_addr
	);

	let tor_dir = format!("{}/tor/sender", data_dir);
	tor_config::output_tor_sender_config(
		tor_dir.as_str(),
		&server_config.socks_proxy_addr.to_string(),
		HashMap::new(),
		HashMap::new(),
	)
	.map_err(|e| TorError::ConfigError(e))?;

	// Start TOR process
	let mut tor_process = TorProcess::new();
	tor_process
		.torrc_path("./torrc")
		.working_dir(tor_dir.as_str())
		.timeout(40)
		.completion_percent(100)
		.launch()
		.map_err(TorError::ProcessError)?;
	Ok(tor_process)
}
