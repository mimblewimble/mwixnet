// Copyright 2026 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use clap::{load_yaml, App, Error, ErrorKind};
use hyper::Uri;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use grin_p2p::tor::arti::tor_post;
use grin_p2p::tor::ov3::OnionV3Address;
use grin_p2p::tor::start_tor;
use grin_wallet_config::config::GRIN_HOME;
use mwixnet::config::{ConfigError, TorMwixnetConfig};

fn target(value: &str) -> Result<(String, String), String> {
	let (name, address) = value.split_once('=').ok_or("Expected NAME=ADDRESS.onion")?;
	if name.is_empty()
		|| !name
			.bytes()
			.all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
	{
		return Err("Use letters, numbers, '-' or '_' for the name".into());
	}
	let url: Uri = address
		.parse()
		.map_err(|e| format!("Bad url format: {}", e))?;
	let host = url.host().ok_or(format!("Bad url host for {}", address))?;
	OnionV3Address::try_from(host).map_err(|e| e.to_string())?;
	Ok((name.into(), format!("http://{host}/v1")))
}

fn healthy(body: &str) -> bool {
	serde_json::from_str::<Value>(body).is_ok_and(|v| {
		v["jsonrpc"] == "2.0" && v["id"] == 1 && v["result"] == "ok" && v.get("error").is_none()
	})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let yml = load_yaml!("mwixnet-monitor.yml");
	let args = App::from_yaml(yml).get_matches();
	let targets: Vec<_> = args
		.values_of("target")
		.unwrap()
		.map(|value| target(value).map_err(|error| format!("Invalid target '{value}': {error}")))
		.collect::<Result<_, _>>()
		.unwrap_or_else(|error| Error::with_description(&error, ErrorKind::ValueValidation).exit());

	let mut config = match args.value_of("config_file") {
		Some(path) => read_tor_config(PathBuf::from(path))?,
		None => TorMwixnetConfig::default(),
	};

	// Set Tor data path.
	let data_dir = match args.value_of("data_dir") {
		Some(value) => PathBuf::from(value),
		None => {
			let mut grin_path = dirs::home_dir().unwrap_or_default();
			grin_path.push(GRIN_HOME);
			grin_path.push("mwixnet-monitor");
			grin_path
		}
	};
	config.data_file_dir = data_dir.to_str().unwrap().into();

	eprintln!("Starting Tor");
	start_tor(&config)?;
	eprintln!("Tor started successfully");

	tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()?
		.block_on(async {
			let mut interval = tokio::time::interval(Duration::from_secs(120));
			interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
			loop {
				interval.tick().await;
				let results = targets
					.iter()
					.map(|(name, url)| {
						let start = Instant::now();
						let body = json!({"jsonrpc":"2.0", "id":1, "method":"health", "params":[]})
							.to_string();

						let mut headers = HashMap::new();
						headers.insert("accept", "application/json");
						headers.insert("content-type", "application/json");

						let result = tor_post(&config, body, Some(headers), url);
						let elapsed = start.elapsed().as_secs_f64();
						match result {
							Ok(body) if healthy(&body) => {
								println!("{name} ok {elapsed:.2}s");
								true
							}
							Ok(_) => {
								println!("{name} failed {elapsed:.2}s invalid health response");
								false
							}
							Err(error) => {
								println!(
									"{name} failed {elapsed:.2}s {}",
									error.to_string().replace(['\n', '\r'], " ")
								);
								false
							}
						}
					})
					.collect::<Vec<_>>();
				if args.is_present("once") {
					return if results.into_iter().all(|ok| ok) {
						Ok::<(), Box<dyn std::error::Error>>(())
					} else {
						Err("Health check failed".into())
					};
				}
			}
		})?;
	Ok(())
}

/// The config attributes saved to disk
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct RawConfig {
	tor: Option<TorMwixnetConfig>,
}

fn read_tor_config(config_path: PathBuf) -> Result<TorMwixnetConfig, ConfigError> {
	let contents = std::fs::read_to_string(config_path).map_err(ConfigError::ReadConfigError)?;
	let raw_config: RawConfig = toml::from_str(&contents).map_err(ConfigError::DecodingError)?;
	Ok(raw_config.tor.unwrap_or_default())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn targets() {
		let onion = "mza3u6vkqodqc6kjjapfbcjrg7hgpkuw6nyq5xvfjqp5jm2lfeaocwqd.onion";
		assert_eq!(
			target(&format!("swap={onion}")).unwrap(),
			("swap".into(), format!("http://{onion}/v1"))
		);
		for value in [
			"swap",
			"swap=localhost",
			"swap=example.com",
			&format!("={onion}"),
			&format!("swap\n={onion}"),
		] {
			assert!(target(value).is_err());
		}
	}

	#[test]
	fn responses() {
		assert!(healthy(r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#));
		for body in [
			"not json",
			r#"{"result":"ok"}"#,
			r#"{"jsonrpc":"2.0","id":2,"result":"ok"}"#,
			r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}"#,
			r#"{"jsonrpc":"2.0","id":1,"result":"ok","error":null}"#,
		] {
			assert!(!healthy(body));
		}
	}
}
