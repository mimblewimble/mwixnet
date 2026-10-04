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

use std::path::PathBuf;
use std::time::{Duration, Instant};

use arti_client::{config::TorClientConfigBuilder, TorClient};
use clap::{App, Arg};
use futures::future::join_all;
use mwixnet::tor::async_post;
use serde_json::{json, Value};
use tor_hsservice::HsId;
use tor_rtcompat::PreferredRuntime;

fn target(value: &str) -> Result<(String, String), String> {
	let (name, address) = value.split_once('=').ok_or("Expected NAME=ADDRESS.onion")?;
	if name.is_empty()
		|| !name
			.bytes()
			.all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
	{
		return Err("Use letters, numbers, '-' or '_' for the name".into());
	}
	address.parse::<HsId>().map_err(|e| e.to_string())?;
	Ok((name.into(), format!("http://{address}/v1")))
}

fn healthy(body: &str) -> bool {
	serde_json::from_str::<Value>(body).is_ok_and(|v| {
		v["jsonrpc"] == "2.0" && v["id"] == 1 && v["result"] == "ok" && v.get("error").is_none()
	})
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let args = App::new("mwixnet-monitor")
		.about("Check onion health every two minutes")
		.arg(
			Arg::with_name("data-dir")
				.long("data-dir")
				.takes_value(true)
				.required(true),
		)
		.arg(
			Arg::with_name("once")
				.long("once")
				.help("Check once and exit"),
		)
		.arg(
			Arg::with_name("target")
				.value_name("NAME=ADDRESS.onion")
				.multiple(true)
				.required(true)
				.validator(|v| target(&v).map(|_| ())),
		)
		.get_matches();
	let targets: Vec<_> = args
		.values_of("target")
		.unwrap()
		.map(|v| target(v).unwrap())
		.collect();
	let data_dir = PathBuf::from(args.value_of("data-dir").unwrap());
	let mut config =
		TorClientConfigBuilder::from_directories(data_dir.join("state"), data_dir.join("cache"));
	config.address_filter().allow_onion_addrs(true);
	eprintln!("Bootstrapping Tor");
	let client = TorClient::with_runtime(PreferredRuntime::current()?)
		.config(config.build()?)
		.create_bootstrapped()
		.await?;
	eprintln!("Tor ready");
	let mut interval = tokio::time::interval(Duration::from_secs(120));
	interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	loop {
		interval.tick().await;
		let results = join_all(targets.iter().map(|(name, url)| {
			let client = client.clone();
			async move {
				let start = Instant::now();
				let body =
					json!({"jsonrpc":"2.0", "id":1, "method":"health", "params":[]}).to_string();
				let result = async_post(client, url, body).await;
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
			}
		}))
		.await;
		if args.is_present("once") {
			return if results.into_iter().all(|ok| ok) {
				Ok(())
			} else {
				Err("Health check failed".into())
			};
		}
	}
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
