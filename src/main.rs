use config::ServerConfig;
use node::HttpGrinNode;
use wallet::HttpWallet;

use clap::App;
use grin_util::{StopState, ZeroingString};
use rpassword;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate clap;

mod config;
mod error;
mod node;
mod onion;
mod secp;
mod server;
mod types;
mod wallet;

const DEFAULT_INTERVAL: u32 = 12 * 60 * 60;

fn main() {
	real_main().unwrap();
	std::process::exit(0);
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
	let yml = load_yaml!("../mwixnet.yml");
	let args = App::from_yaml(yml).get_matches();

	let config_path = match args.value_of("config_file") {
		Some(path) => PathBuf::from(path),
		None => {
			let mut grin_path = config::get_grin_path();
			grin_path.push("mwixnet-config.toml");
			grin_path
		}
	};

	let round_time = args
		.value_of("round_time")
		.map(|t| t.parse::<u32>().unwrap());
	let bind_addr = args.value_of("bind_addr");
	let grin_node_url = args.value_of("grin_node_url");
	let grin_node_secret_path = args.value_of("grin_node_secret_path");
	let wallet_owner_url = args.value_of("wallet_owner_url");
	let wallet_owner_secret_path = args.value_of("wallet_owner_secret_path");

	// Write a new config file if init-config command is supplied
	if let ("init-config", Some(_)) = args.subcommand() {
		if config_path.exists() {
			panic!(
				"Config file already exists at {}",
				config_path.to_string_lossy()
			);
		}

		let server_config = ServerConfig {
			key: secp::random_secret(),
			interval_s: round_time.unwrap_or(DEFAULT_INTERVAL),
			addr: bind_addr.unwrap_or("0.0.0.0:3000").parse()?,
			grin_node_url: grin_node_url.unwrap_or("127.0.0.1:3413").parse()?,
			grin_node_secret_path: match grin_node_secret_path {
				Some(p) => Some(p.to_owned()),
				None => config::node_secret_path().to_str().map(|p| p.to_owned()),
			},
			wallet_owner_url: wallet_owner_url.unwrap_or("127.0.0.1:3420").parse()?,
			wallet_owner_secret_path: match wallet_owner_secret_path {
				Some(p) => Some(p.to_owned()),
				None => config::wallet_owner_secret_path()
					.to_str()
					.map(|p| p.to_owned()),
			},
		};

		let password = prompt_password_confirm();
		config::write_config(&config_path, &server_config, &password)?;
		println!(
			"Config file written to {:?}. Please back this file up in a safe place.",
			config_path
		);
		return Ok(());
	}

	let password = prompt_password();
	let mut server_config = config::load_config(&config_path, &password)?;

	// Override bind_addr, if supplied
	if let Some(bind_addr) = bind_addr {
		server_config.addr = bind_addr.parse()?;
	}

	// Override grin_node_url, if supplied
	if let Some(grin_node_url) = grin_node_url {
		server_config.grin_node_url = grin_node_url.parse()?;
	}

	// Override grin_node_secret_path, if supplied
	if let Some(grin_node_secret_path) = grin_node_secret_path {
		server_config.grin_node_secret_path = Some(grin_node_secret_path.to_owned());
	}

	// Override wallet_owner_url, if supplied
	if let Some(wallet_owner_url) = wallet_owner_url {
		server_config.wallet_owner_url = wallet_owner_url.parse()?;
	}

	// Override wallet_owner_secret_path, if supplied
	if let Some(wallet_owner_secret_path) = wallet_owner_secret_path {
		server_config.wallet_owner_secret_path = Some(wallet_owner_secret_path.to_owned());
	}

	// Open wallet
	let wallet_pass = prompt_wallet_password(&args.value_of("wallet_pass"));
	let wallet = HttpWallet::open_wallet(
		&server_config.wallet_owner_url,
		&server_config.wallet_owner_api_secret(),
		&wallet_pass,
	)?;

	// Create GrinNode
	let node = HttpGrinNode::new(
		&server_config.grin_node_url,
		&server_config.node_api_secret(),
	);

	let stop_state = Arc::new(StopState::new());
	let stop_state_clone = stop_state.clone();

	let rt = Runtime::new()?;
	rt.spawn(async move {
		futures::executor::block_on(build_signals_fut());
		stop_state_clone.stop();
	});

	// Start the mwixnet server
	server::listen(
		&server_config,
		Arc::new(wallet),
		Arc::new(node),
		&stop_state,
	)
}

async fn build_signals_fut() {
	if cfg!(unix) {
		use tokio::signal::unix::{signal, SignalKind};

		// Listen for SIGINT, SIGQUIT, and SIGTERM
		let mut terminate_signal =
			signal(SignalKind::terminate()).expect("failed to create terminate signal");
		let mut quit_signal = signal(SignalKind::quit()).expect("failed to create quit signal");
		let mut interrupt_signal =
			signal(SignalKind::interrupt()).expect("failed to create interrupt signal");

		futures::future::select_all(vec![
			Box::pin(terminate_signal.recv()),
			Box::pin(quit_signal.recv()),
			Box::pin(interrupt_signal.recv()),
		])
		.await;
	} else {
		tokio::signal::ctrl_c()
			.await
			.expect("failed to install CTRL+C signal handler");
	}
}

fn prompt_password() -> ZeroingString {
	ZeroingString::from(rpassword::prompt_password_stdout("Server password: ").unwrap())
}

fn prompt_password_confirm() -> ZeroingString {
	let mut first = "first".to_string();
	let mut second = "second".to_string();
	while first != second {
		first = rpassword::prompt_password_stdout("Server password: ").unwrap();
		second = rpassword::prompt_password_stdout("Confirm server password: ").unwrap();
	}
	ZeroingString::from(first)
}

fn prompt_wallet_password(wallet_pass: &Option<&str>) -> ZeroingString {
	match *wallet_pass {
		Some(wallet_pass) => ZeroingString::from(wallet_pass),
		None => {
			ZeroingString::from(rpassword::prompt_password_stdout("Wallet password: ").unwrap())
		}
	}
}
