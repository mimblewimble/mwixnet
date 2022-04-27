use config::ServerConfig;
use error::{Error, ErrorKind};
use node::HttpGrinNode;
use wallet::HttpWallet;

use clap::App;
use grin_util::{StopState, ZeroingString};
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

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
	if let Err(e) = real_main() {
        io::stderr().write_all(format!("mwixnet server exited with error:\n{}\n", e).as_bytes()).unwrap();
        std::process::exit(1);
    }

	std::process::exit(0);
}

fn real_main() -> std::result::Result<(), Box<dyn std::error::Error>> {
	let yml = load_yaml!("../mwixnet.yml");
	let args = App::from_yaml(yml).get_matches();
    
    let config_path = match args.value_of("config_file") {
        Some(path) => PathBuf::from(path),
        None => {
            let mut current_dir = env::current_dir()?;
            current_dir.push("mwixnet-config.toml");
            current_dir
        }
    };
    let password = args.value_of("pass").ok_or(Error::new(ErrorKind::LoadConfigError))?;
    let password = ZeroingString::from(password);

    let round_time = args.value_of("round_time").map(|t| t.parse::<u32>().unwrap() );
    let bind_addr = args.value_of("bind_addr");
    let grin_node_url = args.value_of("grin_node_url");
    let wallet_owner_url = args.value_of("wallet_owner_url");
    
    // Write a new config file if init-config command is supplied
    if let ("init-config", Some(_)) = args.subcommand() {
        if config_path.exists() {
            panic!("Config file already exists at {}", config_path.to_string_lossy());
        }

        let server_config = ServerConfig {
            key: secp::random_secret(),
            interval_s: round_time.unwrap_or(DEFAULT_INTERVAL),
            addr: bind_addr.unwrap_or("0.0.0.0:3000").parse()?,
            grin_node_url: grin_node_url.unwrap_or("127.0.0.1:3413").parse()?,
            wallet_owner_url: wallet_owner_url.unwrap_or("127.0.0.1:3420").parse()?,
        };

        config::write_config(&config_path, &server_config, &password)?;
        println!("Config file written to {:?}. Please back this file up in a safe place.", config_path);
        return Ok(());
    }

    let mut server_config = config::load_config(&config_path, &password)?;

    // Override bind_addr, if supplied
    if let Some(bind_addr) = bind_addr {
        server_config.addr = bind_addr.parse()?;
    }

    // Override grin_node_url, if supplied
    if let Some(grin_node_url) = grin_node_url {
        server_config.grin_node_url = grin_node_url.parse()?;
    }

    // Override wallet_owner_url, if supplied
    if let Some(wallet_owner_url) = wallet_owner_url {
        server_config.wallet_owner_url = wallet_owner_url.parse()?;
    }

    // Open wallet
    let wallet_pass = args.value_of("wallet_pass").ok_or(error::Error::new(error::ErrorKind::LoadConfigError))?;
    let wallet_pass = grin_util::ZeroingString::from(wallet_pass);
    let wallet = HttpWallet::open_wallet(&server_config.wallet_owner_url, &wallet_pass)?;

    // Create GrinNode
    let node = HttpGrinNode::new(&server_config.grin_node_url, &None);
    
    let stop_state = Arc::new(StopState::new());

    let stop_state_clone = stop_state.clone();
    std::thread::spawn(move || {
        let shutdown_signal = async move {
            // Wait for the CTRL+C signal
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install CTRL+C signal handler");
        };
        futures::executor::block_on(shutdown_signal);
        stop_state_clone.stop();
    });

    server::listen(&server_config, Arc::new(wallet), Arc::new(node), &stop_state)
}