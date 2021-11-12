use server::ServerConfig;

#[macro_use]
extern crate lazy_static;

mod error;
mod onion;
mod secp;
mod ser;
mod server;
mod types;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_key = secp::insecure_rand_secret()?; // todo - load from encrypted key file
    let server_config = ServerConfig {
        key: secret_key,
        addr: "127.0.0.1:3000".parse().unwrap(),
        is_first: true
    };

    let shutdown_signal = async move {
        // Wait for the CTRL+C signal
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C signal handler");
    };

    server::listen(&server_config, shutdown_signal)
}