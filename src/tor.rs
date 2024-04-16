use std::sync::Arc;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use arti_hyper::ArtiHttpConnector;
use curve25519_dalek::digest::Digest;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use futures::task::SpawnExt;
use sha2::Sha512;
use thiserror::Error;
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsrproxy::config::{
	Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{
	HsIdKeypairSpecifier, HsIdPublicKeySpecifier, HsNickname, RunningOnionService,
};
use tor_keymgr::key_specifier_derive::internal;
use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder, KeystoreSelector};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_rtcompat::Runtime;

use secp256k1zkp::SecretKey;

use crate::config::ServerConfig;

/// Tor error types
#[derive(Error, Debug)]
pub enum TorError {
	#[error("Error generating config: {0:?}")]
	ConfigError(grin_wallet_impls::Error),
	#[error("Error starting process: {0:?}")]
	ProcessError(grin_wallet_impls::tor::process::Error),
}

pub struct TorService<R: Runtime> {
	tor_client: Option<TorClient<R>>,
	hidden_services: Vec<Arc<RunningOnionService>>,
}

impl<R: Runtime> TorService<R> {
	/// Builds a hyper::Client with an ArtiHttpConnector over the TorClient.
	/// The returned Client makes HTTP requests through the TorClient directly, eliminating the need for a socks proxy.
	pub fn new_hyper_client(
		&self,
	) -> hyper::Client<ArtiHttpConnector<R, TlsConnector>, hyper::Body> {
		let tls_connector = TlsConnector::builder().unwrap().build().unwrap();
		let tor_connector = ArtiHttpConnector::new(self.tor_client.clone().unwrap(), tls_connector);

		hyper::Client::builder().build::<_, hyper::Body>(tor_connector)
	}

	pub fn stop(&mut self) {
		self.tor_client = None;
		self.hidden_services.clear();
	}
}

pub async fn async_init_tor<R>(
	runtime: R,
	data_dir: &str,
	server_config: &ServerConfig,
) -> Result<TorService<R>, TorError>
where
	R: Runtime,
{
	warn!("Initializing TOR");

	let state_dir = format!("{}/tor/state", &data_dir);
	let cache_dir = format!("{}/tor/cache", &data_dir);
	let hs_nickname = HsNickname::new("listener".to_string()).unwrap();

	let mut client_config_builder =
		TorClientConfigBuilder::from_directories(state_dir.clone(), cache_dir.clone());
	client_config_builder
		.address_filter()
		.allow_onion_addrs(true);
	let client_config = client_config_builder.build().unwrap();

	add_key_to_store(&client_config, &state_dir, &server_config.key, &hs_nickname)?;
	let tor_client = TorClient::with_runtime(runtime)
		.config(client_config)
		.create_bootstrapped()
		.await
		.unwrap();

	let service =
		async_launch_hidden_service(hs_nickname.clone(), &tor_client, &server_config).await?;
	let tor_instance = TorService {
		tor_client: Some(tor_client),
		hidden_services: vec![service],
	};
	Ok(tor_instance)
}

async fn async_launch_hidden_service<R>(
	hs_nickname: HsNickname,
	tor_client: &TorClient<R>,
	server_config: &ServerConfig,
) -> Result<Arc<RunningOnionService>, TorError>
where
	R: Runtime,
{
	let svc_cfg = OnionServiceConfigBuilder::default()
		.nickname(hs_nickname.clone())
		.build()
		.unwrap();

	let (service, request_stream) = tor_client.launch_onion_service(svc_cfg).unwrap();

	let proxy_rule = ProxyRule::new(
		ProxyPattern::one_port(80).unwrap(),
		ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(server_config.addr)),
	);
	let mut proxy_cfg_builder = ProxyConfigBuilder::default();
	proxy_cfg_builder.set_proxy_ports(vec![proxy_rule]);
	let proxy = OnionServiceReverseProxy::new(proxy_cfg_builder.build().unwrap());

	{
		let proxy = proxy.clone();
		let runtime_clone = tor_client.runtime().clone();
		tor_client
			.runtime()
			.spawn(async move {
				match proxy
					.handle_requests(runtime_clone, hs_nickname.clone(), request_stream)
					.await
				{
					Ok(()) => {
						debug!("Onion service {} exited cleanly.", hs_nickname);
					}
					Err(e) => {
						warn!("Onion service {} exited with an error: {}", hs_nickname, e);
					}
				}
			})
			.unwrap();
	}

	warn!(
		"Server listening at http://{}.onion",
		server_config.onion_address().to_ov3_str()
	);
	Ok(service)
}

// TODO: Add proper error handling
fn add_key_to_store(
	tor_config: &TorClientConfig,
	state_dir: &String,
	secret_key: &SecretKey,
	hs_nickname: &HsNickname,
) -> Result<(), TorError> {
	let key_store_dir = format!("{}/keystore", &state_dir);
	let arti_store =
		ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, &tor_config.fs_mistrust())
			.unwrap();
	info!("Using keystore from {key_store_dir:?}");

	let key_manager = KeyMgrBuilder::default()
		.default_store(Box::new(arti_store))
		.build()
		.map_err(|_| internal!("failed to build keymgr"))
		.unwrap();

	let expanded_sk = ExpandedSecretKey::from_bytes(
		Sha512::default()
			.chain_update(secret_key)
			.finalize()
			.as_ref(),
	);

	let mut sk_bytes = [0_u8; 64];
	sk_bytes[0..32].copy_from_slice(&expanded_sk.scalar.to_bytes());
	sk_bytes[32..64].copy_from_slice(&expanded_sk.hash_prefix);
	let expanded_kp = ExpandedKeypair::from_secret_key_bytes(sk_bytes).unwrap();

	key_manager
		.insert(
			HsIdKey::from(expanded_kp.public().clone()),
			&HsIdPublicKeySpecifier::new(hs_nickname.clone()),
			KeystoreSelector::Default,
		)
		.unwrap();

	key_manager
		.insert(
			HsIdKeypair::from(expanded_kp),
			&HsIdKeypairSpecifier::new(hs_nickname.clone()),
			KeystoreSelector::Default,
		)
		.unwrap();

	Ok(())
}
