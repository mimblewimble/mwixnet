use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use curve25519_dalek::digest::Digest;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use futures::{task::SpawnExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use sha2::Sha512;
use thiserror::Error;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsrproxy::config::{
	Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::status::{Problem as OnionServiceProblem, State as OnionServiceState};
use tor_hsservice::{
	HsId, HsIdKeypairSpecifier, HsIdPublicKeySpecifier, HsNickname, RunningOnionService,
};
use tor_keymgr::key_specifier_derive::internal;
use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder, KeystoreSelector};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_rtcompat::{Runtime, SleepProviderExt, ToplevelBlockOn};

use secp256k1zkp::SecretKey;

use crate::config::ServerConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

fn set_timeout_floor(config: &mut TorClientConfigBuilder, timeout_ms: i32) {
	config
		.override_net_params()
		.insert("cbtmintimeout".into(), timeout_ms);
}

/// Tor error types
#[derive(Error, Debug)]
pub enum TorError {
	#[error("Error generating config: {0:?}")]
	ConfigError(grin_wallet_impls::Error),
	#[error("Error starting process: {0:?}")]
	ProcessError(grin_wallet_impls::tor::process::Error),
	#[error("Tor request failed: {0}")]
	RequestError(String),
	#[error("Tor request timed out")]
	RequestTimeout,
	#[error("Tor request returned HTTP status {0}")]
	ResponseStatusError(hyper::StatusCode),
}

pub struct TorService<R: Runtime> {
	tor_client: Option<Arc<TorClient<R>>>,
	hidden_service: Option<Arc<RunningOnionService>>,
	proxy: Option<Arc<OnionServiceReverseProxy>>,
	proxy_worker: Option<JoinHandle<()>>,
}

impl<R: Runtime> TorService<R> {
	/// Returns the Tor client used for direct asynchronous connections.
	///
	/// This replaces the former `new_hyper_client` API.
	pub fn client(&self) -> Option<Arc<TorClient<R>>> {
		self.tor_client.clone()
	}

	pub fn stop(&mut self) -> Result<(), TorError> {
		if let Some(proxy) = self.proxy.take() {
			proxy.shutdown();
		}
		self.proxy_worker
			.take()
			.map(|worker| worker.join())
			.transpose()
			.map_err(|_| TorError::RequestError("Onion proxy thread panicked".into()))?;
		self.hidden_service = None;
		self.tor_client = None;
		Ok(())
	}
}

pub async fn async_init_tor<R>(
	runtime: R,
	data_dir: &str,
	server_config: &ServerConfig,
) -> Result<TorService<R>, TorError>
where
	R: Runtime + ToplevelBlockOn,
{
	info!("Initializing Tor client");

	let state_dir = format!("{}/tor/state", &data_dir);
	let cache_dir = format!("{}/tor/cache", &data_dir);
	let onion_address = server_config.onion_address().to_string();
	let hs_nickname = HsNickname::new(onion_address.clone())
		.map_err(|error| TorError::RequestError(format!("Invalid Onion nickname: {error}")))?;
	let mut client_config_builder =
		TorClientConfigBuilder::from_directories(state_dir.clone(), cache_dir.clone());
	set_timeout_floor(
		&mut client_config_builder,
		server_config.min_circuit_timeout_ms,
	);
	client_config_builder
		.address_filter()
		.allow_onion_addrs(true);
	let client_config = client_config_builder.build().unwrap();

	add_key_to_store(&client_config, &state_dir, &server_config.key, &hs_nickname)?;
	let tor_client = TorClient::with_runtime(runtime)
		.config(client_config)
		.create_bootstrapped()
		.await
		.map_err(|error| {
			TorError::RequestError(format!("Tor bootstrap failed: {}", error_chain(&error)))
		})?;

	let (service, proxy, proxy_worker) =
		async_launch_hidden_service(hs_nickname.clone(), &tor_client, server_config).await?;
	spawn_status_logger(tor_client.runtime(), &service, onion_address)?;
	let tor_instance = TorService {
		tor_client: Some(tor_client),
		hidden_service: Some(service),
		proxy: Some(proxy),
		proxy_worker: Some(proxy_worker),
	};
	Ok(tor_instance)
}

async fn async_launch_hidden_service<R>(
	hs_nickname: HsNickname,
	tor_client: &TorClient<R>,
	server_config: &ServerConfig,
) -> Result<
	(
		Arc<RunningOnionService>,
		Arc<OnionServiceReverseProxy>,
		JoinHandle<()>,
	),
	TorError,
>
where
	R: Runtime + ToplevelBlockOn,
{
	let svc_cfg = OnionServiceConfigBuilder::default()
		.nickname(hs_nickname.clone())
		.build()
		.unwrap();

	let (service, request_stream) = tor_client
		.launch_onion_service(svc_cfg)
		.map_err(|error| TorError::RequestError(error_chain(&error)))?
		.ok_or_else(|| TorError::RequestError("Can not launch onion service".into()))?;

	let proxy_rule = ProxyRule::new(
		ProxyPattern::one_port(80).unwrap(),
		ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(server_config.addr)),
	);
	let mut proxy_cfg_builder = ProxyConfigBuilder::default();
	proxy_cfg_builder.set_proxy_ports(vec![proxy_rule]);
	let proxy = OnionServiceReverseProxy::new(proxy_cfg_builder.build().unwrap());
	let expected_address = format!("{}.onion", server_config.onion_address().to_ov3_str());
	let expected_address: HsId = expected_address
		.parse()
		.map_err(|error| TorError::RequestError(format!("Invalid Onion identity: {error}")))?;

	let worker = {
		let proxy = proxy.clone();
		let runtime = tor_client.runtime().clone();
		thread::spawn(move || {
			runtime.clone().block_on(async move {
				let mut request_stream = request_stream;
				loop {
					match proxy
						.handle_requests(runtime.clone(), hs_nickname.clone(), &mut request_stream)
						.await
					{
						Ok(()) => {
							debug!("Onion service {} exited cleanly.", hs_nickname);
							break;
						}
						Err(error) => {
							warn!(
								"Onion service {} proxy failed: {}; retrying in 1 second",
								hs_nickname, error
							);
							runtime.sleep(Duration::from_secs(1)).await;
						}
					}
				}
			});
		})
	};

	let launched_address = service
		.onion_address()
		.ok_or_else(|| TorError::RequestError("Onion service has no identity".into()))?;
	if launched_address != expected_address {
		proxy.shutdown();
		let _ = worker.join();
		return Err(TorError::RequestError(format!(
			"Onion service identity mismatch: expected {}, launched {:?}",
			server_config.onion_address().to_ov3_str(),
			launched_address
		)));
	}

	info!(
		"Onion service reactor launched at http://{}.onion",
		server_config.onion_address().to_ov3_str()
	);
	Ok((service, proxy, worker))
}

fn spawn_status_logger<R>(
	runtime: &R,
	service: &RunningOnionService,
	onion_address: String,
) -> Result<(), TorError>
where
	R: Runtime,
{
	let mut statuses = service.status_events();
	runtime
		.spawn(async move {
			let mut previous = None;
			let mut has_reached_running = false;
			while let Some(status) = statuses.next().await {
				let state = status.state();
				let problem = status.current_problem().and_then(onion_service_problem);
				debug!("Onion service status at http://{onion_address}.onion: {status:?}");
				if previous == Some((state, problem)) {
					continue;
				}
				previous = Some((state, problem));
				match state {
					OnionServiceState::Running => {
						has_reached_running = true;
						info!("Onion service is reachable at http://{onion_address}.onion")
					}
					OnionServiceState::DegradedReachable => match problem {
						Some(problem) => warn!(
							"Onion service is reachable but degraded ({problem}) at http://{onion_address}.onion"
						),
						None => warn!(
							"Onion service is reachable but degraded at http://{onion_address}.onion"
						),
					},
					OnionServiceState::Bootstrapping if !has_reached_running => {
						info!("Onion service is bootstrapping at http://{onion_address}.onion")
					}
					// Arti also uses Bootstrapping while refreshing a running service's
					// descriptor, so avoid implying that the process restarted.
					OnionServiceState::Bootstrapping => match problem {
						Some(problem) => warn!(
							"Onion service status changed to Bootstrapping ({problem}) at http://{onion_address}.onion"
						),
						None => info!(
							"Onion service status changed to Bootstrapping (no problem reported) at http://{onion_address}.onion"
						),
					},
					OnionServiceState::Recovering | OnionServiceState::DegradedUnreachable => {
						match problem {
							Some(problem) => warn!(
								"Onion service is not fully reachable ({state:?}, {problem}) at http://{onion_address}.onion"
							),
							None => warn!(
								"Onion service is not fully reachable ({state:?}) at http://{onion_address}.onion"
							),
						}
					}
					OnionServiceState::Broken => {
						error!("Onion service is broken at http://{onion_address}.onion")
					}
					OnionServiceState::Shutdown => {
						info!("Onion service stopped at http://{onion_address}.onion")
					}
					_ => warn!(
						"Onion service status changed to {state:?} at http://{onion_address}.onion"
					),
				}
			}
		})
		.map_err(|error| {
			TorError::RequestError(format!("Could not monitor Onion service: {error}"))
		})?;
	Ok(())
}

fn onion_service_problem(problem: &OnionServiceProblem) -> Option<&'static str> {
	match problem {
		OnionServiceProblem::Runtime(_) => Some("runtime problem"),
		OnionServiceProblem::DescriptorUpload(errors) if !errors.is_empty() => {
			Some("descriptor upload problem")
		}
		OnionServiceProblem::Ipt(errors) if !errors.is_empty() => {
			Some("introduction point problem")
		}
		OnionServiceProblem::DescriptorUpload(_) | OnionServiceProblem::Ipt(_) => None,
		_ => Some("unknown problem"),
	}
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
		ArtiNativeKeystore::from_path_and_mistrust(&key_store_dir, tor_config.fs_mistrust())
			.unwrap();
	info!("Using keystore from {key_store_dir:?}");

	let key_manager = KeyMgrBuilder::default()
		.primary_store(Box::new(arti_store))
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
			HsIdKey::from(*expanded_kp.public()),
			&HsIdPublicKeySpecifier::new(hs_nickname.clone()),
			KeystoreSelector::Primary,
			true,
		)
		.unwrap();

	key_manager
		.insert(
			HsIdKeypair::from(expanded_kp),
			&HsIdKeypairSpecifier::new(hs_nickname.clone()),
			KeystoreSelector::Primary,
			true,
		)
		.unwrap();

	Ok(())
}

pub async fn async_post<R: Runtime>(
	client: Arc<TorClient<R>>,
	url: &str,
	body: String,
) -> Result<String, TorError> {
	async_post_with_timeout(client, url, body, REQUEST_TIMEOUT).await
}

fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
	let mut message = error.to_string();
	let mut source = error.source();
	while let Some(error) = source {
		message.push_str(": ");
		message.push_str(&error.to_string());
		source = error.source();
	}
	message
}

async fn async_post_with_timeout<R: Runtime>(
	client: Arc<TorClient<R>>,
	url: &str,
	body: String,
	timeout: Duration,
) -> Result<String, TorError> {
	let uri: Uri = url
		.parse()
		.map_err(|e| TorError::RequestError(format!("Bad URL: {e}")))?;
	let host = uri
		.host()
		.ok_or_else(|| TorError::RequestError("URL has no host".into()))?
		.to_string();
	let request_target = uri
		.path_and_query()
		.map(|path| path.as_str())
		.unwrap_or("/")
		.to_string();
	let runtime = client.runtime().clone();
	runtime
		.clone()
		.timeout(timeout, async move {
			let port = uri.port_u16().unwrap_or(80);
			let stream = client
				.connect((host.clone(), port))
				.await
				.map_err(|error| TorError::RequestError(error_chain(&error)))?;
			let (mut sender, connection) =
				hyper::client::conn::http1::handshake(TokioIo::new(stream))
					.await
					.map_err(|error| TorError::RequestError(error_chain(&error)))?;

			let connection_runtime = runtime.clone();
			connection_runtime
				.spawn(async move {
					if let Err(error) = connection.await {
						warn!("Tor connection error: {}", error_chain(&error));
					}
				})
				.map_err(|error| {
					TorError::RequestError(format!("Could not start HTTP connection: {error}"))
				})?;

			let response = sender
				.send_request(
					Request::builder()
						.uri(request_target)
						.method("POST")
						.header("host", host)
						.header("content-type", "application/json")
						.body::<Full<Bytes>>(Full::from(body))
						.map_err(|error| TorError::RequestError(error_chain(&error)))?,
				)
				.await
				.map_err(|error| TorError::RequestError(error_chain(&error)))?;
			if !response.status().is_success() {
				return Err(TorError::ResponseStatusError(response.status()));
			}
			let bytes = response
				.into_body()
				.collect()
				.await
				.map_err(|error| TorError::RequestError(error_chain(&error)))?
				.to_bytes();
			String::from_utf8(bytes.to_vec())
				.map_err(|error| TorError::RequestError(error_chain(&error)))
		})
		.await
		.map_err(|_| TorError::RequestTimeout)?
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn timeout_floor() {
		let mut config = TorClientConfigBuilder::default();
		set_timeout_floor(&mut config, 1_234);

		assert_eq!(
			config.override_net_params().get("cbtmintimeout"),
			Some(&1_234)
		);
	}
}
