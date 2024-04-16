use std::time::Duration;

use grin_api::json_rpc;
use grin_util::to_base64;
use grin_wallet_api::{EncryptedRequest, EncryptedResponse, JsonId};
use hyper::body::Body as HyperBody;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use hyper::Request;
use serde_json::json;
use thiserror::Error;

use secp256k1zkp::SecretKey;

/// Error types for HTTP client connections
#[derive(Error, Debug)]
pub enum HttpError {
	#[error("Error decrypting response")]
	DecryptResponseError(),
	#[error("Hyper HTTP error: {0:?}")]
	HyperHttpError(hyper::http::Error),
	#[error("Hyper request failed with error: {0:?}")]
	RequestFailed(hyper::Error),
	#[error("Error with response body: {0:?}")]
	ResponseBodyError(hyper::Error),
	#[error("Error deserializing JSON response: {0:?}")]
	ResponseJsonError(serde_json::Error),
	#[error("Error decoding JSON-RPC response: {0:?}")]
	ResponseParseError(json_rpc::Error),
	#[error("Wrong response code: {0}")]
	ResponseStatusError(hyper::StatusCode),
}

pub async fn async_send_enc_request<D: serde::de::DeserializeOwned>(
	url: &String,
	api_secret: &Option<String>,
	method: &str,
	params: &serde_json::Value,
	shared_key: &SecretKey,
) -> Result<D, HttpError> {
	let req = json!({
		"method": method,
		"params": params,
		"id": JsonId::IntId(1),
		"jsonrpc": "2.0",
	});
	let enc_req = EncryptedRequest::from_json(&JsonId::IntId(1), &req, &shared_key).unwrap();
	let req = build_request(&url, &api_secret, serde_json::to_string(&enc_req).unwrap())?;
	let response_str = send_request_async(req).await?;
	let enc_res: EncryptedResponse =
		serde_json::from_str(&response_str).map_err(HttpError::ResponseJsonError)?;

	let decrypted = enc_res
		.decrypt(&shared_key)
		.map_err(|_| HttpError::DecryptResponseError())?;

	let response: json_rpc::Response =
		serde_json::from_value(decrypted).map_err(HttpError::ResponseJsonError)?;
	let parsed = response
		.clone()
		.into_result()
		.map_err(HttpError::ResponseParseError)?;
	Ok(parsed)
}

pub async fn async_send_json_request<D: serde::de::DeserializeOwned>(
	url: &String,
	api_secret: &Option<String>,
	method: &str,
	params: &serde_json::Value,
) -> Result<D, HttpError> {
	let req_body = json!({
		"method": method,
		"params": params,
		"id": 1,
		"jsonrpc": "2.0",
	});
	let req = build_request(&url, &api_secret, serde_json::to_string(&req_body).unwrap())?;
	let data = send_request_async(req).await?;
	let ser: json_rpc::Response =
		serde_json::from_str(&data).map_err(HttpError::ResponseJsonError)?;
	let parsed = ser
		.clone()
		.into_result()
		.map_err(HttpError::ResponseParseError)?;
	Ok(parsed)
}

pub fn build_request(
	url: &String,
	api_secret: &Option<String>,
	req_body: String,
) -> Result<Request<HyperBody>, HttpError> {
	let mut req_builder = hyper::Request::builder();
	if let Some(api_secret) = api_secret {
		let basic_auth = format!("Basic {}", to_base64(&format!("grin:{}", api_secret)));
		req_builder = req_builder.header(AUTHORIZATION, basic_auth);
	}

	req_builder
		.method(hyper::Method::POST)
		.uri(url)
		.header(USER_AGENT, "grin-client")
		.header(ACCEPT, "application/json")
		.header(CONTENT_TYPE, "application/json")
		.body(HyperBody::from(req_body))
		.map_err(HttpError::HyperHttpError)
}

async fn send_request_async(req: Request<HyperBody>) -> Result<String, HttpError> {
	let client = hyper::Client::builder()
		.pool_idle_timeout(Duration::from_secs(30))
		.build_http();

	let resp = client
		.request(req)
		.await
		.map_err(HttpError::RequestFailed)?;
	if !resp.status().is_success() {
		return Err(HttpError::ResponseStatusError(resp.status()));
	}

	let raw = hyper::body::to_bytes(resp)
		.await
		.map_err(HttpError::ResponseBodyError)?;

	Ok(String::from_utf8_lossy(&raw).to_string())
}
