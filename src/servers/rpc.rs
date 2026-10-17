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

//! Shared HTTP transport for the asynchronous swap and mix APIs

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::JoinHandle;

use bytes::Bytes;
use grin_api::{ApiServer, Handler, HandlerObj, ResponseFuture, Router};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use jsonrpc_core::IoHandler;
use tokio::{runtime::Handle, sync::mpsc};

const MAX_BODY_SIZE: usize = 5 * 1024 * 1024;

pub struct RpcServer {
	thread: Option<JoinHandle<()>>,
	shutdown: mpsc::Sender<()>,
	addr: SocketAddr,
}

impl RpcServer {
	pub fn start(
		addr: SocketAddr,
		io: IoHandler,
		runtime: Handle,
	) -> Result<Self, grin_api::Error> {
		let handler = Arc::new(RpcHandler {
			io: Arc::new(io),
			runtime,
		});
		let mut router = Router::new();
		router.add_route("/", handler.clone())?;
		router.add_route("/**", handler)?;
		let (shutdown, receiver) = mpsc::channel(1);
		let mut api = ApiServer::new();
		let thread = api.start(addr, router, None, (shutdown.clone(), receiver))?;
		Ok(Self {
			thread: Some(thread),
			shutdown,
			addr,
		})
	}

	pub fn address(&self) -> &SocketAddr {
		&self.addr
	}

	pub fn close_handle(&self) -> mpsc::Sender<()> {
		self.shutdown.clone()
	}

	pub fn wait(mut self) {
		if let Some(thread) = self.thread.take() {
			thread.join().expect("RPC server thread panicked");
		}
	}
}

impl Drop for RpcServer {
	fn drop(&mut self) {
		let _ = self.shutdown.try_send(());
	}
}

struct RpcHandler {
	io: Arc<IoHandler>,
	runtime: Handle,
}

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<BoxBody<Bytes, Infallible>> {
	let content_type = if status.is_success() {
		"application/json; charset=utf-8"
	} else {
		"text/plain; charset=utf-8"
	};
	Response::builder()
		.status(status)
		.header(header::CONTENT_TYPE, content_type)
		.body(Full::new(body.into()).boxed())
		.unwrap()
}

impl Handler for RpcHandler {
	fn call(
		&self,
		req: Request<Incoming>,
		_: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		if req.uri() != "/v1" {
			return Box::pin(async { Ok(response(StatusCode::BAD_REQUEST, "Only v1 supported")) });
		}
		let io = self.io.clone();
		let runtime = self.runtime.clone();
		Box::pin(async move {
			let origin = req.headers().get(header::ORIGIN).cloned();
			let requested_headers = req
				.headers()
				.get(header::ACCESS_CONTROL_REQUEST_HEADERS)
				.cloned();
			let options = req.method() == Method::OPTIONS;
			let mut res = match *req.method() {
				Method::OPTIONS => response(StatusCode::OK, ""),
				Method::POST => {
					let is_json = req
						.headers()
						.get(header::CONTENT_TYPE)
						.and_then(|v| v.to_str().ok())
						.map(|v| {
							[
								"application/json",
								"application/json; charset=utf-8",
								"application/json;charset=utf-8",
							]
							.iter()
							.any(|t| v.eq_ignore_ascii_case(t))
						})
						.unwrap_or(false);
					if is_json {
						read_request(req.into_body(), io, runtime).await?
					} else {
						response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Supplied content type is not allowed. Content-Type: application/json is required\n")
					}
				}
				_ => response(
					StatusCode::METHOD_NOT_ALLOWED,
					"Used HTTP Method is not allowed. POST or OPTIONS is required\n",
				),
			};
			let headers = res.headers_mut();
			if options {
				headers.insert(header::ALLOW, "OPTIONS, POST".parse().unwrap());
				headers.insert(header::ACCEPT, "application/json".parse().unwrap());
			}
			if let Some(origin) = origin {
				headers.insert(header::VARY, "origin".parse().unwrap());
				headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
				headers.insert(
					header::ACCESS_CONTROL_ALLOW_METHODS,
					"OPTIONS, POST".parse().unwrap(),
				);
				if let Some(requested) = requested_headers {
					headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested);
				}
			}
			Ok(res)
		})
	}
}

async fn read_request(
	mut body: Incoming,
	io: Arc<IoHandler>,
	runtime: Handle,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
	let mut bytes = Vec::new();
	while let Some(frame) = body.frame().await {
		if let Ok(data) = frame?.into_data() {
			if data.len() > MAX_BODY_SIZE - bytes.len() {
				return Ok(response(
					StatusCode::PAYLOAD_TOO_LARGE,
					"request body size exceeds allowed maximum",
				));
			}
			bytes.extend_from_slice(&data);
		}
	}
	let request = match String::from_utf8(bytes) {
		Ok(request) => request,
		Err(error) => {
			return Ok(response(
				StatusCode::BAD_REQUEST,
				format!(
					"utf-8 encoding error at byte {} in request body",
					error.utf8_error().valid_up_to()
				),
			))
		}
	};
	// Keep RPC work on the caller's runtime
	let result = runtime
		.spawn(async move { io.handle_request(&request).await })
		.await;
	Ok(match result {
		Ok(body) => response(
			StatusCode::OK,
			body.map(|body| format!("{}\n", body)).unwrap_or_default(),
		),
		Err(_) => response(StatusCode::SERVICE_UNAVAILABLE, "Server is closing."),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use hyper_util::{client::legacy::Client, rt::TokioExecutor};
	use serde_json::{json, Value};
	use std::net::TcpListener;
	use tokio::time::{timeout, Duration};

	fn start(io: IoHandler) -> RpcServer {
		let addr = TcpListener::bind("127.0.0.1:0")
			.unwrap()
			.local_addr()
			.unwrap();
		RpcServer::start(addr, io, Handle::current()).unwrap()
	}

	async fn send(
		server: &RpcServer,
		method: Method,
		path: &str,
		content_type: &str,
		body: Vec<u8>,
	) -> (StatusCode, hyper::HeaderMap, Bytes) {
		let req = Request::builder()
			.method(method)
			.uri(format!("http://{}{}", server.address(), path))
			.header(header::CONTENT_TYPE, content_type)
			.header(header::ORIGIN, "http://localhost:8000")
			.header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
			.body(Full::new(Bytes::from(body)))
			.unwrap();
		let client = Client::builder(TokioExecutor::new()).build_http();
		let res = timeout(Duration::from_secs(5), client.request(req))
			.await
			.unwrap()
			.unwrap();
		let (parts, body) = res.into_parts();
		(
			parts.status,
			parts.headers,
			body.collect().await.unwrap().to_bytes(),
		)
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn protocol() {
		let mut io = IoHandler::new();
		io.add_sync_method("health", |_| Ok(json!("ok")));
		let server = start(io);
		for (body, expected) in [
			(
				r#"[{"jsonrpc":"2.0","method":"health","id":1},{"jsonrpc":"2.0","method":"health"}]"#,
				Some(json!([{"jsonrpc":"2.0","result":"ok","id":1}])),
			),
			(r#"{"jsonrpc":"2.0","method":"health"}"#, None),
			(
				"{",
				Some(
					json!({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}),
				),
			),
		] {
			let (status, _, body) = send(
				&server,
				Method::POST,
				"/v1",
				"Application/JSON; charset=UTF-8",
				body.as_bytes().to_vec(),
			)
			.await;
			assert_eq!(status, StatusCode::OK);
			match expected {
				Some(expected) => {
					assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), expected)
				}
				None => assert!(body.is_empty()),
			}
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn transport() {
		let server = start(IoHandler::new());
		for (method, path, content_type, body, expected) in [
			(Method::POST, "/", "application/json", vec![], 400),
			(Method::POST, "/v1?x=1", "application/json", vec![], 400),
			(Method::GET, "/v1", "application/json", vec![], 405),
			(Method::POST, "/v1", "text/plain", vec![], 415),
			(Method::POST, "/v1", "application/json", vec![255], 400),
			(
				Method::POST,
				"/v1",
				"application/json",
				vec![b' '; MAX_BODY_SIZE + 1],
				413,
			),
			(Method::OPTIONS, "/v1", "text/plain", vec![], 200),
		] {
			let (status, headers, _) =
				send(&server, method.clone(), path, content_type, body).await;
			assert_eq!(status.as_u16(), expected, "{method} {path}");
			if method == Method::OPTIONS {
				assert_eq!(headers[header::ALLOW], "OPTIONS, POST");
				assert_eq!(
					headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
					"http://localhost:8000"
				);
				assert_eq!(
					headers[header::ACCESS_CONTROL_ALLOW_HEADERS],
					"content-type"
				);
			}
		}
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn shutdown() {
		let entered = Arc::new(tokio::sync::Notify::new());
		let release = Arc::new(tokio::sync::Notify::new());
		let mut io = IoHandler::new();
		let (started, finish) = (entered.clone(), release.clone());
		io.add_method("wait", move |_| {
			let (started, finish) = (started.clone(), finish.clone());
			async move {
				started.notify_one();
				finish.notified().await;
				Ok(json!({"Ok": "ok"}))
			}
		});
		let server = start(io);
		let addr = *server.address();
		let url = format!("http://{addr}/v1");
		let secret = Some("test".into());
		let params = json!([]);
		let request =
			crate::http::async_send_json_request::<String>(&url, &secret, "wait", &params);
		tokio::pin!(request);
		tokio::select! {
			_ = entered.notified() => {},
			result = &mut request => panic!("request ended early: {result:?}"),
			_ = tokio::time::sleep(Duration::from_secs(5)) => panic!("request did not start"),
		}
		server.close_handle().try_send(()).unwrap();
		timeout(Duration::from_secs(5), async {
			while tokio::net::TcpStream::connect(addr).await.is_ok() {
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.unwrap();
		release.notify_one();
		assert_eq!(
			timeout(Duration::from_secs(5), request)
				.await
				.unwrap()
				.unwrap(),
			"ok"
		);
		timeout(
			Duration::from_secs(5),
			tokio::task::spawn_blocking(move || server.wait()),
		)
		.await
		.unwrap()
		.unwrap();
		assert!(tokio::net::TcpStream::connect(addr).await.is_err());
	}
}
