use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use shunt_plugin_sdk::{BoxFuture, HttpClient, HttpClientError, HttpRequest, HttpResponse};

use crate::error::CoreError;
use crate::tls::UpstreamTlsConfig;
use crate::upstream::ShuntConnector;

/// Default connect timeout for outbound plugin HTTP calls.
pub const DEFAULT_HTTP_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default end-to-end request timeout for outbound plugin HTTP calls.
pub const DEFAULT_HTTP_CLIENT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default maximum response body size (4 MiB) buffered by [`CoreHttpClient`].
pub const DEFAULT_HTTP_CLIENT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Configuration for [`CoreHttpClient`].
#[derive(Debug, Clone)]
pub struct CoreHttpClientConfig {
    pub connect_timeout: Duration,
    pub default_timeout: Duration,
    pub default_max_response_bytes: usize,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    /// Optional additional PEM-encoded root CA certificates (e.g. Kubernetes cluster CA).
    pub extra_ca_pem: Option<Vec<u8>>,
    pub insecure_skip_verify: bool,
}

impl Default for CoreHttpClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_HTTP_CLIENT_CONNECT_TIMEOUT,
            default_timeout: DEFAULT_HTTP_CLIENT_TIMEOUT,
            default_max_response_bytes: DEFAULT_HTTP_CLIENT_MAX_RESPONSE_BYTES,
            pool_idle_timeout: Duration::from_secs(60),
            pool_max_idle_per_host: 8,
            extra_ca_pem: None,
            insecure_skip_verify: false,
        }
    }
}

/// Shared, pooled outbound HTTP/HTTPS client built on Shunt's `hyper` + `rustls` stack.
///
/// Exposed to plugins solely through the [`shunt_plugin_sdk::HttpClient`] trait so plugins
/// remain completely independent of `shunt-engine`, `hyper`, and `rustls`.
pub struct CoreHttpClient {
    config: CoreHttpClientConfig,
    client: Client<ShuntConnector, Full<Bytes>>,
}

impl fmt::Debug for CoreHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreHttpClient")
            .field("config", &self.config)
            .finish()
    }
}

impl CoreHttpClient {
    /// Builds a new [`CoreHttpClient`] with the provided configuration.
    pub fn new(config: CoreHttpClientConfig) -> Result<Self, CoreError> {
        let tls_cfg = UpstreamTlsConfig {
            extra_ca_pem: config.extra_ca_pem.clone(),
            insecure_skip_verify: config.insecure_skip_verify,
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        };
        let connector = ShuntConnector::new(config.connect_timeout, &tls_cfg)?;
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .build(connector);
        Ok(Self { config, client })
    }

    /// Builds a [`CoreHttpClient`] with default settings.
    pub fn new_default() -> Result<Self, CoreError> {
        Self::new(CoreHttpClientConfig::default())
    }

    /// Sends an HTTP/HTTPS request and returns the raw streaming response without buffering the
    /// body, suitable for long-lived Server-Sent Events (SSE) streams.
    ///
    /// `request.timeout` bounds only receiving the response head (headers), not stream lifetime.
    pub async fn send_streaming(
        &self,
        request: HttpRequest,
    ) -> Result<http::Response<hyper::body::Incoming>, HttpClientError> {
        let scheme = request.uri.scheme_str().unwrap_or("");
        if (scheme != "http" && scheme != "https") || request.uri.authority().is_none() {
            return Err(HttpClientError::InvalidUri(format!(
                "URI `{}` must be an absolute http:// or https:// URL",
                request.uri
            )));
        }

        let head_timeout = request
            .timeout
            .unwrap_or(self.config.default_timeout)
            .max(Duration::from_millis(1));

        let mut builder = Request::builder().method(request.method).uri(request.uri);
        if let Some(headers) = builder.headers_mut() {
            *headers = request.headers;
        }
        let hyper_req = builder
            .body(Full::new(request.body))
            .map_err(|e| HttpClientError::InvalidUri(e.to_string()))?;

        tokio::time::timeout(head_timeout, self.client.request(hyper_req))
            .await
            .map_err(|_| HttpClientError::Timeout(head_timeout))?
            .map_err(|e| HttpClientError::Transport(e.to_string()))
    }
}

impl HttpClient for CoreHttpClient {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, HttpClientError>> {
        Box::pin(async move {
            let scheme = request.uri.scheme_str().unwrap_or("");
            if (scheme != "http" && scheme != "https") || request.uri.authority().is_none() {
                return Err(HttpClientError::InvalidUri(format!(
                    "URI `{}` must be an absolute http:// or https:// URL",
                    request.uri
                )));
            }

            let timeout = request
                .timeout
                .unwrap_or(self.config.default_timeout)
                .max(Duration::from_millis(1));
            let max_bytes = request
                .max_response_bytes
                .unwrap_or(self.config.default_max_response_bytes);

            let mut builder = Request::builder().method(request.method).uri(request.uri);
            if let Some(headers) = builder.headers_mut() {
                *headers = request.headers;
            }
            let hyper_req = builder
                .body(Full::new(request.body))
                .map_err(|e| HttpClientError::InvalidUri(e.to_string()))?;

            let fut = async {
                let resp = self
                    .client
                    .request(hyper_req)
                    .await
                    .map_err(|e| HttpClientError::Transport(e.to_string()))?;

                let status = resp.status();
                let headers = resp.headers().clone();
                let mut body_stream = resp.into_body();
                let mut buf = Vec::new();
                while let Some(frame_res) = body_stream.frame().await {
                    let frame = frame_res.map_err(|e| HttpClientError::Transport(e.to_string()))?;
                    if let Ok(data) = frame.into_data() {
                        if buf.len().saturating_add(data.len()) > max_bytes {
                            return Err(HttpClientError::ResponseTooLarge(max_bytes));
                        }
                        buf.extend_from_slice(&data);
                    }
                }
                Ok(HttpResponse {
                    status,
                    headers,
                    body: Bytes::from(buf),
                })
            };

            tokio::time::timeout(timeout, fut)
                .await
                .map_err(|_| HttpClientError::Timeout(timeout))?
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http::{HeaderName, HeaderValue, Response, StatusCode, Uri, header};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    use super::*;

    async fn spawn_echo_server(
        delay: Duration,
        resp_body: &'static [u8],
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| async move {
                        let method = req.method().as_str().to_owned();
                        let header_val = req
                            .headers()
                            .get("x-test-hdr")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let req_body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        let payload = if resp_body.is_empty() {
                            Bytes::from(format!(
                                "{method}|{header_val}|{}",
                                String::from_utf8_lossy(&req_body)
                            ))
                        } else {
                            Bytes::from_static(resp_body)
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "text/plain")
                                .body(Full::new(payload))
                                .unwrap(),
                        )
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn core_http_client_sends_request_and_reads_response() {
        let (addr, server) = spawn_echo_server(Duration::ZERO, b"").await;
        let client = CoreHttpClient::new_default().unwrap();

        let uri: Uri = format!("http://{addr}/token").parse().unwrap();
        let req = HttpRequest::post(uri)
            .with_header(
                HeaderName::from_static("x-test-hdr"),
                HeaderValue::from_static("hello"),
            )
            .with_body("a=1&b=2");

        let resp = client.send(req).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body, Bytes::from_static(b"POST|hello|a=1&b=2"));
        server.abort();
    }

    #[tokio::test]
    async fn core_http_client_enforces_timeout_and_body_cap_and_uri_validation() {
        let client = CoreHttpClient::new_default().unwrap();

        // Relative URI must be rejected cleanly.
        let bad = client
            .send(HttpRequest::get("/relative/path".parse().unwrap()))
            .await;
        assert!(matches!(bad, Err(HttpClientError::InvalidUri(_))));

        // Timeout enforcement.
        let (slow_addr, slow_srv) = spawn_echo_server(Duration::from_millis(250), b"ok").await;
        let timed_out = client
            .send(
                HttpRequest::get(format!("http://{slow_addr}/slow").parse().unwrap())
                    .with_timeout(Duration::from_millis(40)),
            )
            .await;
        assert!(matches!(timed_out, Err(HttpClientError::Timeout(_))));
        slow_srv.abort();

        // Response size cap enforcement.
        let (big_addr, big_srv) = spawn_echo_server(Duration::ZERO, b"0123456789abcdef").await;
        let too_big = client
            .send(
                HttpRequest::get(format!("http://{big_addr}/big").parse().unwrap())
                    .with_max_response_bytes(8),
            )
            .await;
        assert!(matches!(too_big, Err(HttpClientError::ResponseTooLarge(8))));
        big_srv.abort();
    }
}
