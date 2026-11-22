use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use thiserror::Error;

use crate::flow::BoxFuture;

/// Outbound HTTP request sent by a plugin via [`HttpClient`].
///
/// Intentionally decoupled from `hyper` so plugins remain strictly bound to `shunt-plugin-sdk`.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
    /// Optional per-request end-to-end timeout (falls back to client default when `None`).
    pub timeout: Option<Duration>,
    /// Optional cap on buffered response body bytes (falls back to client default when `None`).
    pub max_response_bytes: Option<usize>,
}

impl HttpRequest {
    /// Creates an outbound HTTP request with an empty body and default headers/limits.
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            timeout: None,
            max_response_bytes: None,
        }
    }

    /// Creates an outbound `GET` request.
    pub fn get(uri: Uri) -> Self {
        Self::new(Method::GET, uri)
    }

    /// Creates an outbound `POST` request.
    pub fn post(uri: Uri) -> Self {
        Self::new(Method::POST, uri)
    }

    /// Creates an outbound `PUT` request.
    pub fn put(uri: Uri) -> Self {
        Self::new(Method::PUT, uri)
    }

    /// Inserts a header onto this request.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Sets the request body bytes.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets an explicit end-to-end request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets an explicit maximum response body size in bytes.
    pub fn with_max_response_bytes(mut self, max_bytes: usize) -> Self {
        self.max_response_bytes = Some(max_bytes);
        self
    }
}

/// Outbound HTTP response returned by [`HttpClient::send`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Errors returned by [`HttpClient::send`].
#[derive(Debug, Error)]
pub enum HttpClientError {
    #[error("invalid outbound request URI: {0}")]
    InvalidUri(String),
    #[error("outbound HTTP transport error: {0}")]
    Transport(String),
    #[error("outbound HTTP request timed out after {0:?}")]
    Timeout(Duration),
    #[error("outbound HTTP response body exceeded limit of {0} bytes")]
    ResponseTooLarge(usize),
}

/// General-purpose, AI-agnostic outbound HTTP/HTTPS client exposed to plugins via
/// [`crate::BuildContext::http_client`].
///
/// Enables sideband HTTP calls (such as cloud IAM token refresh, JWKS key fetching, external
/// guardrails, and alert webhooks) while keeping plugins strictly free of `hyper`/`rustls`
/// transport dependencies and preserving warm connection pooling across snapshot reloads.
pub trait HttpClient: fmt::Debug + Send + Sync + 'static {
    /// Executes an outbound HTTP/HTTPS request and collects its bounded response body.
    fn send<'a>(
        &'a self,
        request: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, HttpClientError>>;
}

#[cfg(test)]
mod tests {
    use http::header;

    use super::*;

    #[test]
    fn http_request_builders_set_fields() {
        let uri: Uri = "https://example.com/token".parse().unwrap();
        let req = HttpRequest::post(uri.clone())
            .with_header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .with_body("grant_type=client_credentials")
            .with_timeout(Duration::from_secs(3))
            .with_max_response_bytes(65_536);

        assert_eq!(req.method, Method::POST);
        assert_eq!(req.uri, uri);
        assert_eq!(
            req.headers.get(header::CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            req.body,
            Bytes::from_static(b"grant_type=client_credentials")
        );
        assert_eq!(req.timeout, Some(Duration::from_secs(3)));
        assert_eq!(req.max_response_bytes, Some(65_536));
    }
}
