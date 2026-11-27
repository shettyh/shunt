use thiserror::Error;

/// Core engine errors for transport, TLS, snapshot compilation, and streaming.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] http::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("Hyper client error: {0}")]
    HyperClient(#[from] hyper_util::client::legacy::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("invalid URI `{uri}`: {message}")]
    InvalidUri { uri: String, message: String },

    #[error("unknown upstream `{0}`")]
    UnknownUpstream(String),

    #[error("upstream `{0}` has no endpoints")]
    EmptyUpstream(String),

    #[error("upstream connect timeout after {0:?}")]
    ConnectTimeout(std::time::Duration),

    #[error("upstream response headers timeout (TTFB) after {0:?}")]
    ResponseHeadersTimeout(std::time::Duration),

    #[error("stream idle chunk timeout after {0:?}")]
    IdleChunkTimeout(std::time::Duration),

    #[error("request body read timeout after {0:?}")]
    RequestBodyTimeout(std::time::Duration),

    #[error("request body exceeded max_body_bytes limit of {0} bytes")]
    BodyTooLarge(usize),

    #[error("stream aborted: {0}")]
    StreamAborted(String),

    #[error("plugin `{plugin}` panicked in `{hook}`: {message}")]
    PluginPanic {
        plugin: String,
        hook: &'static str,
        message: String,
    },

    #[error("plugin build error: {0}")]
    PluginBuild(#[from] shunt_plugin_sdk::PluginBuildError),

    #[error("configuration error: {0}")]
    Config(String),
}
