use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::ServerName;
use shunt_plugin_sdk::{
    BoxFuture, DistributedStore, DistributedStoreError, FailurePolicy, QuotaOutcome,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::tls::UpstreamTlsConfig;

const MAX_RESP_LINE_BYTES: usize = 64 * 1024;
const MAX_RESP_BULK_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESP_ARRAY_LEN: usize = 4096;
const MAX_RESP_DEPTH: usize = 16;

/// Atomic Lua script for `try_consume_quota(key, amount, limit, window_ms)`.
/// Returns `[allowed (0|1), current, remaining, retry_after_secs]`.
pub const LUA_TRY_CONSUME_QUOTA: &str = r#"
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local amt = tonumber(ARGV[1])
local lim = tonumber(ARGV[2])
local win = tonumber(ARGV[3])
if cur + amt <= lim then
  local nxt = redis.call('INCRBY', KEYS[1], amt)
  if redis.call('PTTL', KEYS[1]) < 0 then
    redis.call('PEXPIRE', KEYS[1], win)
  end
  return {1, nxt, lim - nxt, 0}
else
  local pttl = redis.call('PTTL', KEYS[1])
  if pttl < 0 then pttl = win end
  local rem = lim - cur
  if rem < 0 then rem = 0 end
  local retry = math.ceil(pttl / 1000)
  if retry < 1 then retry = 1 end
  return {0, cur, rem, retry}
end
"#;

/// Atomic Lua script for `adjust_counter(key, delta, ttl_ms)`.
/// Clamps counter at `>= 0` and preserves existing TTL (or initializes `ttl_ms` if absent).
pub const LUA_ADJUST_COUNTER: &str = r#"
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local delta = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local nxt = cur + delta
if nxt < 0 then nxt = 0 end
local pttl = redis.call('PTTL', KEYS[1])
if pttl > 0 then
  redis.call('SET', KEYS[1], tostring(nxt), 'PX', pttl)
else
  redis.call('SET', KEYS[1], tostring(nxt), 'PX', ttl)
end
return nxt
"#;

/// Parsed configuration for a Redis / Valkey [`RedisStateStore`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RedisStoreConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub db: u8,
    pub key_prefix: String,
    pub pool_size: usize,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub failure_policy: FailurePolicy,
    pub insecure_skip_verify: bool,
}

impl fmt::Debug for RedisStoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisStoreConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("db", &self.db)
            .field("key_prefix", &self.key_prefix)
            .field("pool_size", &self.pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .field("command_timeout", &self.command_timeout)
            .field("failure_policy", &self.failure_policy)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish()
    }
}

impl RedisStoreConfig {
    /// Parses a `redis://` or `rediss://` URL into a [`RedisStoreConfig`].
    ///
    /// Supported forms:
    /// - `redis://127.0.0.1:6379`
    /// - `redis://:secret@127.0.0.1:6379/1`
    /// - `redis://alice:secret@redis.internal:6379/0`
    /// - `rediss://user:pass@valkey.example.com:6380/2`
    /// - `redis://[::1]:6379`
    pub fn from_url(url: &str) -> Result<Self, String> {
        let trimmed = url.trim();
        let (tls, rest) = if let Some(r) = trimmed.strip_prefix("redis://") {
            (false, r)
        } else if let Some(r) = trimmed.strip_prefix("rediss://") {
            (true, r)
        } else {
            return Err(format!(
                "invalid Redis URL `{trimmed}`: expected `redis://` or `rediss://`"
            ));
        };

        // Strip query string if present (not used currently).
        let without_query = rest.split('?').next().unwrap_or(rest);
        let (authority, path) = match without_query.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (without_query, None),
        };

        if authority.is_empty() {
            return Err("Redis URL is missing host".to_owned());
        }

        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, authority),
        };

        let (username, password) = match userinfo {
            Some(u) => match u.split_once(':') {
                Some((user, pass)) => {
                    let uname = if user.is_empty() {
                        None
                    } else {
                        Some(percent_decode_simple(user))
                    };
                    let pwd = if pass.is_empty() {
                        None
                    } else {
                        Some(percent_decode_simple(pass))
                    };
                    (uname, pwd)
                }
                None => (None, Some(percent_decode_simple(u))),
            },
            None => (None, None),
        };

        let (host, port) = parse_host_port(hostport)?;

        let db = match path.map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| format!("invalid Redis DB index `{p}` in URL"))?,
            None => 0,
        };

        Ok(Self {
            host,
            port,
            tls,
            username,
            password,
            db,
            key_prefix: "shunt:".to_owned(),
            pool_size: 8,
            connect_timeout: Duration::from_millis(1_000),
            command_timeout: Duration::from_millis(250),
            failure_policy: FailurePolicy::FailOpen,
            insecure_skip_verify: false,
        })
    }
}

fn parse_host_port(hostport: &str) -> Result<(String, u16), String> {
    if hostport.is_empty() {
        return Err("Redis URL is missing host".to_owned());
    }
    if let Some(rest) = hostport.strip_prefix('[') {
        let Some((ipv6, after)) = rest.split_once(']') else {
            return Err(format!("unclosed IPv6 literal in `{hostport}`"));
        };
        if ipv6.is_empty() {
            return Err("empty IPv6 host in Redis URL".to_owned());
        }
        let port = if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port `{port_str}` in Redis URL"))?
        } else if after.is_empty() {
            6379
        } else {
            return Err(format!(
                "unexpected trailing characters `{after}` after IPv6"
            ));
        };
        Ok((ipv6.to_owned(), port))
    } else if let Some((h, port_str)) = hostport.rsplit_once(':') {
        if h.is_empty() {
            return Err("Redis URL is missing host".to_owned());
        }
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("invalid port `{port_str}` in Redis URL"))?;
        Ok((h.to_owned(), port))
    } else {
        Ok((hostport.to_owned(), 6379))
    }
}

fn percent_decode_simple(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// RESP2 protocol value decoded from a Redis / Valkey stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),
    Array(Option<Vec<RespValue>>),
}

impl RespValue {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            RespValue::Integer(n) => Some(*n),
            RespValue::BulkString(Some(bytes)) => {
                std::str::from_utf8(bytes).ok()?.trim().parse().ok()
            }
            RespValue::SimpleString(s) => s.trim().parse().ok(),
            _ => None,
        }
    }
}

/// Errors emitted while parsing RESP2 wire frames.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RespError {
    #[error("invalid RESP2 type prefix byte 0x{0:02x}")]
    InvalidPrefix(u8),
    #[error("RESP2 line exceeded maximum length ({MAX_RESP_LINE_BYTES} bytes)")]
    LineTooLong,
    #[error("invalid RESP2 integer: {0}")]
    InvalidInteger(String),
    #[error("invalid RESP2 bulk string length: {0}")]
    InvalidBulkLength(i64),
    #[error("RESP2 bulk string exceeded maximum size ({0} > {MAX_RESP_BULK_BYTES})")]
    BulkTooLarge(usize),
    #[error("invalid RESP2 array length: {0}")]
    InvalidArrayLength(i64),
    #[error("RESP2 array exceeded maximum length ({0} > {MAX_RESP_ARRAY_LEN})")]
    ArrayTooLarge(usize),
    #[error("RESP2 nesting depth exceeded maximum ({MAX_RESP_DEPTH})")]
    MaxDepthExceeded,
    #[error("RESP2 bulk string missing trailing CRLF")]
    MissingCrlf,
}

/// Encodes a Redis command array as a RESP2 bulk-string array.
pub fn encode_resp_command(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(b'*');
    out.extend_from_slice(args.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    for arg in args {
        out.push(b'$');
        out.extend_from_slice(arg.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(arg);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Encodes a [`RespValue`] into RESP2 wire bytes (primarily for testing and round-trip checks).
pub fn encode_resp_value(val: &RespValue, out: &mut Vec<u8>) {
    match val {
        RespValue::SimpleString(s) => {
            out.push(b'+');
            out.extend_from_slice(s.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        RespValue::Error(s) => {
            out.push(b'-');
            out.extend_from_slice(s.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        RespValue::Integer(n) => {
            out.push(b':');
            out.extend_from_slice(n.to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        RespValue::BulkString(None) => {
            out.extend_from_slice(b"$-1\r\n");
        }
        RespValue::BulkString(Some(bytes)) => {
            out.push(b'$');
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(bytes);
            out.extend_from_slice(b"\r\n");
        }
        RespValue::Array(None) => {
            out.extend_from_slice(b"*-1\r\n");
        }
        RespValue::Array(Some(items)) => {
            out.push(b'*');
            out.extend_from_slice(items.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
            for item in items {
                encode_resp_value(item, out);
            }
        }
    }
}

/// Decodes a single RESP2 frame from `buf`, returning `Ok(Some((value, bytes_consumed)))`
/// when a complete frame is available, `Ok(None)` if more bytes are needed, or `Err` on
/// malformed input.
pub fn decode_resp_frame(buf: &[u8]) -> Result<Option<(RespValue, usize)>, RespError> {
    decode_resp_frame_depth(buf, 0)
}

fn decode_resp_frame_depth(
    buf: &[u8],
    depth: usize,
) -> Result<Option<(RespValue, usize)>, RespError> {
    if depth > MAX_RESP_DEPTH {
        return Err(RespError::MaxDepthExceeded);
    }
    if buf.is_empty() {
        return Ok(None);
    }

    let prefix = buf[0];
    let Some((line, next_pos)) = read_crlf_line(&buf[1..])? else {
        return Ok(None);
    };
    let line_end = 1 + next_pos;

    match prefix {
        b'+' => {
            let s = String::from_utf8_lossy(line).into_owned();
            Ok(Some((RespValue::SimpleString(s), line_end)))
        }
        b'-' => {
            let s = String::from_utf8_lossy(line).into_owned();
            Ok(Some((RespValue::Error(s), line_end)))
        }
        b':' => {
            let n = parse_resp_i64(line)?;
            Ok(Some((RespValue::Integer(n), line_end)))
        }
        b'$' => {
            let len = parse_resp_i64(line)?;
            if len == -1 {
                return Ok(Some((RespValue::BulkString(None), line_end)));
            }
            if len < -1 {
                return Err(RespError::InvalidBulkLength(len));
            }
            let len_usize = usize::try_from(len).map_err(|_| RespError::InvalidBulkLength(len))?;
            if len_usize > MAX_RESP_BULK_BYTES {
                return Err(RespError::BulkTooLarge(len_usize));
            }
            let total_needed = match line_end
                .checked_add(len_usize)
                .and_then(|v| v.checked_add(2))
            {
                Some(t) => t,
                None => return Err(RespError::BulkTooLarge(len_usize)),
            };
            if buf.len() < total_needed {
                return Ok(None);
            }
            let payload = &buf[line_end..line_end + len_usize];
            if &buf[line_end + len_usize..total_needed] != b"\r\n" {
                return Err(RespError::MissingCrlf);
            }
            Ok(Some((
                RespValue::BulkString(Some(payload.to_vec())),
                total_needed,
            )))
        }
        b'*' => {
            let len = parse_resp_i64(line)?;
            if len == -1 {
                return Ok(Some((RespValue::Array(None), line_end)));
            }
            if len < -1 {
                return Err(RespError::InvalidArrayLength(len));
            }
            let count = usize::try_from(len).map_err(|_| RespError::InvalidArrayLength(len))?;
            if count > MAX_RESP_ARRAY_LEN {
                return Err(RespError::ArrayTooLarge(count));
            }
            let mut cursor = line_end;
            let mut items = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                match decode_resp_frame_depth(&buf[cursor..], depth + 1)? {
                    Some((item, consumed)) => {
                        cursor += consumed;
                        items.push(item);
                    }
                    None => return Ok(None),
                }
            }
            Ok(Some((RespValue::Array(Some(items)), cursor)))
        }
        other => Err(RespError::InvalidPrefix(other)),
    }
}

fn read_crlf_line(slice: &[u8]) -> Result<Option<(&[u8], usize)>, RespError> {
    let search_len = slice.len().min(MAX_RESP_LINE_BYTES + 2);
    for i in 0..search_len.saturating_sub(1) {
        if slice[i] == b'\r' && slice[i + 1] == b'\n' {
            return Ok(Some((&slice[..i], i + 2)));
        }
    }
    if slice.len() > MAX_RESP_LINE_BYTES + 1 {
        return Err(RespError::LineTooLong);
    }
    Ok(None)
}

fn parse_resp_i64(line: &[u8]) -> Result<i64, RespError> {
    let s = std::str::from_utf8(line)
        .map_err(|_| RespError::InvalidInteger(String::from_utf8_lossy(line).into_owned()))?;
    s.parse::<i64>()
        .map_err(|_| RespError::InvalidInteger(s.to_owned()))
}

enum RedisStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for RedisStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RedisStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            RedisStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RedisStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            RedisStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            RedisStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RedisStream::Plain(s) => Pin::new(s).poll_flush(cx),
            RedisStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RedisStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            RedisStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

struct RedisConn {
    stream: RedisStream,
    read_buf: Vec<u8>,
}

impl RedisConn {
    async fn connect(cfg: &RedisStoreConfig) -> Result<Self, DistributedStoreError> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let tcp = tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| DistributedStoreError::Timeout(cfg.connect_timeout))?
            .map_err(|e| DistributedStoreError::Connection(format!("connect {addr}: {e}")))?;
        let _ = tcp.set_nodelay(true);

        let stream = if cfg.tls {
            let tls_cfg = UpstreamTlsConfig {
                extra_ca_pem: None,
                insecure_skip_verify: cfg.insecure_skip_verify,
                alpn_protocols: Vec::new(),
            };
            let client_cfg = tls_cfg
                .build_client_config(Some(Vec::new()))
                .map_err(|e| DistributedStoreError::Connection(format!("TLS config: {e}")))?;
            let connector = TlsConnector::from(client_cfg);
            let server_name = ServerName::try_from(cfg.host.clone()).map_err(|e| {
                DistributedStoreError::Connection(format!("invalid TLS server name: {e}"))
            })?;
            let tls_stream =
                tokio::time::timeout(cfg.connect_timeout, connector.connect(server_name, tcp))
                    .await
                    .map_err(|_| DistributedStoreError::Timeout(cfg.connect_timeout))?
                    .map_err(|e| {
                        DistributedStoreError::Connection(format!("TLS handshake {addr}: {e}"))
                    })?;
            RedisStream::Tls(Box::new(tls_stream))
        } else {
            RedisStream::Plain(tcp)
        };

        let mut conn = Self {
            stream,
            read_buf: Vec::with_capacity(4096),
        };

        if let Some(password) = &cfg.password {
            let resp = match &cfg.username {
                Some(user) => {
                    conn.execute_raw(
                        &[b"AUTH", user.as_bytes(), password.as_bytes()],
                        cfg.command_timeout,
                    )
                    .await?
                }
                None => {
                    conn.execute_raw(&[b"AUTH", password.as_bytes()], cfg.command_timeout)
                        .await?
                }
            };
            if let RespValue::Error(msg) = resp {
                return Err(DistributedStoreError::Command(format!(
                    "AUTH failed: {msg}"
                )));
            }
        }

        if cfg.db != 0 {
            let db_str = cfg.db.to_string();
            let resp = conn
                .execute_raw(&[b"SELECT", db_str.as_bytes()], cfg.command_timeout)
                .await?;
            if let RespValue::Error(msg) = resp {
                return Err(DistributedStoreError::Command(format!(
                    "SELECT {} failed: {msg}",
                    cfg.db
                )));
            }
        }

        Ok(conn)
    }

    async fn execute_raw(
        &mut self,
        args: &[&[u8]],
        timeout: Duration,
    ) -> Result<RespValue, DistributedStoreError> {
        let encoded = encode_resp_command(args);
        tokio::time::timeout(timeout, async {
            self.stream
                .write_all(&encoded)
                .await
                .map_err(|e| DistributedStoreError::Connection(e.to_string()))?;
            self.stream
                .flush()
                .await
                .map_err(|e| DistributedStoreError::Connection(e.to_string()))?;

            let mut tmp = [0u8; 4096];
            loop {
                if let Some((val, consumed)) = decode_resp_frame(&self.read_buf)
                    .map_err(|e| DistributedStoreError::Protocol(e.to_string()))?
                {
                    self.read_buf.drain(..consumed);
                    return Ok(val);
                }
                let n = self
                    .stream
                    .read(&mut tmp)
                    .await
                    .map_err(|e| DistributedStoreError::Connection(e.to_string()))?;
                if n == 0 {
                    return Err(DistributedStoreError::Connection(
                        "unexpected EOF from Redis/Valkey server".to_owned(),
                    ));
                }
                self.read_buf.extend_from_slice(&tmp[..n]);
            }
        })
        .await
        .map_err(|_| DistributedStoreError::Timeout(timeout))?
    }
}

/// Pure-Rust, zero-external-SDK pooled Redis / Valkey [`DistributedStore`] backend.
pub struct RedisStateStore {
    config: RedisStoreConfig,
    idle: Mutex<Vec<RedisConn>>,
    permits: Semaphore,
}

impl fmt::Debug for RedisStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisStateStore")
            .field("config", &self.config)
            .finish()
    }
}

impl RedisStateStore {
    pub fn new(mut config: RedisStoreConfig) -> Self {
        config.pool_size = config.pool_size.max(1);
        let pool_size = config.pool_size;
        Self {
            config,
            idle: Mutex::new(Vec::with_capacity(pool_size)),
            permits: Semaphore::new(pool_size),
        }
    }

    pub fn config(&self) -> &RedisStoreConfig {
        &self.config
    }

    fn prefixed_key(&self, key: &str) -> String {
        if self.config.key_prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{}{key}", self.config.key_prefix)
        }
    }

    /// Executes a RESP2 command using a pooled connection, transparently retrying once
    /// if a stale idle connection was closed by the server.
    pub async fn command(&self, args: &[&[u8]]) -> Result<RespValue, DistributedStoreError> {
        let _permit = tokio::time::timeout(self.config.command_timeout, self.permits.acquire())
            .await
            .map_err(|_| DistributedStoreError::Timeout(self.config.command_timeout))?
            .map_err(|_| DistributedStoreError::Connection("pool semaphore closed".to_owned()))?;

        let existing = { self.idle.lock().await.pop() };
        if let Some(mut conn) = existing {
            match conn.execute_raw(args, self.config.command_timeout).await {
                Ok(val) => {
                    self.idle.lock().await.push(conn);
                    return Ok(val);
                }
                Err(DistributedStoreError::Connection(_)) => {
                    // Drop stale pooled connection and retry once on a fresh connection.
                }
                Err(e) => return Err(e),
            }
        }

        let mut fresh = RedisConn::connect(&self.config).await?;
        let val = fresh.execute_raw(args, self.config.command_timeout).await?;
        self.idle.lock().await.push(fresh);
        Ok(val)
    }

    /// Issues `PING` against the configured Redis / Valkey server.
    pub async fn ping(&self) -> Result<(), DistributedStoreError> {
        match self.command(&[b"PING"]).await? {
            RespValue::SimpleString(_) | RespValue::BulkString(Some(_)) => Ok(()),
            RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
            other => Err(DistributedStoreError::Protocol(format!(
                "unexpected PING reply: {other:?}"
            ))),
        }
    }
}

impl DistributedStore for RedisStateStore {
    fn backend_name(&self) -> &str {
        "redis"
    }

    fn failure_policy(&self) -> FailurePolicy {
        self.config.failure_policy
    }

    fn try_consume_quota<'a>(
        &'a self,
        key: &'a str,
        amount: u64,
        limit: u64,
        window: Duration,
    ) -> BoxFuture<'a, Result<QuotaOutcome, DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        let window_ms = window.as_millis().max(1).min(i64::MAX as u128) as i64;
        Box::pin(async move {
            let amt_s = amount.to_string();
            let lim_s = limit.to_string();
            let win_s = window_ms.to_string();
            let resp = self
                .command(&[
                    b"EVAL",
                    LUA_TRY_CONSUME_QUOTA.as_bytes(),
                    b"1",
                    full_key.as_bytes(),
                    amt_s.as_bytes(),
                    lim_s.as_bytes(),
                    win_s.as_bytes(),
                ])
                .await?;
            match resp {
                RespValue::Array(Some(items)) if items.len() == 4 => {
                    let allowed = items[0].as_i64().unwrap_or(0) != 0;
                    let current = items[1].as_i64().unwrap_or(0).max(0) as u64;
                    let remaining = items[2].as_i64().unwrap_or(0).max(0) as u64;
                    let retry_after_secs = items[3].as_i64().unwrap_or(0).max(0) as u64;
                    Ok(QuotaOutcome {
                        allowed,
                        current,
                        limit,
                        remaining,
                        retry_after_secs,
                    })
                }
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => Err(DistributedStoreError::Protocol(format!(
                    "unexpected EVAL reply for try_consume_quota: {other:?}"
                ))),
            }
        })
    }

    fn adjust_counter<'a>(
        &'a self,
        key: &'a str,
        delta: i64,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<i64, DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        let ttl_ms = ttl.as_millis().max(1).min(i64::MAX as u128) as i64;
        Box::pin(async move {
            let delta_s = delta.to_string();
            let ttl_s = ttl_ms.to_string();
            let resp = self
                .command(&[
                    b"EVAL",
                    LUA_ADJUST_COUNTER.as_bytes(),
                    b"1",
                    full_key.as_bytes(),
                    delta_s.as_bytes(),
                    ttl_s.as_bytes(),
                ])
                .await?;
            match resp {
                RespValue::Integer(n) => Ok(n),
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => other.as_i64().ok_or_else(|| {
                    DistributedStoreError::Protocol(format!(
                        "unexpected EVAL reply for adjust_counter: {other:?}"
                    ))
                }),
            }
        })
    }

    fn get_counter<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<i64, DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        Box::pin(async move {
            match self.command(&[b"GET", full_key.as_bytes()]).await? {
                RespValue::BulkString(None) => Ok(0),
                RespValue::BulkString(Some(bytes)) => {
                    let s = std::str::from_utf8(&bytes).map_err(|e| {
                        DistributedStoreError::Protocol(format!("non-UTF8 counter: {e}"))
                    })?;
                    s.trim().parse::<i64>().map_err(|e| {
                        DistributedStoreError::Protocol(format!("invalid counter `{s}`: {e}"))
                    })
                }
                RespValue::Integer(n) => Ok(n),
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => Err(DistributedStoreError::Protocol(format!(
                    "unexpected GET reply: {other:?}"
                ))),
            }
        })
    }

    fn set_flag<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        let ttl_ms = ttl.as_millis().max(1).min(i64::MAX as u128) as i64;
        Box::pin(async move {
            let ttl_s = ttl_ms.to_string();
            match self
                .command(&[b"SET", full_key.as_bytes(), b"1", b"PX", ttl_s.as_bytes()])
                .await?
            {
                RespValue::SimpleString(_) | RespValue::BulkString(Some(_)) => Ok(()),
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => Err(DistributedStoreError::Protocol(format!(
                    "unexpected SET reply: {other:?}"
                ))),
            }
        })
    }

    fn has_flag<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<bool, DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        Box::pin(async move {
            match self.command(&[b"EXISTS", full_key.as_bytes()]).await? {
                RespValue::Integer(n) => Ok(n > 0),
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => Err(DistributedStoreError::Protocol(format!(
                    "unexpected EXISTS reply: {other:?}"
                ))),
            }
        })
    }

    fn get_bytes<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<Bytes>, DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        Box::pin(async move {
            match self.command(&[b"GET", full_key.as_bytes()]).await? {
                RespValue::BulkString(None) => Ok(None),
                RespValue::BulkString(Some(bytes)) => Ok(Some(Bytes::from(bytes))),
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => Err(DistributedStoreError::Protocol(format!(
                    "unexpected GET reply: {other:?}"
                ))),
            }
        })
    }

    fn set_bytes<'a>(
        &'a self,
        key: &'a str,
        value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        let ttl_ms = ttl.as_millis().max(1).min(i64::MAX as u128) as i64;
        Box::pin(async move {
            let ttl_s = ttl_ms.to_string();
            match self
                .command(&[
                    b"SET",
                    full_key.as_bytes(),
                    value.as_ref(),
                    b"PX",
                    ttl_s.as_bytes(),
                ])
                .await?
            {
                RespValue::SimpleString(_) | RespValue::BulkString(Some(_)) => Ok(()),
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => Err(DistributedStoreError::Protocol(format!(
                    "unexpected SET reply: {other:?}"
                ))),
            }
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), DistributedStoreError>> {
        let full_key = self.prefixed_key(key);
        Box::pin(async move {
            match self.command(&[b"DEL", full_key.as_bytes()]).await? {
                RespValue::Integer(_) => Ok(()),
                RespValue::Error(e) => Err(DistributedStoreError::Command(e)),
                other => Err(DistributedStoreError::Protocol(format!(
                    "unexpected DEL reply: {other:?}"
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Default)]
    struct MockRedisState {
        entries: HashMap<String, (String, Option<Instant>)>,
        required_password: Option<String>,
        selected_dbs: Vec<u8>,
    }

    impl MockRedisState {
        fn prune(&mut self) {
            let now = Instant::now();
            self.entries
                .retain(|_, (_, exp)| exp.map(|t| now < t).unwrap_or(true));
        }
    }

    async fn spawn_mock_redis(
        required_password: Option<String>,
    ) -> (
        SocketAddr,
        Arc<Mutex<MockRedisState>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(MockRedisState {
            required_password,
            ..Default::default()
        }));
        let state_clone = Arc::clone(&state);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let st = Arc::clone(&state_clone);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let mut authed = st.lock().unwrap().required_password.is_none();
                    while let Ok(n) = socket.read(&mut tmp).await {
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        while let Ok(Some((val, consumed))) = decode_resp_frame(&buf) {
                            buf.drain(..consumed);
                            let reply = handle_mock_cmd(val, &st, &mut authed);
                            let mut out = Vec::new();
                            encode_resp_value(&reply, &mut out);
                            if socket.write_all(&out).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });

        (addr, state, handle)
    }

    fn handle_mock_cmd(
        val: RespValue,
        state: &Arc<Mutex<MockRedisState>>,
        authed: &mut bool,
    ) -> RespValue {
        let RespValue::Array(Some(items)) = val else {
            return RespValue::Error("ERR expected array".to_owned());
        };
        let args: Vec<String> = items
            .into_iter()
            .filter_map(|v| match v {
                RespValue::BulkString(Some(b)) => Some(String::from_utf8_lossy(&b).into_owned()),
                RespValue::SimpleString(s) => Some(s),
                _ => None,
            })
            .collect();
        if args.is_empty() {
            return RespValue::Error("ERR empty command".to_owned());
        }
        let cmd = args[0].to_ascii_uppercase();
        if cmd == "AUTH" {
            let guard = state.lock().unwrap();
            let provided = args.last().cloned().unwrap_or_default();
            if guard.required_password.as_deref() == Some(provided.as_str()) {
                *authed = true;
                return RespValue::SimpleString("OK".to_owned());
            }
            return RespValue::Error("WRONGPASS invalid password".to_owned());
        }
        if !*authed {
            return RespValue::Error("NOAUTH Authentication required".to_owned());
        }

        let mut guard = state.lock().unwrap();
        guard.prune();

        match cmd.as_str() {
            "PING" => RespValue::SimpleString("PONG".to_owned()),
            "SELECT" => {
                if let Some(db) = args.get(1).and_then(|s| s.parse::<u8>().ok()) {
                    guard.selected_dbs.push(db);
                }
                RespValue::SimpleString("OK".to_owned())
            }
            "GET" => match guard.entries.get(&args[1]) {
                Some((v, _)) => RespValue::BulkString(Some(v.as_bytes().to_vec())),
                None => RespValue::BulkString(None),
            },
            "SET" => {
                let key = args[1].clone();
                let val = args[2].clone();
                let mut exp = None;
                if args.len() >= 5
                    && args[3].eq_ignore_ascii_case("PX")
                    && let Ok(ms) = args[4].parse::<u64>()
                {
                    exp = Some(Instant::now() + Duration::from_millis(ms));
                }
                guard.entries.insert(key, (val, exp));
                RespValue::SimpleString("OK".to_owned())
            }
            "EXISTS" => {
                let exists = i64::from(guard.entries.contains_key(&args[1]));
                RespValue::Integer(exists)
            }
            "DEL" => {
                let removed = i64::from(guard.entries.remove(&args[1]).is_some());
                RespValue::Integer(removed)
            }
            "EVAL" => {
                let script = &args[1];
                let key = args[3].clone();
                if script.contains("INCRBY") {
                    let amt: i64 = args[4].parse().unwrap_or(0);
                    let lim: i64 = args[5].parse().unwrap_or(0);
                    let win: u64 = args[6].parse().unwrap_or(1000);
                    let (cur, existing_exp) = guard
                        .entries
                        .get(&key)
                        .map(|(v, e)| (v.parse::<i64>().unwrap_or(0), *e))
                        .unwrap_or((0, None));
                    if cur + amt <= lim {
                        let nxt = cur + amt;
                        let exp = existing_exp
                            .unwrap_or_else(|| Instant::now() + Duration::from_millis(win));
                        guard.entries.insert(key, (nxt.to_string(), Some(exp)));
                        RespValue::Array(Some(vec![
                            RespValue::Integer(1),
                            RespValue::Integer(nxt),
                            RespValue::Integer((lim - nxt).max(0)),
                            RespValue::Integer(0),
                        ]))
                    } else {
                        let pttl = existing_exp
                            .map(|t| t.saturating_duration_since(Instant::now()).as_millis() as u64)
                            .unwrap_or(win);
                        let retry = pttl.div_ceil(1000).max(1) as i64;
                        RespValue::Array(Some(vec![
                            RespValue::Integer(0),
                            RespValue::Integer(cur),
                            RespValue::Integer((lim - cur).max(0)),
                            RespValue::Integer(retry),
                        ]))
                    }
                } else {
                    // adjust_counter
                    let delta: i64 = args[4].parse().unwrap_or(0);
                    let ttl: u64 = args[5].parse().unwrap_or(1000);
                    let (cur, existing_exp) = guard
                        .entries
                        .get(&key)
                        .map(|(v, e)| (v.parse::<i64>().unwrap_or(0), *e))
                        .unwrap_or((0, None));
                    let nxt = (cur + delta).max(0);
                    let exp =
                        existing_exp.unwrap_or_else(|| Instant::now() + Duration::from_millis(ttl));
                    guard.entries.insert(key, (nxt.to_string(), Some(exp)));
                    RespValue::Integer(nxt)
                }
            }
            _ => RespValue::Error(format!("ERR unknown command `{cmd}`")),
        }
    }

    #[test]
    fn parses_redis_urls() {
        let c1 = RedisStoreConfig::from_url("redis://127.0.0.1:6379").unwrap();
        assert_eq!(c1.host, "127.0.0.1");
        assert_eq!(c1.port, 6379);
        assert!(!c1.tls);
        assert_eq!(c1.db, 0);

        let c2 = RedisStoreConfig::from_url("rediss://alice:s%40cret@valkey.local:6380/3").unwrap();
        assert!(c2.tls);
        assert_eq!(c2.username.as_deref(), Some("alice"));
        assert_eq!(c2.password.as_deref(), Some("s@cret"));
        assert_eq!(c2.host, "valkey.local");
        assert_eq!(c2.port, 6380);
        assert_eq!(c2.db, 3);

        let c3 = RedisStoreConfig::from_url("redis://[::1]:6399/1").unwrap();
        assert_eq!(c3.host, "::1");
        assert_eq!(c3.port, 6399);
        assert_eq!(c3.db, 1);

        assert!(RedisStoreConfig::from_url("http://127.0.0.1:6379").is_err());
    }

    #[test]
    fn resp2_round_trip_and_bounds() {
        let sample = RespValue::Array(Some(vec![
            RespValue::SimpleString("OK".to_owned()),
            RespValue::Error("ERR nope".to_owned()),
            RespValue::Integer(-42),
            RespValue::BulkString(Some(b"hello\r\nworld".to_vec())),
            RespValue::BulkString(None),
            RespValue::Array(None),
        ]));
        let mut wire = Vec::new();
        encode_resp_value(&sample, &mut wire);

        // Partial prefixes return Ok(None)
        for cut in 0..wire.len() {
            assert_eq!(decode_resp_frame(&wire[..cut]), Ok(None));
        }
        let (decoded, consumed) = decode_resp_frame(&wire).unwrap().unwrap();
        assert_eq!(decoded, sample);
        assert_eq!(consumed, wire.len());
    }

    #[tokio::test]
    async fn redis_state_store_round_trip_against_mock_server() {
        let (addr, state, handle) = spawn_mock_redis(Some("secret123".to_owned())).await;
        let url = format!("redis://:secret123@{addr}/2");
        let cfg = RedisStoreConfig::from_url(&url).unwrap();
        let store = RedisStateStore::new(cfg);

        store.ping().await.unwrap();
        assert_eq!(state.lock().unwrap().selected_dbs, vec![2]);

        // Quota consume & reject
        let q1 = store
            .try_consume_quota("rpm:alice", 6, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(q1.allowed);
        assert_eq!(q1.current, 6);
        assert_eq!(q1.remaining, 4);

        let q2 = store
            .try_consume_quota("rpm:alice", 5, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!q2.allowed);
        assert_eq!(q2.current, 6);
        assert!(q2.retry_after_secs >= 1);

        // Adjust counter positive and negative (clamped at 0)
        assert_eq!(
            store
                .adjust_counter("spend:alice", 500, Duration::from_secs(60))
                .await
                .unwrap(),
            500
        );
        assert_eq!(store.get_counter("spend:alice").await.unwrap(), 500);
        assert_eq!(
            store
                .adjust_counter("spend:alice", -900, Duration::from_secs(60))
                .await
                .unwrap(),
            0
        );

        // Flags
        assert!(!store.has_flag("cd:openai").await.unwrap());
        store
            .set_flag("cd:openai", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(store.has_flag("cd:openai").await.unwrap());
        store.delete("cd:openai").await.unwrap();
        assert!(!store.has_flag("cd:openai").await.unwrap());

        handle.abort();
    }
}
