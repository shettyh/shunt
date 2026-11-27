//! Pure-Rust JWT / JWKS / OIDC authentication plugin built strictly on `shunt-plugin-sdk`
//! and `ring` (zero external JWT or HTTP transport crates).
//!
//! Supports:
//! - Algorithms: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`,
//!   `PS512`, `ES256`, `ES384`, `EdDSA` (unconditionally rejects `alg: "none"` and prevents
//!   key-type confusion attacks).
//! - Key sources: remote `jwks_uri`, OIDC Discovery (`oidc_discovery_url` / `oidc_discovery`),
//!   inline/file static JWKS, and static HMAC secrets or PEM SPKI public keys.
//! - Zero-allocation sync fast path (`HookResult::Ready`) whenever JWKS is warm or static keys
//!   are used; singleflight coalesced async refresh (`HookResult::Pending`) on cold cache,
//!   TTL expiry, or unknown `kid` rotation (with anti-DoS minimum refresh cooldown).

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ring::hmac;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::{Map, Value};
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Clock, Flow, HeaderName, HeaderValue, HookMask, HookResult,
    HttpClient, HttpPlugin, HttpRequest, PluginBuildError, PluginConfig, PluginFactory, RequestCtx,
    RequestHead, StatusCode, Uri, header,
};
use tracing::warn;

use crate::bearer_auth::AuthSubject;

const DEFAULT_JWKS_CACHE_TTL_SECS: u64 = 300;
const DEFAULT_JWKS_MIN_REFRESH_SECS: u64 = 10;
const DEFAULT_JWKS_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_JWKS_MAX_BYTES: usize = 512 * 1024;
const DEFAULT_CLOCK_SKEW_SECS: u64 = 60;

/// Verified JWT payload claims attached to [`RequestCtx::extensions`] on successful auth.
#[derive(Debug, Clone)]
pub struct JwtClaims(pub Map<String, Value>);

impl JwtClaims {
    /// Resolves a dot-separated claim path (e.g. `"sub"`, `"org.id"`, `"realm_access.roles"`).
    pub fn get_path(&self, path: &str) -> Option<&Value> {
        let mut segments = path.split('.');
        let first = segments.next()?;
        let mut cur = self.0.get(first)?;
        for seg in segments {
            cur = cur.as_object()?.get(seg)?;
        }
        Some(cur)
    }
}

/// Supported JWS signing algorithms (RFC 7518).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtAlgorithm {
    Hs256,
    Hs384,
    Hs512,
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    EdDsa,
}

impl JwtAlgorithm {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "HS256" => Some(Self::Hs256),
            "HS384" => Some(Self::Hs384),
            "HS512" => Some(Self::Hs512),
            "RS256" => Some(Self::Rs256),
            "RS384" => Some(Self::Rs384),
            "RS512" => Some(Self::Rs512),
            "PS256" => Some(Self::Ps256),
            "PS384" => Some(Self::Ps384),
            "PS512" => Some(Self::Ps512),
            "ES256" => Some(Self::Es256),
            "ES384" => Some(Self::Es384),
            "EdDSA" => Some(Self::EdDsa),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
        }
    }
}

/// Compiled verification key material (strictly typed to prevent algorithm confusion attacks).
#[derive(Debug, Clone)]
pub enum VerificationKeyMaterial {
    Hmac(Vec<u8>),
    Rsa { n: Vec<u8>, e: Vec<u8> },
    EcP256(Vec<u8>),  // 65-byte uncompressed SEC1 point 0x04 || x || y
    EcP384(Vec<u8>),  // 97-byte uncompressed SEC1 point 0x04 || x || y
    Ed25519(Vec<u8>), // 32-byte raw public key
}

/// Compiled JWK / static verification key entry.
#[derive(Debug, Clone)]
pub struct VerificationKey {
    pub kid: Option<String>,
    pub alg: Option<JwtAlgorithm>,
    pub material: VerificationKeyMaterial,
}

impl VerificationKey {
    /// Verifies `sig` over `signing_input` using `alg`, enforcing strict key-type compatibility.
    pub fn verify(&self, alg: JwtAlgorithm, signing_input: &[u8], sig: &[u8]) -> bool {
        if let Some(key_alg) = self.alg
            && key_alg != alg
        {
            return false;
        }
        match (&self.material, alg) {
            (VerificationKeyMaterial::Hmac(secret), JwtAlgorithm::Hs256) => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
                hmac::verify(&key, signing_input, sig).is_ok()
            }
            (VerificationKeyMaterial::Hmac(secret), JwtAlgorithm::Hs384) => {
                let key = hmac::Key::new(hmac::HMAC_SHA384, secret);
                hmac::verify(&key, signing_input, sig).is_ok()
            }
            (VerificationKeyMaterial::Hmac(secret), JwtAlgorithm::Hs512) => {
                let key = hmac::Key::new(hmac::HMAC_SHA512, secret);
                hmac::verify(&key, signing_input, sig).is_ok()
            }
            (VerificationKeyMaterial::Rsa { n, e }, JwtAlgorithm::Rs256) => {
                RsaPublicKeyComponents { n, e }
                    .verify(&signature::RSA_PKCS1_2048_8192_SHA256, signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::Rsa { n, e }, JwtAlgorithm::Rs384) => {
                RsaPublicKeyComponents { n, e }
                    .verify(&signature::RSA_PKCS1_2048_8192_SHA384, signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::Rsa { n, e }, JwtAlgorithm::Rs512) => {
                RsaPublicKeyComponents { n, e }
                    .verify(&signature::RSA_PKCS1_2048_8192_SHA512, signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::Rsa { n, e }, JwtAlgorithm::Ps256) => {
                RsaPublicKeyComponents { n, e }
                    .verify(&signature::RSA_PSS_2048_8192_SHA256, signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::Rsa { n, e }, JwtAlgorithm::Ps384) => {
                RsaPublicKeyComponents { n, e }
                    .verify(&signature::RSA_PSS_2048_8192_SHA384, signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::Rsa { n, e }, JwtAlgorithm::Ps512) => {
                RsaPublicKeyComponents { n, e }
                    .verify(&signature::RSA_PSS_2048_8192_SHA512, signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::EcP256(pt), JwtAlgorithm::Es256) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, pt)
                    .verify(signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::EcP384(pt), JwtAlgorithm::Es384) => {
                UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, pt)
                    .verify(signing_input, sig)
                    .is_ok()
            }
            (VerificationKeyMaterial::Ed25519(pk), JwtAlgorithm::EdDsa) => {
                UnparsedPublicKey::new(&signature::ED25519, pk)
                    .verify(signing_input, sig)
                    .is_ok()
            }
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticKeySpec {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    /// HMAC shared secret (plain UTF-8 or `env:VAR` or `b64url:...`).
    #[serde(default)]
    secret: Option<String>,
    /// PEM-encoded SPKI public key (`-----BEGIN PUBLIC KEY-----`, plain or `env:VAR`).
    #[serde(default)]
    public_key_pem: Option<String>,
    /// Path to PEM-encoded SPKI public key file.
    #[serde(default)]
    public_key_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JwtAuthConfig {
    /// Remote JWKS endpoint URL (e.g. `https://auth.example.com/.well-known/jwks.json`).
    jwks_uri: Option<String>,
    /// Optional OIDC discovery URL (e.g. `https://auth.example.com/.well-known/openid-configuration`).
    oidc_discovery_url: Option<String>,
    /// Auto-discover `jwks_uri` from `<issuer>/.well-known/openid-configuration` when `jwks_uri` is unset.
    oidc_discovery: bool,
    /// Inline static JWKS JSON string (supports `env:VAR`).
    jwks_inline: Option<String>,
    /// Local path to a static JWKS JSON file.
    jwks_file: Option<PathBuf>,
    /// Static HMAC secrets or PEM public keys.
    keys: Vec<StaticKeySpec>,
    /// Allowed JWS algorithms (default: `["RS256", "ES256", "EdDSA"]`, or inferred from static HMAC keys if empty).
    algorithms: Vec<String>,
    /// Single required `iss` value (shorthand for `issuers = [issuer]`).
    issuer: Option<String>,
    /// Allowed `iss` values.
    issuers: Vec<String>,
    /// Single required `aud` value (shorthand for `audiences = [audience]`).
    audience: Option<String>,
    /// Allowed `aud` values (token's `aud` string or array must match at least one).
    audiences: Vec<String>,
    /// Require the `exp` claim to be present and valid (default: `true`).
    require_exp: bool,
    /// Clock skew leeway in seconds applied to `exp` and `nbf` checks (default: `60`).
    clock_skew_secs: u64,
    /// Required OAuth2 scopes (all must be present in space-delimited `scope` or `scp` array).
    required_scopes: Vec<String>,
    /// Exact claim assertions (`claim_path -> expected JSON value`; arrays check membership).
    required_claims: BTreeMap<String, Value>,
    /// Map JWT claim paths to forwarded request headers (incoming spoofed values are stripped first).
    forward_claims: BTreeMap<String, String>,
    /// Optional custom header to read JWT from (defaults to `Authorization: Bearer <token>`).
    header_name: Option<String>,
    /// Optional cookie name fallback for extracting JWT.
    cookie_name: Option<String>,
    /// Optional query parameter fallback for extracting JWT (opt-in; disabled by default).
    query_param: Option<String>,
    /// Strip the incoming token header after successful authentication (default: `false`).
    strip_header: bool,
    /// Allow unauthenticated requests without a token to proceed (invalid tokens still return `401`).
    allow_missing: bool,
    /// Realm advertised in `WWW-Authenticate` header (default: `"shunt"`).
    realm: String,
    /// JWKS cache TTL in seconds (default: `300`).
    jwks_cache_ttl_secs: u64,
    /// Anti-DoS minimum interval between unknown-`kid` JWKS refreshes in seconds (default: `10`).
    jwks_min_refresh_secs: u64,
    /// Outbound HTTP timeout for JWKS / OIDC discovery requests in ms (default: `5000`).
    jwks_timeout_ms: u64,
}

impl Default for JwtAuthConfig {
    fn default() -> Self {
        Self {
            jwks_uri: None,
            oidc_discovery_url: None,
            oidc_discovery: false,
            jwks_inline: None,
            jwks_file: None,
            keys: Vec::new(),
            algorithms: Vec::new(),
            issuer: None,
            issuers: Vec::new(),
            audience: None,
            audiences: Vec::new(),
            require_exp: true,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            required_scopes: Vec::new(),
            required_claims: BTreeMap::new(),
            forward_claims: BTreeMap::new(),
            header_name: None,
            cookie_name: None,
            query_param: None,
            strip_header: false,
            allow_missing: false,
            realm: "shunt".to_owned(),
            jwks_cache_ttl_secs: DEFAULT_JWKS_CACHE_TTL_SECS,
            jwks_min_refresh_secs: DEFAULT_JWKS_MIN_REFRESH_SECS,
            jwks_timeout_ms: DEFAULT_JWKS_TIMEOUT_MS,
        }
    }
}

/// Reload-persistent JWKS cache stored in [`shunt_plugin_sdk::StateStore`] with singleflight
/// coalescing (pure `std`, zero `tokio` dependency).
struct JwksCache {
    state: RwLock<JwksCacheInner>,
    flight: Mutex<FlightState>,
}

#[derive(Default)]
struct JwksCacheInner {
    keys: Vec<VerificationKey>,
    fetched_at: Option<Duration>,
    last_refresh_attempt: Option<Duration>,
    discovered_jwks_uri: Option<String>,
}

#[derive(Default)]
struct FlightState {
    in_flight: bool,
    waiters: Vec<Waker>,
}

impl JwksCache {
    fn new() -> Self {
        Self {
            state: RwLock::new(JwksCacheInner::default()),
            flight: Mutex::new(FlightState::default()),
        }
    }

    fn try_acquire_leader(&self) -> bool {
        let mut g = self.flight.lock().expect("JwksCache flight lock poisoned");
        if g.in_flight {
            false
        } else {
            g.in_flight = true;
            true
        }
    }

    fn release_leader(&self) {
        let waiters = {
            let mut g = self.flight.lock().expect("JwksCache flight lock poisoned");
            g.in_flight = false;
            std::mem::take(&mut g.waiters)
        };
        for w in waiters {
            w.wake();
        }
    }

    fn wait_in_flight(&self) -> WaitFlight<'_> {
        WaitFlight { cache: self }
    }
}

struct LeaderGuard<'a>(&'a JwksCache);

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        self.0.release_leader();
    }
}

struct WaitFlight<'a> {
    cache: &'a JwksCache,
}

impl Future for WaitFlight<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut g = self
            .cache
            .flight
            .lock()
            .expect("JwksCache flight lock poisoned");
        if !g.in_flight {
            Poll::Ready(())
        } else {
            g.waiters.push(cx.waker().clone());
            Poll::Pending
        }
    }
}

pub struct JwtAuthFactory;

impl PluginFactory for JwtAuthFactory {
    fn name(&self) -> &str {
        "jwt-auth"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: JwtAuthConfig = config.deserialize(self.name())?;

        let mut issuers = cfg.issuers;
        if let Some(iss) = cfg.issuer {
            issuers.push(iss);
        }
        let mut audiences = cfg.audiences;
        if let Some(aud) = cfg.audience {
            audiences.push(aud);
        }

        let oidc_discovery_url = if let Some(url) = cfg.oidc_discovery_url {
            Some(url)
        } else if cfg.oidc_discovery {
            let base = issuers
                .first()
                .ok_or_else(|| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "`oidc_discovery = true` requires `issuer` or `oidc_discovery_url`"
                        .to_owned(),
                })?;
            Some(format!(
                "{}/.well-known/openid-configuration",
                base.trim_end_matches('/')
            ))
        } else {
            None
        };

        let mut static_keys = Vec::new();
        if let Some(raw_jwks) = &cfg.jwks_inline {
            let resolved = resolve_env(raw_jwks, self.name(), "jwks_inline")?;
            static_keys.extend(parse_jwks_json(&resolved).map_err(|msg| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("jwks_inline: {msg}"),
                }
            })?);
        }
        if let Some(path) = &cfg.jwks_file {
            let raw = std::fs::read_to_string(path).map_err(|e| PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("failed to read jwks_file `{}`: {e}", path.display()),
            })?;
            static_keys.extend(parse_jwks_json(&raw).map_err(|msg| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("jwks_file `{}`: {msg}", path.display()),
                }
            })?);
        }
        for spec in cfg.keys {
            static_keys.push(compile_static_key(self.name(), spec)?);
        }

        if cfg.jwks_uri.is_none() && oidc_discovery_url.is_none() && static_keys.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "jwt-auth requires `jwks_uri`, `oidc_discovery_url`, `jwks_inline`, `jwks_file`, or `keys`".to_owned(),
            });
        }

        let allowed_algorithms = if cfg.algorithms.is_empty() {
            let has_hmac = static_keys
                .iter()
                .any(|k| matches!(k.material, VerificationKeyMaterial::Hmac(_)));
            if has_hmac && cfg.jwks_uri.is_none() && oidc_discovery_url.is_none() {
                vec![
                    JwtAlgorithm::Hs256,
                    JwtAlgorithm::Hs384,
                    JwtAlgorithm::Hs512,
                ]
            } else {
                vec![
                    JwtAlgorithm::Rs256,
                    JwtAlgorithm::Es256,
                    JwtAlgorithm::EdDsa,
                ]
            }
        } else {
            let mut algs = Vec::with_capacity(cfg.algorithms.len());
            for a in cfg.algorithms {
                let parsed =
                    JwtAlgorithm::parse(&a).ok_or_else(|| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("unsupported or disallowed JWT algorithm `{a}`"),
                    })?;
                algs.push(parsed);
            }
            algs
        };

        let header_name = match cfg.header_name {
            Some(raw) => Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid `header_name` `{raw}`: {e}"),
                }
            })?),
            None => None,
        };

        let mut forward_claims = Vec::with_capacity(cfg.forward_claims.len());
        for (claim_path, hdr_str) in cfg.forward_claims {
            let hn = HeaderName::from_bytes(hdr_str.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!(
                        "invalid header name `{hdr_str}` in `forward_claims.{claim_path}`: {e}"
                    ),
                }
            })?;
            forward_claims.push((claim_path, hn));
        }

        if let Some(uri) = &cfg.jwks_uri {
            validate_http_url(uri, self.name(), "jwks_uri")?;
        }
        if let Some(uri) = &oidc_discovery_url {
            validate_http_url(uri, self.name(), "oidc_discovery_url")?;
        }

        let www_authenticate = HeaderValue::from_str(&format!("Bearer realm=\"{}\"", cfg.realm))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer"));

        let http_client = ctx.http_client();
        if (cfg.jwks_uri.is_some() || oidc_discovery_url.is_some()) && http_client.is_none() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`jwks_uri` / `oidc_discovery_url` requires an outbound `HttpClient` on BuildContext".to_owned(),
            });
        }

        let jwks_cache = if cfg.jwks_uri.is_some() || oidc_discovery_url.is_some() {
            let cache_key = format!(
                "jwks:{}:{}",
                cfg.jwks_uri.as_deref().unwrap_or(""),
                oidc_discovery_url.as_deref().unwrap_or("")
            );
            Some(ctx.state_handle().get_or_init(&cache_key, JwksCache::new))
        } else {
            None
        };

        Ok(Arc::new(JwtAuthPlugin {
            jwks_uri: cfg.jwks_uri,
            oidc_discovery_url,
            static_keys,
            allowed_algorithms,
            issuers,
            audiences,
            require_exp: cfg.require_exp,
            clock_skew_secs: cfg.clock_skew_secs,
            required_scopes: cfg.required_scopes,
            required_claims: cfg.required_claims,
            forward_claims,
            header_name,
            cookie_name: cfg.cookie_name,
            query_param: cfg.query_param,
            strip_header: cfg.strip_header,
            allow_missing: cfg.allow_missing,
            www_authenticate,
            jwks_cache_ttl: Duration::from_secs(cfg.jwks_cache_ttl_secs.max(1)),
            jwks_min_refresh: Duration::from_secs(cfg.jwks_min_refresh_secs),
            jwks_timeout: Duration::from_millis(cfg.jwks_timeout_ms.max(100)),
            clock: ctx.clock(),
            http_client,
            jwks_cache,
        }))
    }
}

fn validate_http_url(raw: &str, plugin: &str, field: &str) -> Result<(), PluginBuildError> {
    let uri: Uri = raw.parse().map_err(|e| PluginBuildError::BuildFailed {
        plugin: plugin.to_owned(),
        message: format!("{field}: invalid URL `{raw}`: {e}"),
    })?;
    let scheme = uri.scheme_str().unwrap_or("");
    if (scheme != "http" && scheme != "https") || uri.authority().is_none() {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("{field}: `{raw}` must be an absolute http:// or https:// URL"),
        });
    }
    Ok(())
}

fn resolve_env(raw: &str, plugin: &str, field: &str) -> Result<String, PluginBuildError> {
    if let Some(var) = raw.strip_prefix("env:") {
        std::env::var(var).map_err(|_| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("{field}: environment variable `{var}` is not set"),
        })
    } else {
        Ok(raw.to_owned())
    }
}

fn compile_static_key(
    plugin: &str,
    spec: StaticKeySpec,
) -> Result<VerificationKey, PluginBuildError> {
    let alg = match spec.alg {
        Some(a) => Some(
            JwtAlgorithm::parse(&a).ok_or_else(|| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("unsupported JWT algorithm `{a}` in static key"),
            })?,
        ),
        None => None,
    };

    let sources = usize::from(spec.secret.is_some())
        + usize::from(spec.public_key_pem.is_some())
        + usize::from(spec.public_key_file.is_some());
    if sources != 1 {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: "each static key must specify exactly one of `secret`, `public_key_pem`, or `public_key_file`".to_owned(),
        });
    }

    let material = if let Some(raw_secret) = spec.secret {
        let resolved = resolve_env(&raw_secret, plugin, "keys[].secret")?;
        let bytes = if let Some(b64) = resolved.strip_prefix("b64url:") {
            base64url_decode(b64).map_err(|msg| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid b64url secret: {msg}"),
            })?
        } else {
            resolved.into_bytes()
        };
        if bytes.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: "static HMAC secret cannot be empty".to_owned(),
            });
        }
        VerificationKeyMaterial::Hmac(bytes)
    } else {
        let pem = if let Some(inline) = spec.public_key_pem {
            resolve_env(&inline, plugin, "keys[].public_key_pem")?
        } else {
            let path = spec.public_key_file.expect("checked sources == 1");
            std::fs::read_to_string(&path).map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("failed to read public_key_file `{}`: {e}", path.display()),
            })?
        };
        parse_spki_pem_public_key(&pem).map_err(|msg| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid public key PEM: {msg}"),
        })?
    };

    Ok(VerificationKey {
        kid: spec.kid,
        alg,
        material,
    })
}

pub struct JwtAuthPlugin {
    jwks_uri: Option<String>,
    oidc_discovery_url: Option<String>,
    static_keys: Vec<VerificationKey>,
    allowed_algorithms: Vec<JwtAlgorithm>,
    issuers: Vec<String>,
    audiences: Vec<String>,
    require_exp: bool,
    clock_skew_secs: u64,
    required_scopes: Vec<String>,
    required_claims: BTreeMap<String, Value>,
    forward_claims: Vec<(String, HeaderName)>,
    header_name: Option<HeaderName>,
    cookie_name: Option<String>,
    query_param: Option<String>,
    strip_header: bool,
    allow_missing: bool,
    www_authenticate: HeaderValue,
    jwks_cache_ttl: Duration,
    jwks_min_refresh: Duration,
    jwks_timeout: Duration,
    clock: Arc<dyn Clock>,
    http_client: Option<Arc<dyn HttpClient>>,
    jwks_cache: Option<Arc<JwksCache>>,
}

/// Parsed unverified JWT segments.
#[derive(Debug)]
pub struct ParsedJwt<'a> {
    pub signing_input: &'a [u8],
    pub alg: JwtAlgorithm,
    pub kid: Option<String>,
    pub claims: Map<String, Value>,
    pub signature: Vec<u8>,
}

/// Parses and structurally validates a compact JWS (`header.payload.signature`) without
/// verifying its cryptographic signature yet.
pub fn parse_jwt_unverified(token: &str) -> Result<ParsedJwt<'_>, &'static str> {
    let mut parts = token.split('.');
    let header_b64 = parts.next().ok_or("malformed_jwt")?;
    let payload_b64 = parts.next().ok_or("malformed_jwt")?;
    let sig_b64 = parts.next().ok_or("malformed_jwt")?;
    if parts.next().is_some()
        || header_b64.is_empty()
        || payload_b64.is_empty()
        || sig_b64.is_empty()
    {
        return Err("malformed_jwt");
    }

    let header_bytes = base64url_decode(header_b64).map_err(|_| "invalid_jwt_header_encoding")?;
    let header_json: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| "invalid_jwt_header_json")?;
    let header_obj = header_json.as_object().ok_or("invalid_jwt_header_json")?;

    // Reject unknown critical header parameters per RFC 7515 §4.1.11.
    if let Some(crit) = header_obj.get("crit")
        && crit.as_array().map(|a| !a.is_empty()).unwrap_or(true)
    {
        return Err("unsupported_jwt_crit_header");
    }

    let alg_str = header_obj
        .get("alg")
        .and_then(Value::as_str)
        .ok_or("missing_jwt_alg")?;
    if alg_str.eq_ignore_ascii_case("none") {
        return Err("disallowed_jwt_alg_none");
    }
    let alg = JwtAlgorithm::parse(alg_str).ok_or("unsupported_jwt_alg")?;

    let kid = match header_obj.get("kid") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(_) => return Err("invalid_jwt_kid"),
        None => None,
    };

    let payload_bytes =
        base64url_decode(payload_b64).map_err(|_| "invalid_jwt_payload_encoding")?;
    let payload_json: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| "invalid_jwt_payload_json")?;
    let claims = match payload_json {
        Value::Object(map) => map,
        _ => return Err("invalid_jwt_payload_json"),
    };

    let signature = base64url_decode(sig_b64).map_err(|_| "invalid_jwt_signature_encoding")?;
    let signing_input = &token.as_bytes()[..header_b64.len() + 1 + payload_b64.len()];

    Ok(ParsedJwt {
        signing_input,
        alg,
        kid,
        claims,
        signature,
    })
}

enum VerifyKeyOutcome {
    Verified,
    InvalidSignature,
    UnknownKid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenSource {
    Header,
    Cookie,
    Query,
}

impl JwtAuthPlugin {
    fn extract_token(
        &self,
        req: &RequestHead,
    ) -> Result<Option<(String, TokenSource)>, &'static str> {
        let mut selected: Option<(String, TokenSource)> = None;

        if let Some(hdr) = &self.header_name {
            let mut vals = req.headers.get_all(hdr).iter();
            if let Some(first) = vals.next() {
                if vals.next().is_some() {
                    return Err("multiple_authorization_headers");
                }
                if let Ok(raw) = first.to_str() {
                    let trimmed = raw.trim();
                    let tok = strip_bearer_prefix(trimmed).unwrap_or(trimmed).trim();
                    if !tok.is_empty() {
                        selected = Some((tok.to_owned(), TokenSource::Header));
                    }
                }
            }
        } else {
            let mut vals = req.headers.get_all(header::AUTHORIZATION).iter();
            if let Some(first) = vals.next() {
                if vals.next().is_some() {
                    return Err("multiple_authorization_headers");
                }
                if let Ok(raw) = first.to_str() {
                    let trimmed = raw.trim();
                    if let Some(tok) = strip_bearer_prefix(trimmed).map(str::trim)
                        && !tok.is_empty()
                    {
                        selected = Some((tok.to_owned(), TokenSource::Header));
                    }
                }
            }
        }

        if let Some(cookie_name) = &self.cookie_name {
            let mut seen_cookie = false;
            let mut found: Option<String> = None;
            for val in req.headers.get_all(header::COOKIE) {
                if let Ok(s) = val.to_str() {
                    for pair in s.split(';') {
                        if let Some((k, v)) = pair.trim().split_once('=')
                            && k.trim() == cookie_name
                        {
                            if seen_cookie {
                                return Err("multiple_auth_cookies");
                            }
                            seen_cookie = true;
                            let trimmed = v.trim();
                            if !trimmed.is_empty() {
                                found = Some(trimmed.to_owned());
                            }
                        }
                    }
                }
            }
            if let Some(tok) = found {
                if selected.is_some() {
                    return Err("multiple_auth_sources");
                }
                selected = Some((tok, TokenSource::Cookie));
            }
        }

        if let Some(qp) = &self.query_param
            && let Some(query) = req.uri.query()
        {
            let mut seen_param = false;
            let mut found: Option<String> = None;
            for pair in query.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                if k == qp {
                    if seen_param {
                        return Err("multiple_auth_query_params");
                    }
                    seen_param = true;
                    if !v.is_empty() {
                        found = Some(v.to_owned());
                    }
                }
            }
            if let Some(tok) = found {
                if selected.is_some() {
                    return Err("multiple_auth_sources");
                }
                selected = Some((tok, TokenSource::Query));
            }
        }

        Ok(selected)
    }

    fn strip_forwarded_claim_headers(&self, req: &mut RequestHead) {
        for (_, hdr) in &self.forward_claims {
            req.headers.remove(hdr);
        }
    }

    fn unauthorized(&self, code: &'static str) -> BufferedResponse {
        BufferedResponse::json(StatusCode::UNAUTHORIZED, format!(r#"{{"error":"{code}"}}"#))
            .with_header(header::WWW_AUTHENTICATE, self.www_authenticate.clone())
    }

    fn forbidden(&self, code: &'static str) -> BufferedResponse {
        BufferedResponse::json(StatusCode::FORBIDDEN, format!(r#"{{"error":"{code}"}}"#))
    }

    fn verify_signature_against(
        &self,
        parsed: &ParsedJwt<'_>,
        dynamic_keys: &[VerificationKey],
    ) -> VerifyKeyOutcome {
        let mut saw_matching_kid = false;
        let all_keys = self.static_keys.iter().chain(dynamic_keys.iter());

        if let Some(ref kid) = parsed.kid {
            for key in all_keys {
                if key.kid.as_deref() == Some(kid.as_str()) {
                    saw_matching_kid = true;
                    if key.verify(parsed.alg, parsed.signing_input, &parsed.signature) {
                        return VerifyKeyOutcome::Verified;
                    }
                }
            }
            // Fallback: static keys without a `kid` can verify tokens carrying a `kid` when no kid matched.
            if !saw_matching_kid {
                for key in &self.static_keys {
                    if key.kid.is_none()
                        && key.verify(parsed.alg, parsed.signing_input, &parsed.signature)
                    {
                        return VerifyKeyOutcome::Verified;
                    }
                }
                return VerifyKeyOutcome::UnknownKid;
            }
            VerifyKeyOutcome::InvalidSignature
        } else {
            for key in all_keys {
                if key.verify(parsed.alg, parsed.signing_input, &parsed.signature) {
                    return VerifyKeyOutcome::Verified;
                }
            }
            VerifyKeyOutcome::InvalidSignature
        }
    }

    fn validate_claims(
        &self,
        claims: &Map<String, Value>,
    ) -> Result<(), (StatusCode, &'static str)> {
        let now_secs = self.clock.unix_timestamp_secs();

        // `exp` (Expiration Time)
        match claims.get("exp") {
            Some(v) => {
                let exp = value_as_u64(v).ok_or((StatusCode::UNAUTHORIZED, "invalid_exp_claim"))?;
                if now_secs > exp.saturating_add(self.clock_skew_secs) {
                    return Err((StatusCode::UNAUTHORIZED, "token_expired"));
                }
            }
            None if self.require_exp => {
                return Err((StatusCode::UNAUTHORIZED, "missing_exp_claim"));
            }
            None => {}
        }

        // `nbf` (Not Before)
        if let Some(v) = claims.get("nbf") {
            let nbf = value_as_u64(v).ok_or((StatusCode::UNAUTHORIZED, "invalid_nbf_claim"))?;
            if now_secs.saturating_add(self.clock_skew_secs) < nbf {
                return Err((StatusCode::UNAUTHORIZED, "token_not_yet_valid"));
            }
        }

        // `iss` (Issuer)
        if !self.issuers.is_empty() {
            let iss = claims
                .get("iss")
                .and_then(Value::as_str)
                .ok_or((StatusCode::UNAUTHORIZED, "invalid_issuer"))?;
            if !self.issuers.iter().any(|allowed| allowed == iss) {
                return Err((StatusCode::UNAUTHORIZED, "invalid_issuer"));
            }
        }

        // `aud` (Audience: string or array of strings per RFC 7519 §4.1.3)
        if !self.audiences.is_empty() {
            let matched = match claims.get("aud") {
                Some(Value::String(s)) => self.audiences.iter().any(|a| a == s),
                Some(Value::Array(arr)) => arr.iter().any(|item| {
                    item.as_str()
                        .map(|s| self.audiences.iter().any(|a| a == s))
                        .unwrap_or(false)
                }),
                _ => false,
            };
            if !matched {
                return Err((StatusCode::UNAUTHORIZED, "invalid_audience"));
            }
        }

        // Required scopes (`scope` space-delimited string or `scp` array/string)
        if !self.required_scopes.is_empty() {
            let mut token_scopes: Vec<&str> = Vec::new();
            if let Some(Value::String(s)) = claims.get("scope") {
                token_scopes.extend(s.split_whitespace());
            }
            match claims.get("scp") {
                Some(Value::String(s)) => token_scopes.extend(s.split_whitespace()),
                Some(Value::Array(arr)) => {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            token_scopes.push(s);
                        }
                    }
                }
                _ => {}
            }
            for req_scope in &self.required_scopes {
                if !token_scopes.iter().any(|s| s == req_scope) {
                    return Err((StatusCode::FORBIDDEN, "insufficient_scope"));
                }
            }
        }

        // Arbitrary required claims (exact equality or array contains)
        if !self.required_claims.is_empty() {
            let wrapped = JwtClaims(claims.clone());
            for (path, expected) in &self.required_claims {
                let Some(actual) = wrapped.get_path(path) else {
                    return Err((StatusCode::FORBIDDEN, "missing_required_claim"));
                };
                let ok = match actual {
                    Value::Array(arr) if !expected.is_array() => arr.iter().any(|v| v == expected),
                    _ => actual == expected,
                };
                if !ok {
                    return Err((StatusCode::FORBIDDEN, "claim_mismatch"));
                }
            }
        }

        Ok(())
    }

    fn apply_authenticated(
        &self,
        ctx: &mut RequestCtx,
        req: &mut RequestHead,
        claims: Map<String, Value>,
        source: TokenSource,
    ) {
        let jwt_claims = JwtClaims(claims);
        for (claim_path, hdr_name) in &self.forward_claims {
            if let Some(val) = jwt_claims.get_path(claim_path)
                && let Some(str_val) = claim_value_to_header_str(val)
                && let Ok(hv) = HeaderValue::from_str(&str_val)
            {
                req.headers.insert(hdr_name.clone(), hv);
            }
        }

        if self.strip_header {
            if source == TokenSource::Header {
                if let Some(hdr) = &self.header_name {
                    req.headers.remove(hdr);
                } else {
                    req.headers.remove(header::AUTHORIZATION);
                }
            } else if let Some(hdr) = &self.header_name {
                req.headers.remove(hdr);
            }
            if let Some(cookie_name) = &self.cookie_name {
                strip_cookie_from_headers(&mut req.headers, cookie_name);
            }
            if let Some(qp) = &self.query_param {
                strip_query_param_from_uri(&mut req.uri, qp);
            }
        }

        if let Some(sub) = jwt_claims.0.get("sub").and_then(Value::as_str) {
            ctx.annotate_str("auth.subject", sub);
            ctx.insert_ext(AuthSubject(sub.to_owned()));
        }
        ctx.annotate_str("auth.method", "jwt");
        ctx.insert_ext(jwt_claims);
    }

    async fn refresh_jwks(&self, cache: &JwksCache) -> Result<Vec<VerificationKey>, String> {
        if cache.try_acquire_leader() {
            let _guard = LeaderGuard(cache);
            let now = self.clock.now();
            {
                let mut st = cache.state.write().expect("JwksCache state lock poisoned");
                st.last_refresh_attempt = Some(now);
            }

            let jwks_url = self.resolve_jwks_uri(cache).await?;
            let uri: Uri = jwks_url
                .parse()
                .map_err(|e| format!("invalid jwks_uri `{jwks_url}`: {e}"))?;
            let req = HttpRequest::get(uri)
                .with_header(header::ACCEPT, HeaderValue::from_static("application/json"))
                .with_timeout(self.jwks_timeout)
                .with_max_response_bytes(DEFAULT_JWKS_MAX_BYTES);

            let http_client = self
                .http_client
                .as_ref()
                .ok_or_else(|| "no HttpClient available for JWKS fetch".to_owned())?;
            let resp = http_client
                .send(req)
                .await
                .map_err(|e| format!("JWKS fetch failed: {e}"))?;
            if !resp.status.is_success() {
                return Err(format!("JWKS endpoint returned HTTP {}", resp.status));
            }
            let body_str = std::str::from_utf8(&resp.body)
                .map_err(|e| format!("JWKS response was not valid UTF-8: {e}"))?;
            let keys = parse_jwks_json(body_str)?;
            {
                let mut st = cache.state.write().expect("JwksCache state lock poisoned");
                st.keys = keys.clone();
                st.fetched_at = Some(self.clock.now());
            }
            return Ok(keys);
        }

        // Another concurrent request is already refreshing; await its completion.
        cache.wait_in_flight().await;
        let st = cache.state.read().expect("JwksCache state lock poisoned");
        if let Some(fetched) = st.fetched_at
            && self.clock.now().saturating_sub(fetched) < self.jwks_cache_ttl
        {
            return Ok(st.keys.clone());
        }
        if !st.keys.is_empty() {
            return Ok(st.keys.clone());
        }
        Err("JWKS refresh failed".to_owned())
    }

    async fn resolve_jwks_uri(&self, cache: &JwksCache) -> Result<String, String> {
        if let Some(uri) = &self.jwks_uri {
            return Ok(uri.clone());
        }
        {
            let st = cache.state.read().expect("JwksCache state lock poisoned");
            if let Some(discovered) = &st.discovered_jwks_uri {
                return Ok(discovered.clone());
            }
        }
        let disc_url = self
            .oidc_discovery_url
            .as_deref()
            .ok_or_else(|| "no jwks_uri or oidc_discovery_url configured".to_owned())?;
        let uri: Uri = disc_url
            .parse()
            .map_err(|e| format!("invalid oidc_discovery_url `{disc_url}`: {e}"))?;
        let req = HttpRequest::get(uri)
            .with_header(header::ACCEPT, HeaderValue::from_static("application/json"))
            .with_timeout(self.jwks_timeout)
            .with_max_response_bytes(DEFAULT_JWKS_MAX_BYTES);
        let http_client = self
            .http_client
            .as_ref()
            .ok_or_else(|| "no HttpClient available for OIDC discovery".to_owned())?;
        let resp = http_client
            .send(req)
            .await
            .map_err(|e| format!("OIDC discovery fetch failed: {e}"))?;
        if !resp.status.is_success() {
            return Err(format!(
                "OIDC discovery endpoint returned HTTP {}",
                resp.status
            ));
        }
        let doc: Value = serde_json::from_slice(&resp.body)
            .map_err(|e| format!("invalid OIDC discovery JSON: {e}"))?;
        let jwks_uri = doc
            .get("jwks_uri")
            .and_then(Value::as_str)
            .ok_or_else(|| "OIDC discovery document missing `jwks_uri`".to_owned())?
            .to_owned();
        {
            let mut st = cache.state.write().expect("JwksCache state lock poisoned");
            st.discovered_jwks_uri = Some(jwks_uri.clone());
        }
        Ok(jwks_uri)
    }
}

impl HttpPlugin for JwtAuthPlugin {
    fn name(&self) -> &str {
        "jwt-auth"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        // Always strip client-supplied claim-forwarding headers before auth.
        self.strip_forwarded_claim_headers(req);

        let (token, token_source) = match self.extract_token(req) {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                if self.allow_missing {
                    return HookResult::Ready(Flow::Continue);
                }
                return HookResult::Ready(Flow::Respond(self.unauthorized("missing_token")));
            }
            Err(code) => {
                return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                    StatusCode::BAD_REQUEST,
                    format!(r#"{{"error":"{code}"}}"#),
                )));
            }
        };

        let parsed = match parse_jwt_unverified(&token) {
            Ok(p) => p,
            Err(code) => return HookResult::Ready(Flow::Respond(self.unauthorized(code))),
        };

        if !self.allowed_algorithms.contains(&parsed.alg) {
            return HookResult::Ready(Flow::Respond(self.unauthorized("disallowed_jwt_alg")));
        }

        // Fast path: static-only configuration (zero async boxing).
        let Some(cache) = &self.jwks_cache else {
            return match self.verify_signature_against(&parsed, &[]) {
                VerifyKeyOutcome::Verified => match self.validate_claims(&parsed.claims) {
                    Ok(()) => {
                        self.apply_authenticated(ctx, req, parsed.claims, token_source);
                        HookResult::Ready(Flow::Continue)
                    }
                    Err((StatusCode::FORBIDDEN, code)) => {
                        HookResult::Ready(Flow::Respond(self.forbidden(code)))
                    }
                    Err((_, code)) => HookResult::Ready(Flow::Respond(self.unauthorized(code))),
                },
                VerifyKeyOutcome::InvalidSignature | VerifyKeyOutcome::UnknownKid => {
                    HookResult::Ready(Flow::Respond(self.unauthorized("invalid_signature")))
                }
            };
        };

        // Sync fast path when JWKS cache is warm!
        let now = self.clock.now();
        let (cache_warm, can_refresh_for_unknown_kid, cached_outcome) = {
            let st = cache.state.read().expect("JwksCache state lock poisoned");
            let warm = st
                .fetched_at
                .map(|t| now.saturating_sub(t) < self.jwks_cache_ttl)
                .unwrap_or(false);
            let can_refresh = st
                .last_refresh_attempt
                .map(|t| now.saturating_sub(t) >= self.jwks_min_refresh)
                .unwrap_or(true);
            let outcome = if warm {
                Some(self.verify_signature_against(&parsed, &st.keys))
            } else {
                None
            };
            (warm, can_refresh, outcome)
        };

        if cache_warm {
            match cached_outcome {
                Some(VerifyKeyOutcome::Verified) => {
                    return match self.validate_claims(&parsed.claims) {
                        Ok(()) => {
                            self.apply_authenticated(ctx, req, parsed.claims, token_source);
                            HookResult::Ready(Flow::Continue)
                        }
                        Err((StatusCode::FORBIDDEN, code)) => {
                            HookResult::Ready(Flow::Respond(self.forbidden(code)))
                        }
                        Err((_, code)) => HookResult::Ready(Flow::Respond(self.unauthorized(code))),
                    };
                }
                Some(VerifyKeyOutcome::InvalidSignature) => {
                    return HookResult::Ready(Flow::Respond(
                        self.unauthorized("invalid_signature"),
                    ));
                }
                Some(VerifyKeyOutcome::UnknownKid) if !can_refresh_for_unknown_kid => {
                    return HookResult::Ready(Flow::Respond(self.unauthorized("unknown_kid")));
                }
                Some(VerifyKeyOutcome::UnknownKid) | None => {
                    // Fall through to async JWKS refresh.
                }
            }
        }

        // Async slow path: fetch/refresh JWKS via HttpClient (singleflight coalesced).
        let cache = Arc::clone(cache);
        HookResult::pending(async move {
            let keys = match self.refresh_jwks(&cache).await {
                Ok(k) => k,
                Err(err) => {
                    warn!(plugin = "jwt-auth", error = %err, "failed to refresh JWKS");
                    // Fallback to existing cached keys if any exist.
                    let st = cache.state.read().expect("JwksCache state lock poisoned");
                    if st.keys.is_empty() && self.static_keys.is_empty() {
                        return Flow::Respond(BufferedResponse::json(
                            StatusCode::SERVICE_UNAVAILABLE,
                            r#"{"error":"jwks_unavailable"}"#,
                        ));
                    }
                    st.keys.clone()
                }
            };

            let parsed = match parse_jwt_unverified(&token) {
                Ok(p) => p,
                Err(code) => return Flow::Respond(self.unauthorized(code)),
            };
            match self.verify_signature_against(&parsed, &keys) {
                VerifyKeyOutcome::Verified => match self.validate_claims(&parsed.claims) {
                    Ok(()) => {
                        self.apply_authenticated(ctx, req, parsed.claims, token_source);
                        Flow::Continue
                    }
                    Err((StatusCode::FORBIDDEN, code)) => Flow::Respond(self.forbidden(code)),
                    Err((_, code)) => Flow::Respond(self.unauthorized(code)),
                },
                VerifyKeyOutcome::UnknownKid => Flow::Respond(self.unauthorized("unknown_kid")),
                VerifyKeyOutcome::InvalidSignature => {
                    Flow::Respond(self.unauthorized("invalid_signature"))
                }
            }
        })
    }
}

fn strip_bearer_prefix(s: &str) -> Option<&str> {
    let prefix = s.get(..7)?;
    if prefix.eq_ignore_ascii_case("bearer ") {
        Some(&s[7..])
    } else {
        None
    }
}

fn strip_cookie_from_headers(headers: &mut shunt_plugin_sdk::HeaderMap, cookie_name: &str) {
    let remaining: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .filter(|pair| {
            !pair.is_empty()
                && pair
                    .split_once('=')
                    .map(|(k, _)| k.trim() != cookie_name)
                    .unwrap_or(true)
        })
        .map(str::to_owned)
        .collect();
    headers.remove(header::COOKIE);
    if !remaining.is_empty()
        && let Ok(val) = HeaderValue::from_str(&remaining.join("; "))
    {
        headers.insert(header::COOKIE, val);
    }
}

fn strip_query_param_from_uri(uri: &mut Uri, param: &str) {
    let Some(query) = uri.query() else {
        return;
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            pair.split_once('=')
                .map(|(k, _)| k != param)
                .unwrap_or(*pair != param)
        })
        .collect();
    let path = uri.path();
    let next_pq = if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    let mut parts = uri.clone().into_parts();
    if let Ok(pq) = next_pq.parse() {
        parts.path_and_query = Some(pq);
        if let Ok(rebuilt) = Uri::from_parts(parts) {
            *uri = rebuilt;
        }
    }
}

fn value_as_u64(v: &Value) -> Option<u64> {
    if let Some(u) = v.as_u64() {
        Some(u)
    } else if let Some(i) = v.as_i64() {
        u64::try_from(i).ok()
    } else if let Some(f) = v.as_f64() {
        if f.is_finite() && f >= 0.0 && f <= u64::MAX as f64 {
            Some(f as u64)
        } else {
            None
        }
    } else {
        None
    }
}

fn claim_value_to_header_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(arr) => {
            let parts: Vec<String> = arr
                .iter()
                .filter_map(|item| match item {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(","))
            }
        }
        _ => None,
    }
}

/// Parses a JSON Web Key Set (`{"keys": [...]}`) into compiled [`VerificationKey`]s.
///
/// Silently skips encryption-only keys (`use: "enc"`) or unsupported curves while returning
/// an error if the document itself is not a valid JWKS JSON object with a `keys` array.
pub fn parse_jwks_json(raw: &str) -> Result<Vec<VerificationKey>, String> {
    let root: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JWKS JSON: {e}"))?;
    let keys_arr = root
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "JWKS JSON missing `keys` array".to_owned())?;

    let mut out = Vec::new();
    for entry in keys_arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if let Some(use_val) = obj.get("use").and_then(Value::as_str)
            && use_val != "sig"
        {
            continue;
        }
        if let Some(ops) = obj.get("key_ops").and_then(Value::as_array)
            && !ops.iter().any(|v| v.as_str() == Some("verify"))
        {
            continue;
        }
        let kid = obj.get("kid").and_then(Value::as_str).map(str::to_owned);
        let alg = match obj.get("alg").and_then(Value::as_str) {
            Some(a) => match JwtAlgorithm::parse(a) {
                Some(parsed) => Some(parsed),
                None => continue,
            },
            None => None,
        };
        let Some(kty) = obj.get("kty").and_then(Value::as_str) else {
            continue;
        };
        let material = match kty {
            "RSA" => {
                let (Some(n_b64), Some(e_b64)) = (
                    obj.get("n").and_then(Value::as_str),
                    obj.get("e").and_then(Value::as_str),
                ) else {
                    continue;
                };
                let (Ok(n), Ok(e)) = (base64url_decode(n_b64), base64url_decode(e_b64)) else {
                    continue;
                };
                if n.is_empty() || e.is_empty() {
                    continue;
                }
                VerificationKeyMaterial::Rsa { n, e }
            }
            "EC" => {
                let (Some(crv), Some(x_b64), Some(y_b64)) = (
                    obj.get("crv").and_then(Value::as_str),
                    obj.get("x").and_then(Value::as_str),
                    obj.get("y").and_then(Value::as_str),
                ) else {
                    continue;
                };
                let (Ok(x), Ok(y)) = (base64url_decode(x_b64), base64url_decode(y_b64)) else {
                    continue;
                };
                match crv {
                    "P-256" => {
                        let Some(pt) = build_ec_uncompressed_point(&x, &y, 32) else {
                            continue;
                        };
                        VerificationKeyMaterial::EcP256(pt)
                    }
                    "P-384" => {
                        let Some(pt) = build_ec_uncompressed_point(&x, &y, 48) else {
                            continue;
                        };
                        VerificationKeyMaterial::EcP384(pt)
                    }
                    _ => continue,
                }
            }
            "OKP" => {
                let (Some(crv), Some(x_b64)) = (
                    obj.get("crv").and_then(Value::as_str),
                    obj.get("x").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if crv != "Ed25519" {
                    continue;
                }
                let Ok(x) = base64url_decode(x_b64) else {
                    continue;
                };
                if x.len() != 32 {
                    continue;
                }
                VerificationKeyMaterial::Ed25519(x)
            }
            "oct" => {
                let Some(k_b64) = obj.get("k").and_then(Value::as_str) else {
                    continue;
                };
                let Ok(k) = base64url_decode(k_b64) else {
                    continue;
                };
                if k.is_empty() {
                    continue;
                }
                VerificationKeyMaterial::Hmac(k)
            }
            _ => continue,
        };

        out.push(VerificationKey { kid, alg, material });
    }
    Ok(out)
}

fn build_ec_uncompressed_point(x: &[u8], y: &[u8], coord_len: usize) -> Option<Vec<u8>> {
    if x.len() > coord_len || y.len() > coord_len {
        return None;
    }
    let mut pt = Vec::with_capacity(1 + coord_len * 2);
    pt.push(0x04);
    pt.resize(1 + (coord_len - x.len()), 0);
    pt.extend_from_slice(x);
    pt.resize(1 + coord_len + (coord_len - y.len()), 0);
    pt.extend_from_slice(y);
    Some(pt)
}

/// Parses a PEM-encoded SPKI public key (`-----BEGIN PUBLIC KEY-----`) for RSA, EC (P-256/P-384),
/// or Ed25519 without external ASN.1 crates.
pub fn parse_spki_pem_public_key(pem: &str) -> Result<VerificationKeyMaterial, String> {
    let mut b64 = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed == "-----BEGIN PUBLIC KEY-----" {
            in_block = true;
            continue;
        }
        if trimmed == "-----END PUBLIC KEY-----" {
            break;
        }
        if in_block {
            b64.push_str(trimmed);
        }
    }
    if b64.is_empty() {
        return Err("missing `-----BEGIN PUBLIC KEY-----` PEM block".to_owned());
    }
    let der = base64_std_decode(&b64)?;

    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    let (seq_tag, spki_body, _) = der_read_tlv(&der).ok_or("malformed SPKI SEQUENCE")?;
    if seq_tag != 0x30 {
        return Err("SPKI root is not a DER SEQUENCE".to_owned());
    }
    let (alg_tag, alg_body, rest) = der_read_tlv(spki_body).ok_or("missing AlgorithmIdentifier")?;
    if alg_tag != 0x30 {
        return Err("AlgorithmIdentifier is not a DER SEQUENCE".to_owned());
    }
    let (oid_tag, oid_bytes, alg_params) = der_read_tlv(alg_body).ok_or("missing algorithm OID")?;
    if oid_tag != 0x06 {
        return Err("algorithm identifier does not start with OID".to_owned());
    }
    let (bit_tag, bit_bytes, _) =
        der_read_tlv(rest).ok_or("missing subjectPublicKey BIT STRING")?;
    if bit_tag != 0x03 || bit_bytes.is_empty() || bit_bytes[0] != 0x00 {
        return Err("malformed subjectPublicKey BIT STRING".to_owned());
    }
    let key_bytes = &bit_bytes[1..];

    // RSA encryption OID 1.2.840.113549.1.1.1
    const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    // EC publicKey OID 1.2.840.10045.2.1
    const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    // prime256v1 (P-256) OID 1.2.840.10045.3.1.7
    const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    // secp384r1 (P-384) OID 1.3.132.0.34
    const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
    // Ed25519 OID 1.3.101.112
    const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

    match oid_bytes {
        OID_RSA => {
            let (rsa_seq_tag, rsa_body, _) =
                der_read_tlv(key_bytes).ok_or("malformed RSAPublicKey SEQUENCE")?;
            if rsa_seq_tag != 0x30 {
                return Err("RSAPublicKey is not a DER SEQUENCE".to_owned());
            }
            let (n_tag, n_raw, after_n) = der_read_tlv(rsa_body).ok_or("missing RSA modulus")?;
            let (e_tag, e_raw, _) = der_read_tlv(after_n).ok_or("missing RSA exponent")?;
            if n_tag != 0x02 || e_tag != 0x02 {
                return Err("RSA modulus/exponent must be DER INTEGERs".to_owned());
            }
            let n = strip_leading_zero(n_raw).to_vec();
            let e = strip_leading_zero(e_raw).to_vec();
            if n.is_empty() || e.is_empty() {
                return Err("empty RSA modulus or exponent".to_owned());
            }
            Ok(VerificationKeyMaterial::Rsa { n, e })
        }
        OID_EC => {
            let (curve_tag, curve_oid, _) =
                der_read_tlv(alg_params).ok_or("missing EC namedCurve OID")?;
            if curve_tag != 0x06 {
                return Err("EC parameters must be a namedCurve OID".to_owned());
            }
            match curve_oid {
                OID_P256 if key_bytes.len() == 65 && key_bytes[0] == 0x04 => {
                    Ok(VerificationKeyMaterial::EcP256(key_bytes.to_vec()))
                }
                OID_P384 if key_bytes.len() == 97 && key_bytes[0] == 0x04 => {
                    Ok(VerificationKeyMaterial::EcP384(key_bytes.to_vec()))
                }
                _ => Err("unsupported EC curve or compressed point".to_owned()),
            }
        }
        OID_ED25519 => {
            if key_bytes.len() != 32 {
                return Err("Ed25519 public key must be 32 bytes".to_owned());
            }
            Ok(VerificationKeyMaterial::Ed25519(key_bytes.to_vec()))
        }
        _ => Err("unsupported SPKI public key algorithm OID".to_owned()),
    }
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0x00]).unwrap_or(bytes)
}

fn der_read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let &tag = input.first()?;
    let &first_len = input.get(1)?;
    let (len, header_len) = if first_len & 0x80 == 0 {
        (usize::from(first_len), 2usize)
    } else {
        let num_bytes = usize::from(first_len & 0x7F);
        if num_bytes == 0 || num_bytes > 4 {
            return None;
        }
        let len_slice = input.get(2..2 + num_bytes)?;
        let mut len = 0usize;
        for &b in len_slice {
            len = len.checked_shl(8)?.checked_add(usize::from(b))?;
        }
        (len, 2 + num_bytes)
    };
    let end = header_len.checked_add(len)?;
    let value = input.get(header_len..end)?;
    let rest = input.get(end..)?;
    Some((tag, value, rest))
}

/// Pure-Rust base64url decoder (supports unpadded RFC 4648 §5 as used by JWT/JWK).
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let s = input.trim_end_matches('=');
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err("invalid base64url length");
    }
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let (chunks, rem) = bytes.as_chunks::<4>();
    for chunk in chunks {
        let a = b64url_val(chunk[0])?;
        let b = b64url_val(chunk[1])?;
        let c = b64url_val(chunk[2])?;
        let d = b64url_val(chunk[3])?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
    }
    match rem.len() {
        0 => {}
        2 => {
            let a = b64url_val(rem[0])?;
            let b = b64url_val(rem[1])?;
            out.push((a << 2) | (b >> 4));
        }
        3 => {
            let a = b64url_val(rem[0])?;
            let b = b64url_val(rem[1])?;
            let c = b64url_val(rem[2])?;
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        }
        _ => return Err("invalid base64url remainder"),
    }
    Ok(out)
}

/// Pure-Rust base64url encoder (no padding, RFC 4648 §5).
pub fn base64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, rem) = data.as_chunks::<3>();
    for c in chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
    }
    match rem {
        [a] => {
            let n = (*a as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn b64url_val(b: u8) -> Result<u8, &'static str> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err("invalid base64url character"),
    }
}

fn base64_std_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    base64url_decode(&cleaned)
}
