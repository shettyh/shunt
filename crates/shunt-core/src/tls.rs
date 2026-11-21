use std::collections::HashMap;
use std::sync::{Arc, Once};

use arc_swap::ArcSwap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

use crate::error::CoreError;

static CRYPTO_INIT: Once = Once::new();

/// Ensures the `ring` crypto provider is installed for `rustls`.
pub fn ensure_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Loads a `CertifiedKey` from PEM-encoded certificate chain and private key bytes.
pub fn load_certified_key_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<CertifiedKey>, CoreError> {
    ensure_crypto_provider();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CoreError::Tls(format!("failed to parse certificate PEM: {e}")))?;

    if certs.is_empty() {
        return Err(CoreError::Tls(
            "certificate PEM contained no certificates".to_owned(),
        ));
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|e| CoreError::Tls(format!("failed to parse private key PEM: {e}")))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| CoreError::Tls(format!("unsupported private key type: {e}")))?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Immutable collection of TLS certificates keyed by SNI hostname (plus optional default).
#[derive(Debug, Default, Clone)]
pub struct CertStore {
    pub default: Option<Arc<CertifiedKey>>,
    pub sni: HashMap<String, Arc<CertifiedKey>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default(mut self, key: Arc<CertifiedKey>) -> Self {
        self.default = Some(key);
        self
    }

    pub fn with_sni(mut self, hostname: impl Into<String>, key: Arc<CertifiedKey>) -> Self {
        self.sni.insert(hostname.into().to_ascii_lowercase(), key);
        self
    }

    pub fn resolve_name(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(raw_name) = name {
            let lower = raw_name.to_ascii_lowercase();
            if let Some(exact) = self.sni.get(&lower) {
                return Some(Arc::clone(exact));
            }
            // Wildcard lookup: `foo.example.com` -> `*.example.com`
            if let Some((_, suffix)) = lower.split_once('.') {
                let wildcard = format!("*.{suffix}");
                if let Some(wc) = self.sni.get(&wildcard) {
                    return Some(Arc::clone(wc));
                }
            }
        }
        self.default.clone()
    }
}

/// Hot-reloadable SNI certificate resolver backed by `ArcSwap`.
#[derive(Debug)]
pub struct DynamicCertResolver {
    store: ArcSwap<CertStore>,
}

impl DynamicCertResolver {
    pub fn new(initial: CertStore) -> Self {
        Self {
            store: ArcSwap::from_pointee(initial),
        }
    }

    /// Atomically swaps in a new certificate store for all subsequent TLS handshakes.
    pub fn reload(&self, next: CertStore) {
        self.store.store(Arc::new(next));
    }

    /// Returns a snapshot of the active `CertStore`.
    pub fn current(&self) -> Arc<CertStore> {
        self.store.load_full()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let store = self.store.load();
        store.resolve_name(client_hello.server_name())
    }
}

/// Server-side TLS listener configuration supporting SNI and hot-reloadable certs.
#[derive(Clone)]
pub struct TlsListenerConfig {
    resolver: Arc<DynamicCertResolver>,
    alpn_protocols: Vec<Vec<u8>>,
}

impl TlsListenerConfig {
    pub fn new(resolver: Arc<DynamicCertResolver>) -> Self {
        Self {
            resolver,
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }

    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    pub fn resolver(&self) -> &Arc<DynamicCertResolver> {
        &self.resolver
    }

    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>, CoreError> {
        ensure_crypto_provider();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&self.resolver) as Arc<dyn ResolvesServerCert>);
        cfg.alpn_protocols = self.alpn_protocols.clone();
        Ok(Arc::new(cfg))
    }
}

/// Upstream client TLS configuration (also used as part of `UpstreamPoolKey`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamTlsConfig {
    /// Additional PEM-encoded root CA certificates.
    pub extra_ca_pem: Option<Vec<u8>>,
    /// Skip TLS certificate verification (development / self-signed test upstreams only).
    pub insecure_skip_verify: bool,
    /// ALPN protocols advertised to upstream.
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            extra_ca_pem: None,
            insecure_skip_verify: false,
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }
}

impl UpstreamTlsConfig {
    pub fn build_client_config(
        &self,
        alpn_override: Option<Vec<Vec<u8>>>,
    ) -> Result<Arc<ClientConfig>, CoreError> {
        ensure_crypto_provider();

        let mut cfg = if self.insecure_skip_verify {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            if let Some(pem) = &self.extra_ca_pem {
                let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| CoreError::Tls(format!("failed to parse upstream CA PEM: {e}")))?;
                for cert in certs {
                    roots
                        .add(cert)
                        .map_err(|e| CoreError::Tls(format!("invalid upstream CA cert: {e}")))?;
                }
            }

            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };

        cfg.alpn_protocols = alpn_override.unwrap_or_else(|| self.alpn_protocols.clone());
        Ok(Arc::new(cfg))
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
