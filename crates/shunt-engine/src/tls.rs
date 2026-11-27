use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Once};

use arc_swap::ArcSwap;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use shunt_plugin_sdk::ClientCertInfo;

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

/// Mutual TLS (mTLS) client certificate verification policy on a TLS listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuthMode {
    /// Do not request or verify client certificates (standard server-auth TLS).
    #[default]
    None,
    /// Request a client certificate if offered and verify it against `ca_pem`,
    /// but allow unauthenticated clients (route plugins such as `mtls-auth` can enforce selectively).
    Optional,
    /// Require a valid client certificate signed by `ca_pem` at TLS handshake time.
    Required,
}

/// Mutual TLS client CA bundle and verification mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAuthConfig {
    pub mode: ClientAuthMode,
    /// PEM-encoded client CA root certificate(s) (required when `mode != None`).
    pub ca_pem: Vec<u8>,
}

/// Server-side TLS listener configuration supporting SNI, hot-reloadable certs, and mTLS.
#[derive(Clone)]
pub struct TlsListenerConfig {
    resolver: Arc<DynamicCertResolver>,
    alpn_protocols: Vec<Vec<u8>>,
    client_auth: Option<ClientAuthConfig>,
}

impl TlsListenerConfig {
    pub fn new(resolver: Arc<DynamicCertResolver>) -> Self {
        Self {
            resolver,
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            client_auth: None,
        }
    }

    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    pub fn with_client_auth(mut self, client_auth: Option<ClientAuthConfig>) -> Self {
        self.client_auth = client_auth;
        self
    }

    pub fn resolver(&self) -> &Arc<DynamicCertResolver> {
        &self.resolver
    }

    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    pub fn client_auth(&self) -> Option<&ClientAuthConfig> {
        self.client_auth.as_ref()
    }

    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>, CoreError> {
        build_server_config_with_auth(
            &self.resolver,
            &self.alpn_protocols,
            self.client_auth.as_ref(),
        )
    }
}

/// Builds a `rustls::ServerConfig` using `resolver`, `alpn_protocols`, and optional mTLS `client_auth`.
pub fn build_server_config_with_auth(
    resolver: &Arc<DynamicCertResolver>,
    alpn_protocols: &[Vec<u8>],
    client_auth: Option<&ClientAuthConfig>,
) -> Result<Arc<ServerConfig>, CoreError> {
    ensure_crypto_provider();
    let mut cfg = match client_auth {
        Some(auth) if auth.mode != ClientAuthMode::None => {
            let mut roots = RootCertStore::empty();
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&auth.ca_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| CoreError::Tls(format!("failed to parse client CA PEM: {e}")))?;
            if certs.is_empty() {
                return Err(CoreError::Tls(
                    "client CA PEM contained no certificates".to_owned(),
                ));
            }
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| CoreError::Tls(format!("invalid client CA cert: {e}")))?;
            }
            let verifier_builder = WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = match auth.mode {
                ClientAuthMode::Required => verifier_builder.build(),
                ClientAuthMode::Optional => verifier_builder.allow_unauthenticated().build(),
                ClientAuthMode::None => unreachable!(),
            }
            .map_err(|e| CoreError::Tls(format!("failed to build mTLS client verifier: {e}")))?;

            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(Arc::clone(resolver) as Arc<dyn ResolvesServerCert>)
        }
        _ => ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(resolver) as Arc<dyn ResolvesServerCert>),
    };
    cfg.alpn_protocols = alpn_protocols.to_vec();
    Ok(Arc::new(cfg))
}

/// Pure-Rust, panic-free DER X.509 certificate metadata extractor for verified mTLS peer certs.
///
/// Extracts Subject CN/DN, Issuer DN, SAN DNS/URI/Email entries, serial hex, and SHA-256
/// fingerprint directly from the leaf DER certificate without external X.509 crates.
pub fn parse_client_cert_info(der: &[u8]) -> Option<ClientCertInfo> {
    if der.is_empty() {
        return None;
    }

    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let sha256_fingerprint = hex_lower(digest.as_ref());

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert_tag, cert_body, _) = der_read_tlv(der)?;
    if cert_tag != 0x30 {
        return None;
    }
    let (tbs_tag, mut tbs, _) = der_read_tlv(cert_body)?;
    if tbs_tag != 0x30 {
        return None;
    }

    // Optional [0] EXPLICIT version
    if tbs.first() == Some(&0xA0) {
        let (_, _, rest) = der_read_tlv(tbs)?;
        tbs = rest;
    }

    // serialNumber INTEGER (0x02)
    let (ser_tag, ser_val, rest) = der_read_tlv(tbs)?;
    if ser_tag != 0x02 {
        return None;
    }
    let serial_hex = hex_lower(ser_val);
    tbs = rest;

    // signature AlgorithmIdentifier (SEQUENCE)
    let (sig_tag, _, rest) = der_read_tlv(tbs)?;
    if sig_tag != 0x30 {
        return None;
    }
    tbs = rest;

    // issuer Name (SEQUENCE)
    let (iss_tag, iss_body, rest) = der_read_tlv(tbs)?;
    if iss_tag != 0x30 {
        return None;
    }
    let (issuer_dn, _) = parse_x509_name(iss_body);
    tbs = rest;

    // validity Validity (SEQUENCE)
    let (val_tag, _, rest) = der_read_tlv(tbs)?;
    if val_tag != 0x30 {
        return None;
    }
    tbs = rest;

    // subject Name (SEQUENCE)
    let (sub_tag, sub_body, rest) = der_read_tlv(tbs)?;
    if sub_tag != 0x30 {
        return None;
    }
    let (subject_dn, subject_cn) = parse_x509_name(sub_body);
    tbs = rest;

    // subjectPublicKeyInfo (SEQUENCE)
    let (spki_tag, _, mut rest) = der_read_tlv(tbs)?;
    if spki_tag != 0x30 {
        return None;
    }

    let mut san_dns = Vec::new();
    let mut san_uris = Vec::new();
    let mut san_emails = Vec::new();

    // Scan remaining optional tagged fields for [3] EXPLICIT Extensions (0xA3).
    while !rest.is_empty() {
        let Some((tag, val, next)) = der_read_tlv(rest) else {
            break;
        };
        if tag == 0xA3 {
            parse_x509_extensions(val, &mut san_dns, &mut san_uris, &mut san_emails);
            break;
        }
        rest = next;
    }

    Some(ClientCertInfo {
        subject_cn,
        subject_dn,
        issuer_dn,
        san_dns,
        san_uris,
        san_emails,
        serial_hex,
        sha256_fingerprint,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
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

fn parse_x509_name(mut body: &[u8]) -> (String, Option<String>) {
    let mut parts = Vec::new();
    let mut cn = None;

    while !body.is_empty() {
        let Some((set_tag, mut set_body, next_rdn)) = der_read_tlv(body) else {
            break;
        };
        body = next_rdn;
        if set_tag != 0x31 {
            continue;
        }
        while !set_body.is_empty() {
            let Some((atv_tag, atv_body, next_atv)) = der_read_tlv(set_body) else {
                break;
            };
            set_body = next_atv;
            if atv_tag != 0x30 {
                continue;
            }
            let Some((oid_tag, oid_bytes, val_rest)) = der_read_tlv(atv_body) else {
                continue;
            };
            if oid_tag != 0x06 {
                continue;
            }
            let Some((val_tag, val_bytes, _)) = der_read_tlv(val_rest) else {
                continue;
            };
            let Some(val_str) = decode_der_string(val_tag, val_bytes) else {
                continue;
            };
            if contains_disallowed_x509_control(&val_str) {
                continue;
            }
            let attr_name = match oid_bytes {
                [0x55, 0x04, 0x03] => {
                    if cn.is_none() {
                        cn = Some(val_str.clone());
                    }
                    "CN"
                }
                [0x55, 0x04, 0x06] => "C",
                [0x55, 0x04, 0x07] => "L",
                [0x55, 0x04, 0x08] => "ST",
                [0x55, 0x04, 0x0A] => "O",
                [0x55, 0x04, 0x0B] => "OU",
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => "emailAddress",
                _ => continue,
            };
            let escaped = escape_rfc4514_value(&val_str);
            parts.push(format!("{attr_name}={escaped}"));
        }
    }

    (parts.join(","), cn)
}

fn contains_disallowed_x509_control(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7F)
}

/// Escapes an X.509 RDN attribute value per RFC 4514 §2.4 so values like `O="Evil,CN=admin"`
/// cannot forge adjacent DN attributes.
fn escape_rfc4514_value(val: &str) -> String {
    let mut out = String::with_capacity(val.len());
    let mut chars = val.chars().peekable();
    let mut is_first = true;
    while let Some(ch) = chars.next() {
        let is_last = chars.peek().is_none();
        let needs_escape = matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (is_first && (ch == ' ' || ch == '#'))
            || (is_last && ch == ' ');
        if needs_escape {
            out.push('\\');
        }
        out.push(ch);
        is_first = false;
    }
    out
}

fn decode_der_string(tag: u8, bytes: &[u8]) -> Option<String> {
    match tag {
        // UTF8String, PrintableString, IA5String, TeletexString, VisibleString
        0x0C | 0x13 | 0x16 | 0x14 | 0x1A => String::from_utf8(bytes.to_vec()).ok(),
        // BMPString (UTF-16BE)
        0x1E if bytes.len().is_multiple_of(2) => {
            let (chunks, _) = bytes.as_chunks::<2>();
            let units: Vec<u16> = chunks.iter().map(|&c| u16::from_be_bytes(c)).collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

fn parse_x509_extensions(
    ext_wrapper: &[u8],
    san_dns: &mut Vec<String>,
    san_uris: &mut Vec<String>,
    san_emails: &mut Vec<String>,
) {
    let Some((seq_tag, mut exts, _)) = der_read_tlv(ext_wrapper) else {
        return;
    };
    if seq_tag != 0x30 {
        return;
    }

    while !exts.is_empty() {
        let Some((ext_tag, ext_body, next_ext)) = der_read_tlv(exts) else {
            break;
        };
        exts = next_ext;
        if ext_tag != 0x30 {
            continue;
        }
        let Some((oid_tag, oid_bytes, mut rest)) = der_read_tlv(ext_body) else {
            continue;
        };
        // OID 2.5.29.17 = subjectAltName
        if oid_tag != 0x06 || oid_bytes != [0x55, 0x1D, 0x11] {
            continue;
        }
        // Optional critical BOOLEAN (0x01)
        if rest.first() == Some(&0x01) {
            let Some((_, _, after_bool)) = der_read_tlv(rest) else {
                continue;
            };
            rest = after_bool;
        }
        // extnValue OCTET STRING (0x04)
        let Some((oct_tag, oct_bytes, _)) = der_read_tlv(rest) else {
            continue;
        };
        if oct_tag != 0x04 {
            continue;
        }
        // GeneralNames ::= SEQUENCE OF GeneralName
        let Some((gn_seq_tag, mut gns, _)) = der_read_tlv(oct_bytes) else {
            continue;
        };
        if gn_seq_tag != 0x30 {
            continue;
        }
        while !gns.is_empty() {
            let Some((gn_tag, gn_val, next_gn)) = der_read_tlv(gns) else {
                break;
            };
            gns = next_gn;
            let Ok(s) = std::str::from_utf8(gn_val) else {
                continue;
            };
            if contains_disallowed_x509_control(s) {
                continue;
            }
            match gn_tag {
                0x81 => san_emails.push(s.to_owned()),
                0x82 => san_dns.push(s.to_owned()),
                0x86 => san_uris.push(s.to_owned()),
                _ => {}
            }
        }
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
