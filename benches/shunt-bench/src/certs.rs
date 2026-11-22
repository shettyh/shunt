use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generates a deterministic-structure ephemeral CA, server cert (`127.0.0.1` + `localhost`),
/// and client cert (for mTLS) in `out_dir`.
pub fn generate_bench_certs(out_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(out_dir)
        .map_err(|e| format!("failed to create cert dir {}: {e}", out_dir.display()))?;

    // 1. Root CA
    let mut ca_params = CertificateParams::new(Vec::new())
        .map_err(|e| format!("failed to create CA params: {e}"))?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Shunt Bench CA");
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "ShuntBench");
    let ca_key = KeyPair::generate().map_err(|e| format!("CA keygen failed: {e}"))?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("CA self-sign failed: {e}"))?;

    // 2. Server cert (localhost + 127.0.0.1)
    let mut srv_params = CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|e| format!("server cert params failed: {e}"))?;
    srv_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    srv_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    srv_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let srv_key = KeyPair::generate().map_err(|e| format!("server keygen failed: {e}"))?;
    let srv_cert = srv_params
        .signed_by(&srv_key, &ca_cert, &ca_key)
        .map_err(|e| format!("server cert sign failed: {e}"))?;

    // 3. Client cert for mTLS
    let mut cli_params = CertificateParams::new(Vec::new())
        .map_err(|e| format!("client cert params failed: {e}"))?;
    cli_params
        .distinguished_name
        .push(DnType::CommonName, "bench-client");
    cli_params
        .distinguished_name
        .push(DnType::OrganizationName, "ShuntBench");
    cli_params.subject_alt_names.push(SanType::DnsName(
        "bench-client.shunt.local".try_into().unwrap(),
    ));
    cli_params.subject_alt_names.push(SanType::URI(
        "spiffe://shunt.local/ns/bench/sa/client"
            .try_into()
            .unwrap(),
    ));
    cli_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let cli_key = KeyPair::generate().map_err(|e| format!("client keygen failed: {e}"))?;
    let cli_cert = cli_params
        .signed_by(&cli_key, &ca_cert, &ca_key)
        .map_err(|e| format!("client cert sign failed: {e}"))?;

    fs::write(out_dir.join("ca.pem"), ca_cert.pem())
        .map_err(|e| format!("failed writing ca.pem: {e}"))?;
    fs::write(out_dir.join("server.pem"), srv_cert.pem())
        .map_err(|e| format!("failed writing server.pem: {e}"))?;
    fs::write(out_dir.join("server-key.pem"), srv_key.serialize_pem())
        .map_err(|e| format!("failed writing server-key.pem: {e}"))?;
    fs::write(out_dir.join("client.pem"), cli_cert.pem())
        .map_err(|e| format!("failed writing client.pem: {e}"))?;
    fs::write(out_dir.join("client-key.pem"), cli_key.serialize_pem())
        .map_err(|e| format!("failed writing client-key.pem: {e}"))?;

    Ok(())
}

/// Builds a `rustls::ClientConfig` for HTTPS/TLS/mTLS load generation.
pub fn build_tls_client_config(
    ca_cert_path: Option<&Path>,
    insecure: bool,
    client_cert_path: Option<&Path>,
    client_key_path: Option<&Path>,
    http2: bool,
) -> Result<Arc<ClientConfig>, String> {
    ensure_crypto_provider();

    let builder = if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification))
    } else {
        let mut roots = RootCertStore::empty();
        if let Some(ca_path) = ca_cert_path {
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(ca_path)
                .map_err(|e| format!("failed to open CA cert {}: {e}", ca_path.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("failed to parse CA cert {}: {e}", ca_path.display()))?;
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|e| format!("invalid CA cert in {}: {e}", ca_path.display()))?;
            }
        } else {
            return Err("HTTPS requires either --ca-cert <path> or --insecure".to_owned());
        }
        ClientConfig::builder().with_root_certificates(roots)
    };

    let mut cfg = match (client_cert_path, client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
                .map_err(|e| format!("failed to open client cert {}: {e}", cert_path.display()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("failed to parse client cert {}: {e}", cert_path.display()))?;
            let key = PrivateKeyDer::from_pem_file(key_path)
                .map_err(|e| format!("failed to load client key {}: {e}", key_path.display()))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| format!("invalid client auth cert/key: {e}"))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err("--client-cert and --client-key must be provided together".to_owned());
        }
    };

    cfg.alpn_protocols = if http2 {
        vec![b"h2".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };

    Ok(Arc::new(cfg))
}

pub fn server_name_for_host(host: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_owned())
            .map_err(|e| format!("invalid TLS server name `{host}`: {e}"))
    }
}

#[derive(Debug)]
struct NoCertVerification;

impl ServerCertVerifier for NoCertVerification {
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
