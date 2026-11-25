use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

use crate::error::ConsoleError;

/// Generates a prefixed, URL-safe CSPRNG secret token (256 bits of entropy).
/// Returns `(plaintext_token, sha256_prefixed_hash, safe_display_prefix)`.
pub fn generate_secret_token(prefix: &str) -> Result<(String, String, String), ConsoleError> {
    let rng = SystemRandom::new();
    let mut raw = [0u8; 32];
    rng.fill(&mut raw)
        .map_err(|_| ConsoleError::Internal("CSPRNG failed".to_owned()))?;
    let encoded = URL_SAFE_NO_PAD.encode(raw);
    let plaintext = format!("{prefix}{encoded}");
    let hash = sha256_prefixed(plaintext.as_bytes());
    let safe_prefix = format!("{}{}...", prefix, &encoded[..6]);
    Ok((plaintext, hash, safe_prefix))
}

/// Generates a sortable ULID prefixed by entity type (e.g. `node_01J...`, `org_01J...`).
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", ulid::Ulid::new())
}

/// Computes lowercase hex SHA-256 digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Computes canonical `sha256:<64-hex>` string.
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// Computes an HTTP ETag token (`"<16-hex>"`) from canonical state bytes.
pub fn compute_etag(bytes: &[u8]) -> String {
    let hex = sha256_hex(bytes);
    format!("\"{}\"", &hex[..16])
}

/// Hashes a user password with Argon2id (OWASP-recommended parameters).
pub fn hash_password(password: &str) -> Result<String, ConsoleError> {
    if password.len() < 8 {
        return Err(ConsoleError::BadRequest(
            "password must be at least 8 characters long".to_owned(),
        ));
    }
    let rng = SystemRandom::new();
    let mut salt_bytes = [0u8; 16];
    rng.fill(&mut salt_bytes)
        .map_err(|_| ConsoleError::Internal("CSPRNG salt generation failed".to_owned()))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| ConsoleError::Internal(format!("salt encode failed: {e}")))?;

    let params = Params::new(19_456, 2, 1, None)
        .map_err(|e| ConsoleError::Internal(format!("argon2 params failed: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ConsoleError::Internal(format!("password hash failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verifies a plaintext password against a stored Argon2id PHC hash.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Constant-time comparison of two byte slices.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validates a resource slug (`a-z0-9-`, 1..=64 chars).
pub fn validate_slug(slug: &str, field: &str) -> Result<(), ConsoleError> {
    if slug.is_empty() || slug.len() > 64 {
        return Err(ConsoleError::BadRequest(format!(
            "`{field}` must be 1..=64 characters long"
        )));
    }
    let valid = slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !valid || !slug.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(ConsoleError::BadRequest(format!(
            "`{field}` (`{slug}`) must start with a lowercase letter/digit and contain only `a-z`, `0-9`, `-`, `_`"
        )));
    }
    Ok(())
}
