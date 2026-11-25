use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::error::ConsoleError;

/// Result of envelope-encrypting a secret value with a fresh random 256-bit DEK.
#[derive(Debug, Clone)]
pub struct EncryptedEnvelope {
    pub ciphertext_b64: String,
    pub nonce_b64: String,
    pub wrapped_dek_b64: String,
    pub dek_nonce_b64: String,
}

/// Envelope-encrypted Secrets Vault (AES-256-GCM DEK wrapped by Master KEK).
///
/// Each secret gets its own random 256-bit Data Encryption Key (DEK) bound to the secret's
/// `(org_id, scope_id, slug, key_version)` via Authenticated Associated Data (AAD) so ciphertext
/// cannot be swapped across tenants or scopes.
pub struct SecretsVault {
    master_key: [u8; 32],
    is_ephemeral_dev_key: bool,
    rng: SystemRandom,
}

impl SecretsVault {
    /// Creates a vault from a 32-byte Master KEK.
    pub fn new(master_key: [u8; 32], is_ephemeral_dev_key: bool) -> Self {
        Self {
            master_key,
            is_ephemeral_dev_key,
            rng: SystemRandom::new(),
        }
    }

    /// Parses a 32-byte Master KEK from 64-char hex or standard/URL base64.
    pub fn from_encoded_key(raw: &str) -> Result<Self, ConsoleError> {
        let key = parse_key_32(raw)?;
        Ok(Self::new(key, false))
    }

    /// Generates a fresh random Master KEK (used for zero-friction local dev mode when
    /// `SHUNT_CONSOLE_MASTER_KEY` is unset; callers persist or warn accordingly).
    pub fn generate_dev_key() -> Result<([u8; 32], String), ConsoleError> {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .map_err(|_| ConsoleError::Vault("failed to generate master key".to_owned()))?;
        Ok((key, STANDARD.encode(key)))
    }

    /// Returns `true` when running on an auto-generated local dev key instead of an explicit KEK.
    pub fn is_ephemeral_dev_key(&self) -> bool {
        self.is_ephemeral_dev_key
    }

    /// Envelope-encrypts `plaintext` bound to `aad_context`.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        aad_context: &str,
    ) -> Result<EncryptedEnvelope, ConsoleError> {
        let mut dek = [0u8; 32];
        let mut data_nonce = [0u8; 12];
        let mut dek_nonce = [0u8; 12];
        self.rng
            .fill(&mut dek)
            .map_err(|_| ConsoleError::Vault("CSPRNG DEK generation failed".to_owned()))?;
        self.rng
            .fill(&mut data_nonce)
            .map_err(|_| ConsoleError::Vault("CSPRNG nonce generation failed".to_owned()))?;
        self.rng
            .fill(&mut dek_nonce)
            .map_err(|_| ConsoleError::Vault("CSPRNG DEK nonce generation failed".to_owned()))?;

        // 1. Encrypt payload using the fresh DEK.
        let data_key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &dek)
                .map_err(|_| ConsoleError::Vault("invalid DEK".to_owned()))?,
        );
        let mut ct = plaintext.to_vec();
        data_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(data_nonce),
                Aad::from(aad_context.as_bytes()),
                &mut ct,
            )
            .map_err(|_| ConsoleError::Vault("secret payload encryption failed".to_owned()))?;

        // 2. Wrap DEK using the Master KEK.
        let kek = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &self.master_key)
                .map_err(|_| ConsoleError::Vault("invalid master KEK".to_owned()))?,
        );
        let mut wrapped = dek.to_vec();
        kek.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(dek_nonce),
            Aad::from(aad_context.as_bytes()),
            &mut wrapped,
        )
        .map_err(|_| ConsoleError::Vault("DEK wrap failed".to_owned()))?;

        Ok(EncryptedEnvelope {
            ciphertext_b64: STANDARD.encode(ct),
            nonce_b64: STANDARD.encode(data_nonce),
            wrapped_dek_b64: STANDARD.encode(wrapped),
            dek_nonce_b64: STANDARD.encode(dek_nonce),
        })
    }

    /// Unwraps the DEK and decrypts an [`EncryptedEnvelope`], enforcing AAD context binding.
    pub fn decrypt(
        &self,
        envelope: &EncryptedEnvelope,
        aad_context: &str,
    ) -> Result<Vec<u8>, ConsoleError> {
        let wrapped = STANDARD
            .decode(&envelope.wrapped_dek_b64)
            .map_err(|e| ConsoleError::Vault(format!("invalid wrapped_dek base64: {e}")))?;
        let dek_nonce_vec = STANDARD
            .decode(&envelope.dek_nonce_b64)
            .map_err(|e| ConsoleError::Vault(format!("invalid dek_nonce base64: {e}")))?;
        let dek_nonce: [u8; 12] = dek_nonce_vec
            .try_into()
            .map_err(|_| ConsoleError::Vault("dek_nonce must be 12 bytes".to_owned()))?;

        let kek = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &self.master_key)
                .map_err(|_| ConsoleError::Vault("invalid master KEK".to_owned()))?,
        );
        let mut dek_buf = wrapped;
        let dek_plain = kek
            .open_in_place(
                Nonce::assume_unique_for_key(dek_nonce),
                Aad::from(aad_context.as_bytes()),
                &mut dek_buf,
            )
            .map_err(|_| {
                ConsoleError::Vault(
                    "failed to unwrap DEK (wrong master key or AAD mismatch)".to_owned(),
                )
            })?;
        let dek: [u8; 32] = dek_plain
            .try_into()
            .map_err(|_| ConsoleError::Vault("unwrapped DEK has invalid length".to_owned()))?;

        let ct = STANDARD
            .decode(&envelope.ciphertext_b64)
            .map_err(|e| ConsoleError::Vault(format!("invalid ciphertext base64: {e}")))?;
        let data_nonce_vec = STANDARD
            .decode(&envelope.nonce_b64)
            .map_err(|e| ConsoleError::Vault(format!("invalid nonce base64: {e}")))?;
        let data_nonce: [u8; 12] = data_nonce_vec
            .try_into()
            .map_err(|_| ConsoleError::Vault("nonce must be 12 bytes".to_owned()))?;

        let data_key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &dek)
                .map_err(|_| ConsoleError::Vault("invalid DEK".to_owned()))?,
        );
        let mut pt_buf = ct;
        let plain = data_key
            .open_in_place(
                Nonce::assume_unique_for_key(data_nonce),
                Aad::from(aad_context.as_bytes()),
                &mut pt_buf,
            )
            .map_err(|_| {
                ConsoleError::Vault(
                    "failed to decrypt secret payload (tampered or AAD mismatch)".to_owned(),
                )
            })?;
        Ok(plain.to_vec())
    }
}

/// Ed25519 signer used to sign published Channel 1 topology bundles (`v1:<rev>:<digest>`).
pub struct BundleSigner {
    key_pair: Ed25519KeyPair,
    public_key_b64: String,
}

impl BundleSigner {
    /// Generates a new Ed25519 key pair and returns `(signer, pkcs8_base64)` for persistence.
    pub fn generate() -> Result<(Self, String), ConsoleError> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| ConsoleError::Vault("Ed25519 keygen failed".to_owned()))?;
        let pkcs8_b64 = STANDARD.encode(pkcs8.as_ref());
        let signer = Self::from_pkcs8_b64(&pkcs8_b64)?;
        Ok((signer, pkcs8_b64))
    }

    /// Loads an existing Ed25519 key pair from base64-encoded PKCS#8 bytes.
    pub fn from_pkcs8_b64(pkcs8_b64: &str) -> Result<Self, ConsoleError> {
        let bytes = STANDARD
            .decode(pkcs8_b64.trim())
            .map_err(|e| ConsoleError::Vault(format!("invalid Ed25519 pkcs8 base64: {e}")))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(&bytes)
            .map_err(|_| ConsoleError::Vault("invalid Ed25519 PKCS#8 key".to_owned()))?;
        let public_key_b64 = STANDARD.encode(key_pair.public_key().as_ref());
        Ok(Self {
            key_pair,
            public_key_b64,
        })
    }

    /// Base64-encoded 32-byte Ed25519 public key distributed to `shunt` nodes.
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    /// Signs a published topology revision (`v1:<revision>:<normalized_digest>`).
    pub fn sign_revision(&self, revision: u64, digest: &str) -> String {
        let normalized = if digest.starts_with("sha256:") {
            digest.to_owned()
        } else {
            format!("sha256:{digest}")
        };
        let msg = format!("v1:{revision}:{normalized}");
        let sig = self.key_pair.sign(msg.as_bytes());
        STANDARD.encode(sig.as_ref())
    }
}

pub fn parse_key_32(raw: &str) -> Result<[u8; 32], ConsoleError> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|e| ConsoleError::Vault(format!("invalid hex master key: {e}")))?;
        }
        return Ok(out);
    }
    let decoded = STANDARD
        .decode(trimmed)
        .map_err(|e| ConsoleError::Vault(format!("invalid base64 master key: {e}")))?;
    decoded
        .try_into()
        .map_err(|_| ConsoleError::Vault("master key must decode to exactly 32 bytes".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_envelope_encryption_enforces_aad_isolation() {
        let (key, _) = SecretsVault::generate_dev_key().unwrap();
        let vault = SecretsVault::new(key, true);
        let env = vault
            .encrypt(b"sk-live-secret-123", "org_1|cluster_1|openai|1")
            .unwrap();
        let pt = vault.decrypt(&env, "org_1|cluster_1|openai|1").unwrap();
        assert_eq!(pt, b"sk-live-secret-123");

        // Swapping AAD across orgs/slugs must fail decryption.
        assert!(vault.decrypt(&env, "org_2|cluster_1|openai|1").is_err());
    }

    #[test]
    fn bundle_signer_verifies_with_data_plane_verifier() {
        let (signer, _) = BundleSigner::generate().unwrap();
        let toml = "[server]\nlisten = \"127.0.0.1:8080\"\n";
        let digest = format!("sha256:{}", crate::crypto::sha256_hex(toml.as_bytes()));
        let sig = signer.sign_revision(7, &digest);
        let bundle = shunt_config::TopologyBundleResponse {
            revision: 7,
            digest,
            compiled_toml: toml.to_owned(),
            signature_b64: Some(sig),
        };
        shunt_config::verify_bundle_integrity(&bundle, Some(signer.public_key_b64())).unwrap();
    }
}
