//! Local (in-process) KMS adapter — wraps DEKs with the master KEK.
//!
//! The KEK (Key Encryption Key) is the vault's `VaultKey`.  Each
//! `generate_data_key()` call creates a fresh 256-bit DEK, wraps it with the
//! KEK using ChaCha20-Poly1305 AEAD + a fresh nonce, and returns both the
//! plaintext DEK and the wrapped ciphertext.
//!
//! # Cloud KMS seam
//!
//! To swap in AWS KMS / GCP Cloud KMS:
//!
//! 1. Create `src/adapters/kms_aws.rs` implementing `KeyManagementService`.
//! 2. Wire via `SecretVaultBuilder::with_kms(Arc::new(AwsKmsAdapter::new(...)))`.
//!
//! The domain layer (`vault.rs`) depends only on the `KeyManagementService`
//! trait — no changes needed there.
//!
//! # TODO (upstream)
//!
//! - AWS KMS adapter: use `aws-sdk-kms` crate, `GenerateDataKey` / `Decrypt`.
//! - GCP KMS adapter: use `google-cloud-kms` crate, `CryptoKey` wrapKeyVersion.
//! - HashiCorp Vault adapter: Transit Secrets Engine encrypt/decrypt endpoints.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use zeroize::Zeroize;

use phenotype_authvault_domain::ports::{DataKey, KeyManagementService, KmsError};

/// Local KMS adapter that wraps DEKs using a master KEK held in memory.
///
/// This is the default adapter; it requires no external infrastructure.
pub struct LocalKmsAdapter {
    kek: [u8; 32],
}

impl LocalKmsAdapter {
    /// Create a local KMS from an existing 32-byte KEK (e.g., the vault master key).
    pub fn new(kek: [u8; 32]) -> Self {
        Self { kek }
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.kek))
    }
}

impl Drop for LocalKmsAdapter {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

impl KeyManagementService for LocalKmsAdapter {
    fn generate_data_key(&self) -> Result<DataKey, KmsError> {
        // Generate a fresh 256-bit DEK.
        let raw_dek = ChaCha20Poly1305::generate_key(&mut OsRng);
        let mut plaintext = [0u8; 32];
        plaintext.copy_from_slice(&raw_dek);

        // Wrap DEK with KEK: nonce (12 B) || ciphertext+tag.
        let cipher = self.cipher();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext =
            cipher.encrypt(&nonce, plaintext.as_ref()).map_err(|_| KmsError::GenerateFailed)?;
        let mut wrapped = nonce.to_vec();
        wrapped.extend_from_slice(&ciphertext);

        Ok(DataKey { plaintext, wrapped })
    }

    fn decrypt_data_key(&self, wrapped: &[u8]) -> Result<[u8; 32], KmsError> {
        if wrapped.len() < 12 {
            return Err(KmsError::UnwrapFailed);
        }
        let (nonce_bytes, ciphertext) = wrapped.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = self.cipher();
        let plaintext_vec =
            cipher.decrypt(nonce, ciphertext).map_err(|_| KmsError::UnwrapFailed)?;
        if plaintext_vec.len() != 32 {
            return Err(KmsError::UnwrapFailed);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plaintext_vec);
        Ok(out)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn make_kms() -> LocalKmsAdapter {
        let kek = {
            let k = ChaCha20Poly1305::generate_key(&mut OsRng);
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&k);
            raw
        };
        LocalKmsAdapter::new(kek)
    }

    // ── round-trip ────────────────────────────────────────────────────────────

    #[test]
    fn generate_and_decrypt_round_trip() {
        let kms = make_kms();
        let dk = kms.generate_data_key().expect("generate");
        let recovered = kms.decrypt_data_key(&dk.wrapped).expect("decrypt");
        assert_eq!(dk.plaintext, recovered, "plaintext DEK must survive wrap/unwrap");
    }

    // ── wrong KEK rejects unwrap ──────────────────────────────────────────────

    #[test]
    fn wrong_kek_fails_to_unwrap() {
        let kms_a = make_kms();
        let kms_b = make_kms(); // different KEK
        let dk = kms_a.generate_data_key().expect("generate");
        let result = kms_b.decrypt_data_key(&dk.wrapped);
        assert!(
            matches!(result, Err(KmsError::UnwrapFailed)),
            "wrong KEK must not unwrap: {result:?}"
        );
    }

    // ── each secret gets a distinct DEK ──────────────────────────────────────

    #[test]
    fn each_generate_produces_distinct_dek() {
        let kms = make_kms();
        let dk1 = kms.generate_data_key().expect("gen1");
        let dk2 = kms.generate_data_key().expect("gen2");
        assert_ne!(dk1.plaintext, dk2.plaintext, "each call must produce a unique DEK");
        assert_ne!(dk1.wrapped, dk2.wrapped, "wrapped DEKs must also differ");
    }

    // ── tampered wrapped-DEK rejected ─────────────────────────────────────────

    #[test]
    fn tampered_wrapped_dek_rejected() {
        let kms = make_kms();
        let dk = kms.generate_data_key().expect("generate");
        let mut tampered = dk.wrapped.clone();
        // Flip a bit in the ciphertext portion (after the 12-byte nonce).
        tampered[12] ^= 0xFF;
        let result = kms.decrypt_data_key(&tampered);
        assert!(
            matches!(result, Err(KmsError::UnwrapFailed)),
            "tampered wrapped DEK must be rejected: {result:?}"
        );
    }

    // ── 100 DEKs all distinct (no DEK reuse) ─────────────────────────────────

    #[test]
    fn no_dek_reuse_across_many_generations() {
        let kms = make_kms();
        let n = 100usize;
        let mut plaintexts: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..n {
            let dk = kms.generate_data_key().expect("generate");
            plaintexts.insert(dk.plaintext.to_vec());
        }
        assert_eq!(plaintexts.len(), n, "DEK reuse detected");
    }
}
