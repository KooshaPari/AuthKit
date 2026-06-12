//! Secret vault with ChaCha20-Poly1305 AEAD at-rest encryption.
//!
//! Every secret is encrypted with a random 96-bit nonce; the master key is a
//! 256-bit key held only in memory (never written to storage).  The on-disk /
//! in-memory ciphertext is `nonce (12 B) || ciphertext+tag`.

use std::collections::HashMap;
use std::sync::Arc;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

use super::ports::{AuditAction, AuditEvent, AuditSink, KeyManagementService};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors that can occur in the vault.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed: bad key or tampered ciphertext")]
    DecryptionFailed,

    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Secret has expired: {0}")]
    Expired(String),

    #[error("Vault key must be exactly 32 bytes")]
    InvalidKeyLength,
}

// ── Master key ────────────────────────────────────────────────────────────────

/// A 256-bit master key used to encrypt / decrypt vault entries.
///
/// Zeroed on drop via [`ZeroizeOnDrop`].
#[derive(Clone, ZeroizeOnDrop)]
pub struct VaultKey {
    raw: [u8; 32],
}

impl VaultKey {
    /// Generate a fresh random master key.
    pub fn generate() -> Self {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&key);
        Self { raw }
    }

    /// Create from an existing 32-byte slice (e.g., loaded from a KMS).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != 32 {
            return Err(VaultError::InvalidKeyLength);
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(bytes);
        Ok(Self { raw })
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.raw))
    }
}

// ── Encrypted envelope ────────────────────────────────────────────────────────

/// Opaque encrypted blob: `nonce (12 B) || ciphertext+tag`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob(Vec<u8>);

impl EncryptedBlob {
    /// Encrypt `plaintext` under `key` with a fresh random nonce.
    pub fn seal(key: &VaultKey, plaintext: &[u8]) -> Result<Self, VaultError> {
        let cipher = key.cipher();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut out = nonce.to_vec(); // 12 bytes
        let ciphertext =
            cipher.encrypt(&nonce, plaintext).map_err(|_| VaultError::EncryptionFailed)?;
        out.extend_from_slice(&ciphertext);
        Ok(Self(out))
    }

    /// Decrypt this blob under `key`.
    pub fn open(&self, key: &VaultKey) -> Result<Vec<u8>, VaultError> {
        if self.0.len() < 12 {
            return Err(VaultError::DecryptionFailed);
        }
        let (nonce_bytes, ciphertext) = self.0.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = key.cipher();
        cipher.decrypt(nonce, ciphertext).map_err(|_| VaultError::DecryptionFailed)
    }

    /// Raw bytes (nonce + ciphertext + tag) — useful for uniqueness checks.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Nonce portion (first 12 bytes).
    pub fn nonce_bytes(&self) -> &[u8] {
        &self.0[..12]
    }
}

// ── Vault entry ───────────────────────────────────────────────────────────────

/// A single encrypted secret stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Logical name / key for this secret.
    pub name: String,
    /// Encrypted secret value.
    pub blob: EncryptedBlob,
    /// When this entry was created.
    pub created_at: DateTime<Utc>,
    /// Optional expiry after which [`SecretVault::get`] returns [`VaultError::Expired`].
    pub expires_at: Option<DateTime<Utc>>,
    /// Monotonically increasing version counter (incremented on each [`SecretVault::rotate`]).
    pub version: u32,
}

impl VaultEntry {
    fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }
}

// ── Vault ─────────────────────────────────────────────────────────────────────

/// In-memory secret vault with AEAD at-rest encryption.
///
/// The `key` never leaves this struct; all entries are stored as ciphertext.
pub struct SecretVault {
    key: VaultKey,
    entries: HashMap<String, VaultEntry>,
    /// Optional audit sink; when set, every read/write/rotate emits an event.
    audit_sink: Option<Arc<dyn AuditSink>>,
}

impl SecretVault {
    /// Create a new vault with the given master key.
    pub fn new(key: VaultKey) -> Self {
        Self { key, entries: HashMap::new(), audit_sink: None }
    }

    /// Attach an audit sink.  Every `put`, `get`, `rotate`, and `remove` will
    /// emit an [`AuditEvent`] to this sink.
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    fn audit(&self, event: AuditEvent) {
        if let Some(sink) = &self.audit_sink {
            sink.record(event);
        }
    }

    /// Store (or overwrite) a secret under `name`.
    ///
    /// `ttl_seconds`: if `Some`, the entry will expire after that many seconds.
    pub fn put(
        &mut self,
        name: impl Into<String>,
        plaintext: &[u8],
        ttl_seconds: Option<i64>,
    ) -> Result<(), VaultError> {
        let name = name.into();
        let blob = EncryptedBlob::seal(&self.key, plaintext);
        match blob {
            Err(e) => {
                self.audit(AuditEvent::failure(
                    None,
                    name.clone(),
                    AuditAction::VaultWrite,
                    e.to_string(),
                ));
                Err(e)
            }
            Ok(blob) => {
                let expires_at =
                    ttl_seconds.map(|secs| Utc::now() + chrono::Duration::seconds(secs));
                let version = self.entries.get(&name).map(|e| e.version + 1).unwrap_or(1);
                self.entries.insert(
                    name.clone(),
                    VaultEntry {
                        name: name.clone(),
                        blob,
                        created_at: Utc::now(),
                        expires_at,
                        version,
                    },
                );
                self.audit(AuditEvent::success(None, name, AuditAction::VaultWrite));
                Ok(())
            }
        }
    }

    /// Retrieve and decrypt a secret by name.
    pub fn get(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        let entry = self.entries.get(name).ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
        if entry.is_expired() {
            self.audit(AuditEvent::failure(None, name, AuditAction::VaultRead, "secret expired"));
            return Err(VaultError::Expired(name.to_owned()));
        }
        let result = entry.blob.open(&self.key);
        match &result {
            Ok(_) => self.audit(AuditEvent::success(None, name, AuditAction::VaultRead)),
            Err(e) => {
                self.audit(AuditEvent::failure(None, name, AuditAction::VaultRead, e.to_string()))
            }
        }
        result
    }

    /// Rotate a secret: re-encrypt the existing plaintext with a fresh nonce,
    /// incrementing the version counter.
    pub fn rotate(&mut self, name: &str) -> Result<(), VaultError> {
        // get() already emits VaultRead; put() will emit VaultWrite on success.
        let plaintext = self.get(name)?; // also checks expiry
        self.put(name, &plaintext, None)
    }

    /// Remove a secret from the vault.
    pub fn remove(&mut self, name: &str) -> bool {
        let removed = self.entries.remove(name).is_some();
        if removed {
            self.audit(AuditEvent::success(None, name, AuditAction::VaultWrite));
        }
        removed
    }

    /// List all non-expired entry names.
    pub fn list(&self) -> Vec<&str> {
        self.entries.values().filter(|e| !e.is_expired()).map(|e| e.name.as_str()).collect()
    }

    /// Metadata for an entry (without decrypting).
    pub fn entry(&self, name: &str) -> Option<&VaultEntry> {
        self.entries.get(name)
    }
}

// ── Envelope-encrypted vault (KMS-backed) ────────────────────────────────────

/// Storage envelope for a KMS-encrypted secret.
///
/// Each secret is encrypted with a unique per-secret DEK.  Only the wrapped
/// (KEK-encrypted) form of the DEK is persisted; the plaintext DEK is
/// zeroized immediately after use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsVaultEntry {
    /// Logical name for this secret.
    pub name: String,
    /// AEAD ciphertext of the secret, encrypted with the plaintext DEK.
    pub blob: EncryptedBlob,
    /// KEK-wrapped DEK — safe to store; useless without the KEK.
    pub wrapped_dek: Vec<u8>,
    /// When this entry was created.
    pub created_at: DateTime<Utc>,
    /// Optional expiry (same semantics as [`VaultEntry`]).
    pub expires_at: Option<DateTime<Utc>>,
    /// Monotonically increasing version counter.
    pub version: u32,
}

impl KmsVaultEntry {
    fn is_expired(&self) -> bool {
        self.expires_at.map(|exp| Utc::now() > exp).unwrap_or(false)
    }
}

/// In-memory secret vault with **envelope encryption** via a KMS port.
///
/// Each secret is encrypted with a fresh per-secret DEK obtained from the KMS.
/// The plaintext DEK is [`ZeroizeOnDrop`] and dropped immediately after each
/// seal / open operation.  Only the wrapped (KEK-encrypted) DEK is stored.
///
/// # Example
///
/// ```rust,ignore
/// let kek = VaultKey::generate();
/// let kms = Arc::new(LocalKmsAdapter::new(kek.raw));
/// let mut vault = KmsSecretVault::new(kms);
/// vault.put("token", b"my-secret", None).unwrap();
/// let plain = vault.get("token").unwrap();
/// assert_eq!(plain, b"my-secret");
/// ```
pub struct KmsSecretVault {
    kms: Arc<dyn KeyManagementService>,
    /// Public for test transplant scenarios only.  External code should use
    /// the `put` / `get` / `remove` API.
    #[doc(hidden)]
    pub entries: HashMap<String, KmsVaultEntry>,
}

impl KmsSecretVault {
    /// Create a new vault backed by the given KMS.
    pub fn new(kms: Arc<dyn KeyManagementService>) -> Self {
        Self { kms, entries: HashMap::new() }
    }

    /// Store (or overwrite) a secret.  A fresh DEK is generated per call.
    ///
    /// `ttl_seconds`: if `Some`, the entry expires after that many seconds.
    pub fn put(
        &mut self,
        name: impl Into<String>,
        plaintext: &[u8],
        ttl_seconds: Option<i64>,
    ) -> Result<(), VaultError> {
        let name = name.into();

        // 1. Ask KMS for a fresh DEK.
        let dk = self.kms.generate_data_key().map_err(|_| VaultError::EncryptionFailed)?;

        // 2. Seal the secret with the plaintext DEK.
        let dek_key = VaultKey::from_bytes(&dk.plaintext)?;
        let blob = EncryptedBlob::seal(&dek_key, plaintext)?;
        // dek_key (and dk.plaintext) are dropped here — ZeroizeOnDrop.

        let wrapped_dek = dk.wrapped.clone();
        let expires_at = ttl_seconds.map(|secs| Utc::now() + chrono::Duration::seconds(secs));
        let version = self.entries.get(&name).map(|e| e.version + 1).unwrap_or(1);

        self.entries.insert(
            name.clone(),
            KmsVaultEntry { name, blob, wrapped_dek, created_at: Utc::now(), expires_at, version },
        );
        Ok(())
    }

    /// Retrieve and decrypt a secret.
    pub fn get(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        let entry = self.entries.get(name).ok_or_else(|| VaultError::NotFound(name.to_owned()))?;
        if entry.is_expired() {
            return Err(VaultError::Expired(name.to_owned()));
        }

        // 1. Ask KMS to unwrap the stored DEK.
        let plaintext_dek = self
            .kms
            .decrypt_data_key(&entry.wrapped_dek)
            .map_err(|_| VaultError::DecryptionFailed)?;

        // 2. Decrypt the blob with the plaintext DEK.
        // dek_key (and plaintext_dek) are ZeroizeOnDrop — dropped at end of scope.
        let dek_key = VaultKey::from_bytes(&plaintext_dek)?;
        entry.blob.open(&dek_key)
    }

    /// Rotate a secret: re-seal with a newly generated DEK.
    pub fn rotate(&mut self, name: &str) -> Result<(), VaultError> {
        let plaintext = self.get(name)?;
        self.put(name, &plaintext, None)
    }

    /// Remove a secret.
    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    /// List all non-expired entry names.
    pub fn list(&self) -> Vec<&str> {
        self.entries.values().filter(|e| !e.is_expired()).map(|e| e.name.as_str()).collect()
    }

    /// Metadata for an entry (without decrypting).
    pub fn entry(&self, name: &str) -> Option<&KmsVaultEntry> {
        self.entries.get(name)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn make_vault() -> SecretVault {
        SecretVault::new(VaultKey::generate())
    }

    // ── round-trip ────────────────────────────────────────────────────────────

    #[test]
    fn round_trip_bytes() {
        let mut v = make_vault();
        v.put("db_password", b"s3cr3t!", None).unwrap();
        let plain = v.get("db_password").unwrap();
        assert_eq!(plain, b"s3cr3t!");
    }

    #[test]
    fn round_trip_unicode() {
        let mut v = make_vault();
        let secret = "日本語テスト🔑";
        v.put("unicode_key", secret.as_bytes(), None).unwrap();
        let plain = v.get("unicode_key").unwrap();
        assert_eq!(String::from_utf8(plain).unwrap(), secret);
    }

    #[test]
    fn round_trip_empty_value() {
        let mut v = make_vault();
        v.put("empty", b"", None).unwrap();
        let plain = v.get("empty").unwrap();
        assert_eq!(plain, b"");
    }

    // ── wrong key ─────────────────────────────────────────────────────────────

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key_a = VaultKey::generate();
        let key_b = VaultKey::generate();

        let blob = EncryptedBlob::seal(&key_a, b"my secret").unwrap();
        let result = blob.open(&key_b);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed)),
            "expected DecryptionFailed, got {result:?}"
        );
    }

    // ── tampered ciphertext (AEAD tag rejection) ───────────────────────────────

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = VaultKey::generate();
        let mut blob = EncryptedBlob::seal(&key, b"sensitive data").unwrap();
        // Flip a bit in the ciphertext portion (after the 12-byte nonce).
        blob.0[12] ^= 0xFF;
        let result = blob.open(&key);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed)),
            "expected DecryptionFailed, got {result:?}"
        );
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = VaultKey::generate();
        let mut blob = EncryptedBlob::seal(&key, b"sensitive data").unwrap();
        // Corrupt the last byte (tag suffix).
        let last = blob.0.len() - 1;
        blob.0[last] ^= 0xFF;
        let result = blob.open(&key);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed)),
            "expected DecryptionFailed, got {result:?}"
        );
    }

    #[test]
    fn tampered_nonce_rejected() {
        let key = VaultKey::generate();
        let mut blob = EncryptedBlob::seal(&key, b"sensitive data").unwrap();
        // Corrupt the nonce (first byte).
        blob.0[0] ^= 0xFF;
        let result = blob.open(&key);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed)),
            "expected DecryptionFailed, got {result:?}"
        );
    }

    // ── nonce uniqueness ──────────────────────────────────────────────────────

    #[test]
    fn nonces_are_unique_across_encryptions() {
        let key = VaultKey::generate();
        let n = 1000;
        let mut nonces: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..n {
            let blob = EncryptedBlob::seal(&key, b"same plaintext").unwrap();
            nonces.insert(blob.nonce_bytes().to_vec());
        }
        assert_eq!(nonces.len(), n, "nonce collision detected");
    }

    #[test]
    fn same_plaintext_yields_different_ciphertexts() {
        let key = VaultKey::generate();
        let blob1 = EncryptedBlob::seal(&key, b"plaintext").unwrap();
        let blob2 = EncryptedBlob::seal(&key, b"plaintext").unwrap();
        assert_ne!(
            blob1.as_bytes(),
            blob2.as_bytes(),
            "ciphertexts must differ due to unique nonces"
        );
    }

    // ── TTL / expiry ──────────────────────────────────────────────────────────

    #[test]
    fn ttl_secret_accessible_before_expiry() {
        let mut v = make_vault();
        v.put("api_key", b"live-key", Some(60)).unwrap();
        let plain = v.get("api_key").unwrap();
        assert_eq!(plain, b"live-key");
    }

    #[test]
    fn expired_secret_returns_error() {
        let mut v = make_vault();
        // TTL of -1 second means already expired.
        v.put("stale_key", b"old-value", Some(-1)).unwrap();
        let result = v.get("stale_key");
        assert!(matches!(result, Err(VaultError::Expired(_))), "expected Expired, got {result:?}");
    }

    // ── not found ─────────────────────────────────────────────────────────────

    #[test]
    fn missing_secret_returns_not_found() {
        let v = make_vault();
        let result = v.get("nonexistent");
        assert!(
            matches!(result, Err(VaultError::NotFound(_))),
            "expected NotFound, got {result:?}"
        );
    }

    // ── versioning / rotation ─────────────────────────────────────────────────

    #[test]
    fn version_increments_on_put() {
        let mut v = make_vault();
        v.put("key", b"v1", None).unwrap();
        assert_eq!(v.entry("key").unwrap().version, 1);
        v.put("key", b"v2", None).unwrap();
        assert_eq!(v.entry("key").unwrap().version, 2);
    }

    #[test]
    fn rotate_re_encrypts_with_new_nonce() {
        let mut v = make_vault();
        v.put("rot_key", b"my-secret", None).unwrap();
        let nonce_before = v.entry("rot_key").unwrap().blob.nonce_bytes().to_vec();

        v.rotate("rot_key").unwrap();
        let nonce_after = v.entry("rot_key").unwrap().blob.nonce_bytes().to_vec();

        assert_ne!(nonce_before, nonce_after, "rotation must use a fresh nonce");

        // Plaintext still recoverable after rotation.
        assert_eq!(v.get("rot_key").unwrap(), b"my-secret");
    }

    #[test]
    fn rotate_increments_version() {
        let mut v = make_vault();
        v.put("ver_key", b"data", None).unwrap();
        v.rotate("ver_key").unwrap();
        assert_eq!(v.entry("ver_key").unwrap().version, 2);
    }

    // ── remove / list ─────────────────────────────────────────────────────────

    #[test]
    fn remove_deletes_entry() {
        let mut v = make_vault();
        v.put("tmp", b"temporary", None).unwrap();
        assert!(v.remove("tmp"));
        assert!(matches!(v.get("tmp"), Err(VaultError::NotFound(_))));
    }

    #[test]
    fn list_excludes_expired_entries() {
        let mut v = make_vault();
        v.put("live", b"a", Some(60)).unwrap();
        v.put("dead", b"b", Some(-1)).unwrap();
        let names = v.list();
        assert!(names.contains(&"live"));
        assert!(!names.contains(&"dead"));
    }

    // ── VaultKey::from_bytes ──────────────────────────────────────────────────

    #[test]
    fn vault_key_from_bytes_wrong_length_fails() {
        let result = VaultKey::from_bytes(&[0u8; 16]);
        assert!(matches!(result, Err(VaultError::InvalidKeyLength)));
    }

    #[test]
    fn vault_key_from_bytes_round_trip() {
        let key = VaultKey::generate();
        let raw = key.raw;
        let restored = VaultKey::from_bytes(&raw).unwrap();
        // Encrypt with original, decrypt with restored.
        let blob = EncryptedBlob::seal(&key, b"test").unwrap();
        assert_eq!(blob.open(&restored).unwrap(), b"test");
    }

    // ── FR-AUTHV-014: Vault audit tests ───────────────────────────────────────

    use std::sync::Arc;

    use crate::adapters::audit::InMemoryAuditSink;
    use crate::domain::ports::{AuditAction, AuditOutcome, AuditSink};

    fn make_audited_vault() -> (SecretVault, Arc<InMemoryAuditSink>) {
        let sink = Arc::new(InMemoryAuditSink::new());
        let vault = SecretVault::new(VaultKey::generate())
            .with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        (vault, sink)
    }

    #[test]
    fn vault_put_emits_vault_write_success() {
        let (mut vault, sink) = make_audited_vault();
        vault.put("api_key", b"value", None).unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::VaultWrite);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(events[0].subject, "api_key");
    }

    #[test]
    fn vault_get_emits_vault_read_success() {
        let (mut vault, sink) = make_audited_vault();
        vault.put("k", b"v", None).unwrap();
        sink.drain();

        vault.get("k").unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::VaultRead);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
    }

    #[test]
    fn vault_get_expired_emits_vault_read_failure_with_reason() {
        let (mut vault, sink) = make_audited_vault();
        vault.put("exp_key", b"v", Some(-1)).unwrap();
        sink.drain();

        let _ = vault.get("exp_key");

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::VaultRead);
        assert_eq!(events[0].outcome, AuditOutcome::Failure);
        assert_eq!(events[0].reason.as_deref(), Some("secret expired"));
    }

    #[test]
    fn vault_rotate_emits_read_then_write() {
        let (mut vault, sink) = make_audited_vault();
        vault.put("r", b"data", None).unwrap();
        sink.drain();

        vault.rotate("r").unwrap();

        let events = sink.events();
        assert!(events.len() >= 2, "rotate must emit VaultRead + VaultWrite");
        assert!(events.iter().any(|e| e.action == AuditAction::VaultRead));
        assert!(events.iter().any(|e| e.action == AuditAction::VaultWrite));
    }

    /// The audit event MUST NOT contain the plaintext secret value.
    #[test]
    fn vault_audit_event_contains_no_plaintext_secret() {
        let (mut vault, sink) = make_audited_vault();
        let plaintext = b"super-secret-password-12345";
        vault.put("pw", plaintext, None).unwrap();
        vault.get("pw").unwrap();

        for event in sink.events() {
            let ptext = std::str::from_utf8(plaintext).unwrap();
            assert_ne!(event.subject, ptext, "plaintext in subject");
            if let Some(reason) = &event.reason {
                assert_ne!(reason.as_str(), ptext, "plaintext in reason");
            }
        }
    }

    // ── FR-AUTHV-015: KMS envelope-encryption tests ───────────────────────────

    use chacha20poly1305::{aead::OsRng as ChaChaOsRng, KeyInit};

    use crate::adapters::kms::LocalKmsAdapter;

    fn make_kms_vault() -> KmsSecretVault {
        let kek_raw = {
            let k = chacha20poly1305::ChaCha20Poly1305::generate_key(&mut ChaChaOsRng);
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&k);
            raw
        };
        let kms = Arc::new(LocalKmsAdapter::new(kek_raw));
        KmsSecretVault::new(kms)
    }

    /// FR-AUTHV-015 AC-1: round-trip — encrypt with generated DEK → wrapped DEK
    /// stored → decrypt via KMS unwrap → recover plaintext.
    #[test]
    fn kms_vault_round_trip() {
        let mut vault = make_kms_vault();
        vault.put("api_key", b"super-secret", None).unwrap();
        let plain = vault.get("api_key").unwrap();
        assert_eq!(plain, b"super-secret");
    }

    #[test]
    fn kms_vault_round_trip_unicode() {
        let mut vault = make_kms_vault();
        let secret = "日本語テスト🔑";
        vault.put("uni", secret.as_bytes(), None).unwrap();
        assert_eq!(vault.get("uni").unwrap(), secret.as_bytes());
    }

    #[test]
    fn kms_vault_round_trip_empty() {
        let mut vault = make_kms_vault();
        vault.put("empty", b"", None).unwrap();
        assert_eq!(vault.get("empty").unwrap(), b"");
    }

    /// FR-AUTHV-015 AC-2: wrong KEK fails to unwrap — simulate by building a
    /// second KMS with a different KEK and transplanting the wrapped_dek.
    #[test]
    fn kms_vault_wrong_kek_fails_to_decrypt() {
        // Two KMS instances with different KEKs.
        let kek_a = {
            let k = chacha20poly1305::ChaCha20Poly1305::generate_key(&mut ChaChaOsRng);
            let mut r = [0u8; 32];
            r.copy_from_slice(&k);
            r
        };
        let kek_b = {
            let k = chacha20poly1305::ChaCha20Poly1305::generate_key(&mut ChaChaOsRng);
            let mut r = [0u8; 32];
            r.copy_from_slice(&k);
            r
        };
        let kms_a = Arc::new(LocalKmsAdapter::new(kek_a));
        let kms_b = Arc::new(LocalKmsAdapter::new(kek_b));

        // Seal with KMS-A.
        let mut vault_a = KmsSecretVault::new(Arc::clone(&kms_a) as Arc<dyn KeyManagementService>);
        vault_a.put("secret", b"value", None).unwrap();

        // Manually transplant the entry into a vault backed by KMS-B.
        let entry_a = vault_a.entry("secret").unwrap().clone();
        let mut vault_b = KmsSecretVault::new(Arc::clone(&kms_b) as Arc<dyn KeyManagementService>);
        vault_b.entries.insert("secret".to_string(), entry_a);

        let result = vault_b.get("secret");
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed)),
            "wrong KEK must not decrypt: {result:?}"
        );
    }

    /// FR-AUTHV-015 AC-3: each secret gets a distinct DEK (no DEK reuse).
    #[test]
    fn kms_vault_each_secret_has_distinct_dek() {
        let mut vault = make_kms_vault();
        vault.put("s1", b"value1", None).unwrap();
        vault.put("s2", b"value2", None).unwrap();
        let wrapped1 = vault.entry("s1").unwrap().wrapped_dek.clone();
        let wrapped2 = vault.entry("s2").unwrap().wrapped_dek.clone();
        assert_ne!(wrapped1, wrapped2, "each secret must use a distinct DEK");
    }

    /// FR-AUTHV-015 AC-4: tampered wrapped-DEK rejected — get() must fail.
    #[test]
    fn kms_vault_tampered_wrapped_dek_rejected() {
        let mut vault = make_kms_vault();
        vault.put("tok", b"payload", None).unwrap();

        // Tamper the wrapped DEK in-place.
        if let Some(entry) = vault.entries.get_mut("tok") {
            entry.wrapped_dek[12] ^= 0xFF;
        }
        let result = vault.get("tok");
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed)),
            "tampered wrapped DEK must be rejected: {result:?}"
        );
    }

    /// Extra: rotate re-seals with a NEW DEK (new wrapped_dek stored).
    #[test]
    fn kms_vault_rotate_uses_new_dek() {
        let mut vault = make_kms_vault();
        vault.put("key", b"data", None).unwrap();
        let wrapped_before = vault.entry("key").unwrap().wrapped_dek.clone();
        vault.rotate("key").unwrap();
        let wrapped_after = vault.entry("key").unwrap().wrapped_dek.clone();
        assert_ne!(wrapped_before, wrapped_after, "rotation must generate a new DEK");
        assert_eq!(vault.get("key").unwrap(), b"data");
    }
}
