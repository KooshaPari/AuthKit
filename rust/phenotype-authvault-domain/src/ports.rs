//! Port definitions - interfaces for external dependencies.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{Session, SessionId, User, UserId};

// ── Audit log port ────────────────────────────────────────────────────────────

/// The action that triggered the audit event.
///
/// Variants cover every security-relevant operation in Authvault.  Secrets
/// and token values are NEVER stored — only identifiers (JTI, subject, key
/// name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditAction {
    /// An access token was successfully issued.
    TokenIssued,
    /// A token was successfully validated.
    TokenValidated,
    /// A token was rejected (expired, bad signature, wrong audience, malformed,
    /// or revoked).
    TokenRejected,
    /// A token was explicitly revoked (added to the deny-list).
    TokenRevoked,
    /// A refresh-token rotation completed successfully.
    TokenRotated,
    /// A secret was read from the vault.
    VaultRead,
    /// A secret was written (created or overwritten) in the vault.
    VaultWrite,
}

/// Outcome of the action: success or failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The operation completed successfully.
    Success,
    /// The operation failed.
    Failure,
}

/// A single immutable audit record.
///
/// # No-secret guarantee
///
/// `AuditEvent` intentionally has no field for token values, plaintext
/// secrets, or cryptographic key material.  Only opaque identifiers (`jti`,
/// subject UUID, vault key name) are recorded.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Wall-clock timestamp at which the event occurred (UTC).
    pub timestamp: DateTime<Utc>,
    /// Optional caller identity (e.g. user ID or service account).  `None`
    /// when the actor is unknown at the time of the event (unauthenticated
    /// request path).
    pub actor: Option<String>,
    /// The resource being acted upon — e.g. JWT subject, vault key name.
    pub subject: String,
    /// The action that occurred.
    pub action: AuditAction,
    /// Whether the action succeeded or failed.
    pub outcome: AuditOutcome,
    /// Human-readable detail for failures (e.g. "token expired", "key not
    /// found").  MUST NOT contain secret material.
    pub reason: Option<String>,
}

impl AuditEvent {
    /// Construct a successful event.
    pub fn success(actor: Option<String>, subject: impl Into<String>, action: AuditAction) -> Self {
        Self {
            timestamp: Utc::now(),
            actor,
            subject: subject.into(),
            action,
            outcome: AuditOutcome::Success,
            reason: None,
        }
    }

    /// Construct a failure event with an explanatory reason.
    pub fn failure(
        actor: Option<String>,
        subject: impl Into<String>,
        action: AuditAction,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            actor,
            subject: subject.into(),
            action,
            outcome: AuditOutcome::Failure,
            reason: Some(reason.into()),
        }
    }
}

/// Port for emitting audit events.
///
/// Implementors MUST be `Send + Sync` (shared via `Arc`).  Implementations
/// MUST NOT perform blocking I/O inside `record`; use an async channel if
/// persistence is required.
pub trait AuditSink: Send + Sync {
    /// Emit a single audit event.  This method is infallible from the caller's
    /// perspective — implementations that encounter write errors SHOULD log
    /// them internally rather than propagating.
    fn record(&self, event: AuditEvent);
}

/// Port for a JWT revocation store (deny-list checked during token validation).
///
/// Implementations MUST be `Send + Sync` and MAY evict entries whose `exp` has
/// passed to bound memory growth.
pub trait RevocationStore: Send + Sync {
    /// Revoke a token by its `jti`.  `exp` is the token's Unix-timestamp expiry;
    /// implementations use it to schedule TTL eviction so the deny-list does not
    /// grow unbounded.
    fn revoke(&self, jti: &str, exp: i64);

    /// Returns `true` when `jti` is present in the deny-list.
    fn is_revoked(&self, jti: &str) -> bool;
}

/// Port for user storage.
#[async_trait]
pub trait UserStorage: Send + Sync {
    /// Create a user.
    async fn create(&self, user: &User) -> Result<(), String>;

    /// Get a user by ID.
    async fn get_by_id(&self, id: &UserId) -> Result<Option<User>, String>;

    /// Get a user by email.
    async fn get_by_email(&self, email: &str) -> Result<Option<User>, String>;

    /// Update a user.
    async fn update(&self, user: &User) -> Result<(), String>;

    /// Delete a user.
    async fn delete(&self, id: &UserId) -> Result<(), String>;

    /// List users.
    async fn list(&self) -> Result<Vec<User>, String>;
}

/// Port for session storage.
#[async_trait]
pub trait SessionStorage: Send + Sync {
    /// Create a session.
    async fn create(&self, session: &Session) -> Result<(), String>;

    /// Get a session by ID.
    async fn get_by_id(&self, id: &SessionId) -> Result<Option<Session>, String>;

    /// Update a session.
    async fn update(&self, session: &Session) -> Result<(), String>;

    /// Delete a session.
    async fn delete(&self, id: &SessionId) -> Result<(), String>;

    /// Delete all sessions for a user.
    async fn delete_by_user(&self, user_id: &str) -> Result<(), String>;

    /// Delete all expired sessions.
    async fn delete_expired(&self) -> Result<usize, String>;
}

/// Port for password hashing.
pub trait PasswordHasher: Send + Sync {
    /// Hash a password.
    fn hash(&self, password: &str) -> Result<String, String>;

    /// Verify a password against a hash.
    fn verify(&self, password: &str, hash: &str) -> bool;
}

/// A Data-Encryption Key (DEK) generated by a KMS.
///
/// Both fields zeroize on drop — plaintext key material never lingers.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct DataKey {
    /// Plaintext DEK (32 bytes) — use for AEAD encrypt/decrypt, then drop.
    pub plaintext: [u8; 32],
    /// KEK-wrapped (ciphertext) DEK — store alongside the encrypted secret.
    pub wrapped: Vec<u8>,
}

/// Port: Key Management Service — envelope-encryption operations.
///
/// # Hexagonal seam
///
/// The vault depends ONLY on this trait.  The local (master-key-wrapping)
/// adapter is the default; cloud adapters (AWS KMS, GCP Cloud KMS, HashiCorp
/// Vault) can be wired in by providing an alternative implementation.
///
/// # Protocol
///
/// 1. `generate_data_key()` → `(plaintext_dek, wrapped_dek)`
/// 2. Vault encrypts the secret with the plaintext DEK (ChaCha20-Poly1305),
///    then **drops** the plaintext DEK.
/// 3. `wrapped_dek` is stored alongside the ciphertext.
/// 4. On retrieval: `decrypt_data_key(wrapped_dek)` → `plaintext_dek`.
/// 5. Vault decrypts the ciphertext, then **drops** the plaintext DEK.
pub trait KeyManagementService: Send + Sync {
    /// Generate a fresh random 256-bit DEK.
    ///
    /// Returns `Ok(DataKey)` where `plaintext` is the raw DEK and `wrapped`
    /// is the KEK-encrypted DEK (safe to persist).
    fn generate_data_key(&self) -> Result<DataKey, KmsError>;

    /// Unwrap a previously wrapped DEK.
    ///
    /// Returns `Ok(plaintext_dek)` or `Err(KmsError::UnwrapFailed)` when the
    /// ciphertext is tampered or the wrong KEK is used.
    fn decrypt_data_key(&self, wrapped: &[u8]) -> Result<[u8; 32], KmsError>;
}

/// Errors emitted by the KMS port.
#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("Failed to generate data key")]
    GenerateFailed,
    #[error("Failed to unwrap data key: tampered or wrong KEK")]
    UnwrapFailed,
}

// ── VaultStore port ───────────────────────────────────────────────────────────

use crate::vault::{VaultEntry, VaultError};

/// Hexagonal port for persistent vault storage.
///
/// The vault domain depends ONLY on this trait.  Two adapters ship out of the
/// box (in the parent authvault crate's adapters layer):
/// - `InMemoryVaultStore` — ephemeral, tests.
/// - `FileVaultStore` — encrypted-at-rest JSON
///   records serialised to a file (records are ALREADY AEAD-sealed ciphertext;
///   the file never holds plaintext).
///
/// # Future seams
/// TODO(GAP-002): Redis adapter — `RedisVaultStore` backed by a `redis::Client`.
/// TODO(GAP-002): Postgres adapter — `PostgresVaultStore` backed by
///   `tokio_postgres::Client` with a `vault_entries` table.
pub trait VaultStore: Send + Sync {
    /// Persist (insert or overwrite) a sealed record.
    fn put(&self, key: &str, record: VaultEntry) -> Result<(), VaultError>;

    /// Retrieve a sealed record by key, or `None` if absent.
    fn get(&self, key: &str) -> Result<Option<VaultEntry>, VaultError>;

    /// Remove a record.  Returns `true` when the key existed.
    fn delete(&self, key: &str) -> Result<bool, VaultError>;

    /// List all stored keys (including expired — callers filter expiry).
    fn list_keys(&self) -> Result<Vec<String>, VaultError>;
}

/// Port for refresh-token rotation state.
///
/// Tracks the *current* refresh-token JTI for each token family.  A family is
/// created when an access+refresh pair is first issued and identified by a
/// stable `family_id` UUID.  On every rotation:
/// - The old JTI is replaced with the new one.
/// - If the presented JTI does **not** match the stored current JTI the family
///   has been replayed → the implementation SHOULD signal compromise so the
///   caller can revoke the entire family.
pub trait RefreshTokenStore: Send + Sync {
    /// Register a new token family with its initial refresh-token JTI and expiry.
    fn insert_family(&self, family_id: &str, refresh_jti: &str, exp: i64);

    /// Attempt to advance the family to a new JTI.
    ///
    /// Returns `Ok(())` when `old_jti` is the current JTI and the store is
    /// updated to `new_jti`.  Returns `Err(true)` when `old_jti` does not match
    /// (reuse / compromise detected).  Returns `Err(false)` when the family does
    /// not exist or has expired.
    fn rotate(
        &self,
        family_id: &str,
        old_jti: &str,
        new_jti: &str,
        new_exp: i64,
    ) -> Result<(), bool>;

    /// Remove all records for a family (used on compromise revocation).
    fn revoke_family(&self, family_id: &str);
}
