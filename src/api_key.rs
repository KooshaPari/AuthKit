//! API-Key authentication (FR-007).
//!
//! Provides a [`ApiKeyService`] that issues, lists, and revokes long-lived
//! API keys suitable for non-interactive SDK clients (CLIs, servers, CI
//! pipelines). Unlike [`crate::session`] tokens or
//! [`crate::magic_link`] tokens, API keys are designed for machine-to-machine
//! authentication and survive across many requests.
//!
//! ## Quick start
//!
//! ```ignore
//! use authkit::api_key::{ApiKeyService, InMemoryApiKeyStore};
//!
//! let store = InMemoryApiKeyStore::new();
//! let svc = ApiKeyService::new(store);
//!
//! // Owner issues a new key for themselves (e.g. from a /settings page).
//! let issued = svc.issue("user_alice", "alice@example.com", None)?;
//!
//! // Caller proves possession of the raw key on a later request.
//! let resolved = svc.verify(&issued.raw_key)?;
//! assert_eq!(resolved.user_id, "user_alice");
//! ```
//!
//! ## Security model
//!
//! API keys are split into two halves — a public **prefix** and a secret
//! **body** — following the GitHub `gh-`-style convention:
//!
//! | Part | Stored as | Visible to user |
//! |------|-----------|-----------------|
//! | Key id (random 8 hex chars) | plaintext | yes (used as lookup index) |
//! | Body (32 random bytes, hex) | **sha256 hash** | yes, **once** at issue time |
//!
//! Because we store only the hash, a database leak does **not** leak the
//! raw keys. The `verify()` method derives the hash from the candidate
//! raw key and compares it to the stored hash in constant time via the
//! [`subtle`] crate. The lookup is O(1) via the key id index, so timing
//! doesn't reveal the position of valid keys.
//!
//! ## Design choices
//!
//! - **Atomic single-use at issue**: the raw key is returned exactly once.
//!   Subsequent verification proves possession of the hash, but we cannot
//!   re-display the raw key.
//! - **Revocation is durable**: revocation removes the key from the active
//!   set, so a leaked raw key can be retired without rotating the parent
//!   user's other credentials.
//! - **Optional expiry**: keys are valid forever by default but can carry
//!   an explicit `expires_at` for short-lived CI tokens.
//! - **Optional label**: a human-readable label (`"ci-deploy"`, `"prod-billing"`)
//!   for accountability in audit logs.
//!
//! [`subtle`]: https://docs.rs/subtle

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Default prefix for our API keys (e.g. `bp_<id>_<body>`).
pub const API_KEY_PREFIX: &str = "bp_";

/// Length of the public id portion in hex chars (8 hex chars = 4 bytes = 2^32 namespace).
pub const KEY_ID_HEX_CHARS: usize = 8;

/// Length of the secret body in hex chars (64 hex chars = 32 bytes = 256 bits).
pub const KEY_BODY_HEX_CHARS: usize = 64;

/// Errors emitted by the API-key service.
#[derive(Debug, Error)]
pub enum ApiKeyError {
    #[error("api key not found or revoked")]
    NotFound,
    #[error("api key expired")]
    Expired,
    #[error("api key hash mismatch (key body invalid)")]
    HashMismatch,
    #[error("api key prefix is malformed: {0}")]
    MalformedKey(String),
    #[error("label is empty")]
    EmptyLabel,
    #[error("user_id is empty")]
    EmptyUserId,
    #[error("store lock poisoned")]
    Poisoned,
}

/// What the caller gets back when a new API key is issued.
///
/// `raw_key` is the only time the secret body is returned to the caller.
/// It must be persisted by the caller immediately — there is no API to
/// retrieve it later. The other fields are stored by the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedApiKey {
    /// The full raw key the user must store. Only available at issue time.
    pub raw_key: String,
    /// The public id portion (8 hex chars).
    pub key_id: String,
    /// The user that owns this key.
    pub user_id: String,
    /// The user's email at issue time (for display in account settings).
    pub user_email: String,
    /// Human-readable label.
    pub label: String,
    /// When the key was issued.
    pub issued_at: DateTime<Utc>,
    /// When the key expires, if any.
    pub expires_at: Option<DateTime<Utc>>,
    /// When the key was issued, hidden once for user (a copy of the raw key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shown_once_at: Option<DateTime<Utc>>,
}

/// Public-facing summary view of an API key (no hash, no raw body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeySummary {
    pub key_id: String,
    pub user_id: String,
    pub user_email: String,
    pub label: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// Internal record: what we actually persist.
///
/// `pub` is required because [`ApiKeyStore::list_for_user`] et al. return
/// `Vec<StoredApiKey>`, and those trait methods are themselves `pub`. Marked
/// `#[doc(hidden)]` so it does not appear in rustdoc — it is an
/// implementation detail of the store trait, not a public API surface.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct StoredApiKey {
    pub key_id: String,
    pub user_id: String,
    pub user_email: String,
    pub label: String,
    pub hash_hex: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// Result returned by [`ApiKeyService::verify`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyResolution {
    pub key_id: String,
    pub user_id: String,
    pub user_email: String,
    pub label: String,
}

/// Hex storage port for API keys. Implementations: in-memory (test/dev),
/// Postgres (prod), SQLite (single-process).
pub trait ApiKeyStore: Send + Sync {
    /// Insert a new API key record. Returns `false` on `key_id` collision
    /// (statistically impossible at 32 bits but worth handling).
    fn insert(&self, record: StoredApiKey) -> Result<bool, ApiKeyError>;

    /// Look up by key id. Returns the full record (including hash).
    fn get_active(&self, key_id: &str) -> Result<Option<StoredApiKey>, ApiKeyError>;

    /// Mark the key revoked. Returns `false` if no such key exists.
    fn revoke(&self, key_id: &str) -> Result<bool, ApiKeyError>;

    /// List all keys for a user (active + revoked).
    fn list_for_user(&self, user_id: &str) -> Result<Vec<StoredApiKey>, ApiKeyError>;
}

/// In-memory API key store. Suitable for tests and single-process dev.
#[derive(Debug, Default)]
pub struct InMemoryApiKeyStore {
    inner: Mutex<HashMap<String, StoredApiKey>>,
}

impl InMemoryApiKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ApiKeyStore for InMemoryApiKeyStore {
    fn insert(&self, record: StoredApiKey) -> Result<bool, ApiKeyError> {
        let mut guard = self.inner.lock().map_err(|_| ApiKeyError::Poisoned)?;
        if guard.contains_key(&record.key_id) {
            return Ok(false);
        }
        guard.insert(record.key_id.clone(), record);
        Ok(true)
    }

    fn get_active(&self, key_id: &str) -> Result<Option<StoredApiKey>, ApiKeyError> {
        let guard = self.inner.lock().map_err(|_| ApiKeyError::Poisoned)?;
        Ok(guard.get(key_id).cloned())
    }

    fn revoke(&self, key_id: &str) -> Result<bool, ApiKeyError> {
        let mut guard = self.inner.lock().map_err(|_| ApiKeyError::Poisoned)?;
        if let Some(rec) = guard.get_mut(key_id) {
            if rec.revoked {
                // Idempotent: already revoked, return false.
                return Ok(false);
            }
            rec.revoked = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn list_for_user(&self, user_id: &str) -> Result<Vec<StoredApiKey>, ApiKeyError> {
        let guard = self.inner.lock().map_err(|_| ApiKeyError::Poisoned)?;
        Ok(guard
            .values()
            .filter(|r| r.user_id == user_id)
            .cloned()
            .collect())
    }
}

/// Facade over any [`ApiKeyStore`].
pub struct ApiKeyService<S: ApiKeyStore> {
    store: S,
}

impl<S: ApiKeyStore> ApiKeyService<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Issue a new API key. `label` is optional; pass `None` for an
    /// empty default. `expires_at` is optional; pass `None` for an
    /// immortal key.
    ///
    /// Returns the full raw key plus a public summary. The caller MUST
    /// persist `raw_key` immediately — it cannot be retrieved later.
    pub fn issue(
        &self,
        user_id: &str,
        user_email: &str,
        label: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<IssuedApiKey, ApiKeyError> {
        if user_id.is_empty() {
            return Err(ApiKeyError::EmptyUserId);
        }
        let label = label.unwrap_or("").to_string();
        if label.is_empty() {
            return Err(ApiKeyError::EmptyLabel);
        }

        let key_id = random_hex(KEY_ID_HEX_CHARS / 2);
        let body = random_hex(KEY_BODY_HEX_CHARS / 2);
        let raw_key = format!("{API_KEY_PREFIX}{key_id}_{body}");

        let hash_hex = sha256_hex(raw_key.as_bytes());
        let now = Utc::now();

        let stored = StoredApiKey {
            key_id: key_id.clone(),
            user_id: user_id.to_string(),
            user_email: user_email.to_string(),
            label: label.clone(),
            hash_hex,
            issued_at: now,
            expires_at,
            revoked: false,
        };

        self.store.insert(stored)?;

        Ok(IssuedApiKey {
            raw_key,
            key_id,
            user_id: user_id.to_string(),
            user_email: user_email.to_string(),
            label,
            issued_at: now,
            expires_at,
            shown_once_at: Some(now),
        })
    }

    /// Verify a raw API key and resolve it to its owner. Returns
    /// `Err(ApiKeyError::NotFound)` if the key id is unknown or revoked,
    /// `Err(ApiKeyError::HashMismatch)` if the body doesn't match, and
    /// `Err(ApiKeyError::Expired)` if the key has passed `expires_at`.
    pub fn verify(&self, raw_key: &str) -> Result<ApiKeyResolution, ApiKeyError> {
        let (key_id, _body) = parse_raw_key(raw_key)?;
        let stored = self
            .store
            .get_active(&key_id)?
            .ok_or(ApiKeyError::NotFound)?;

        if stored.revoked {
            return Err(ApiKeyError::NotFound);
        }
        if let Some(exp) = stored.expires_at {
            if Utc::now() > exp {
                return Err(ApiKeyError::Expired);
            }
        }

        let candidate_hash = sha256_hex(raw_key.as_bytes());
        if stored
            .hash_hex
            .as_bytes()
            .ct_eq(candidate_hash.as_bytes())
            .into()
        {
            Ok(ApiKeyResolution {
                key_id: stored.key_id,
                user_id: stored.user_id,
                user_email: stored.user_email,
                label: stored.label,
            })
        } else {
            Err(ApiKeyError::HashMismatch)
        }
    }

    /// Revoke an API key. Idempotent: revoking an unknown or already-revoked
    /// key returns `Ok(false)` rather than erroring.
    pub fn revoke(&self, key_id: &str) -> Result<bool, ApiKeyError> {
        self.store.revoke(key_id)
    }

    /// List all API keys (active and revoked) for a user, as public
    /// summaries (no hashes).
    pub fn list_for_user(&self, user_id: &str) -> Result<Vec<ApiKeySummary>, ApiKeyError> {
        let records = self.store.list_for_user(user_id)?;
        Ok(records.into_iter().map(record_to_summary).collect())
    }

    /// Convenience: list only the active (non-revoked, non-expired) keys
    /// for a user.
    pub fn list_active_for_user(&self, user_id: &str) -> Result<Vec<ApiKeySummary>, ApiKeyError> {
        let now = Utc::now();
        Ok(self
            .store
            .list_for_user(user_id)?
            .into_iter()
            .filter(|r| !r.revoked && r.expires_at.map_or(true, |e| now <= e))
            .map(record_to_summary)
            .collect())
    }
}

fn record_to_summary(r: StoredApiKey) -> ApiKeySummary {
    ApiKeySummary {
        key_id: r.key_id,
        user_id: r.user_id,
        user_email: r.user_email,
        label: r.label,
        issued_at: r.issued_at,
        expires_at: r.expires_at,
        revoked: r.revoked,
    }
}

/// Parse a raw API key of the form `bp_<id_hex>_<body_hex>` into its
/// parts. Returns `MalformedKey` for any structural inconsistency.
pub fn parse_raw_key(raw: &str) -> Result<(String, String), ApiKeyError> {
    if !raw.starts_with(API_KEY_PREFIX) {
        return Err(ApiKeyError::MalformedKey(format!(
            "missing prefix {API_KEY_PREFIX}"
        )));
    }
    let stripped = &raw[API_KEY_PREFIX.len()..];
    let parts: Vec<&str> = stripped.splitn(2, '_').collect();
    if parts.len() != 2 {
        return Err(ApiKeyError::MalformedKey(
            "expected format bp_<id>_<body>".into(),
        ));
    }
    let key_id = parts[0];
    let body = parts[1];
    if key_id.len() != KEY_ID_HEX_CHARS || body.len() != KEY_BODY_HEX_CHARS {
        return Err(ApiKeyError::MalformedKey(format!(
            "id must be {KEY_ID_HEX_CHARS} hex chars, body must be {KEY_BODY_HEX_CHARS} hex chars"
        )));
    }
    if !key_id.chars().all(|c| c.is_ascii_hexdigit())
        || !body.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ApiKeyError::MalformedKey("non-hex characters".into()));
    }
    Ok((key_id.to_string(), body.to_string()))
}

fn random_hex(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    hex_encode(&out)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn svc() -> ApiKeyService<InMemoryApiKeyStore> {
        ApiKeyService::new(InMemoryApiKeyStore::new())
    }

    #[test]
    fn issued_key_returns_raw_key_and_summary() {
        let s = svc();
        let issued = s
            .issue("user_alice", "alice@example.com", Some("ci-deploy"), None)
            .unwrap();

        assert!(issued.raw_key.starts_with(API_KEY_PREFIX));
        assert_eq!(issued.user_id, "user_alice");
        assert_eq!(issued.label, "ci-deploy");
        assert!(issued.expires_at.is_none());
        // key_id is exactly KEY_ID_HEX_CHARS long
        assert_eq!(issued.key_id.len(), KEY_ID_HEX_CHARS);
        // raw_key body portion is exactly KEY_BODY_HEX_CHARS long
        // raw_key is "bp_" + 8 + "_" + 64 = 75 chars
        assert_eq!(
            issued.raw_key.len(),
            3 + KEY_ID_HEX_CHARS + 1 + KEY_BODY_HEX_CHARS
        );
    }

    #[test]
    fn verify_resolves_to_user() {
        let s = svc();
        let issued = s
            .issue("user_alice", "alice@example.com", Some("ci"), None)
            .unwrap();

        let r = s.verify(&issued.raw_key).unwrap();
        assert_eq!(r.user_id, "user_alice");
        assert_eq!(r.label, "ci");
        assert_eq!(r.key_id, issued.key_id);
    }

    #[test]
    fn verify_unknown_key_id_returns_not_found() {
        let s = svc();
        // Valid shape but never issued
        let zeros = "0".repeat(64);
        let unknown = format!("bp_00000001_{zeros}");
        let err = s.verify(&unknown).unwrap_err();
        assert!(matches!(err, ApiKeyError::NotFound));
    }

    #[test]
    fn verify_wrong_body_returns_hash_mismatch() {
        let s = svc();
        let issued = s
            .issue("user_alice", "alice@example.com", Some("ci"), None)
            .unwrap();
        // Same id, different body
        let zeros = "0".repeat(64);
        let wrong_body = format!("bp_{:0>8}_{zeros}", "1");
        let tampered = format!("bp_{}_{}", issued.key_id, zeros);
        let err = s.verify(&tampered).unwrap_err();
        assert!(matches!(err, ApiKeyError::HashMismatch));
        // Silence unused
        let _ = wrong_body;
    }

    #[test]
    fn verify_revoked_key_returns_not_found() {
        let s = svc();
        let issued = s
            .issue("user_alice", "alice@example.com", Some("ci"), None)
            .unwrap();
        assert!(s.revoke(&issued.key_id).unwrap());
        let err = s.verify(&issued.raw_key).unwrap_err();
        assert!(matches!(err, ApiKeyError::NotFound));
    }

    #[test]
    fn expired_key_rejected() {
        let s = svc();
        let past = Utc::now() - Duration::seconds(1);
        let issued = s
            .issue("user_alice", "alice@example.com", Some("ci"), Some(past))
            .unwrap();
        let err = s.verify(&issued.raw_key).unwrap_err();
        assert!(matches!(err, ApiKeyError::Expired));
    }

    #[test]
    fn future_expiry_accepted() {
        let s = svc();
        let future = Utc::now() + Duration::hours(1);
        let issued = s
            .issue("user_alice", "alice@example.com", Some("ci"), Some(future))
            .unwrap();
        assert!(s.verify(&issued.raw_key).is_ok());
    }

    #[test]
    fn malformed_key_no_prefix() {
        let s = svc();
        let err = s
            .verify("aaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap_err();
        assert!(matches!(err, ApiKeyError::MalformedKey(_)));
    }

    #[test]
    fn malformed_key_wrong_separator() {
        let s = svc();
        // 75+ chars with bp_ prefix but wrong separator char (space instead of _)
        let zeros = "0".repeat(64);
        let bad = format!("bp_0000007a {zeros}");
        let err = s.verify(&bad).unwrap_err();
        assert!(matches!(err, ApiKeyError::MalformedKey(_)));
    }

    #[test]
    fn parse_raw_key_extracts_components() {
        let id = "abcdef01";
        let body = "0".repeat(64);
        let raw = format!("bp_{id}_{body}");
        let (parsed_id, parsed_body) = parse_raw_key(&raw).unwrap();
        assert_eq!(parsed_id, id);
        assert_eq!(parsed_body, body);
    }

    #[test]
    fn reject_empty_user_id() {
        let s = svc();
        let err = s
            .issue("", "alice@example.com", Some("ci"), None)
            .unwrap_err();
        assert!(matches!(err, ApiKeyError::EmptyUserId));
    }

    #[test]
    fn reject_empty_label() {
        let s = svc();
        let err = s
            .issue("user_alice", "alice@example.com", None, None)
            .unwrap_err();
        assert!(matches!(err, ApiKeyError::EmptyLabel));
    }

    #[test]
    fn list_for_user_returns_only_that_user() {
        let s = svc();
        s.issue("user_alice", "alice@example.com", Some("ci"), None)
            .unwrap();
        s.issue("user_bob", "bob@example.com", Some("prod"), None)
            .unwrap();
        let alice_list = s.list_for_user("user_alice").unwrap();
        assert_eq!(alice_list.len(), 1);
        assert_eq!(alice_list[0].user_id, "user_alice");

        let both = s
            .list_for_user("user_alice")
            .unwrap()
            .into_iter()
            .chain(s.list_for_user("user_bob").unwrap())
            .collect::<Vec<_>>();
        assert_eq!(both.len(), 2);
    }

    #[test]
    fn list_active_for_user_filters_revoked_and_expired() {
        let s = svc();
        let active = s
            .issue("user_alice", "alice@example.com", Some("active"), None)
            .unwrap();
        let to_revoke = s
            .issue("user_alice", "alice@example.com", Some("revoked"), None)
            .unwrap();
        let expired = s
            .issue(
                "user_alice",
                "alice@example.com",
                Some("expired"),
                Some(Utc::now() - Duration::seconds(60)),
            )
            .unwrap();

        s.revoke(&to_revoke.key_id).unwrap();

        let active_list = s.list_active_for_user("user_alice").unwrap();
        assert_eq!(active_list.len(), 1);
        assert_eq!(active_list[0].key_id, active.key_id);
        // sanity: the other two exist but were filtered
        let all = s.list_for_user("user_alice").unwrap();
        assert_eq!(all.len(), 3);
        // expired one is the recorded key
        let _ = expired.key_id;
    }

    #[test]
    fn revoke_unknown_key_returns_false() {
        let s = svc();
        assert!(!s.revoke("00000000").unwrap());
    }

    #[test]
    fn revoke_is_idempotent() {
        let s = svc();
        let issued = s
            .issue("user_alice", "alice@example.com", Some("ci"), None)
            .unwrap();
        assert!(s.revoke(&issued.key_id).unwrap());
        assert!(!s.revoke(&issued.key_id).unwrap());
    }

    #[test]
    fn constant_time_compare_via_subtle_called() {
        // We can't directly observe constant-time behavior, but we verify
        // that verify returns HashMismatch for a body that differs from
        // the stored hash. (subtle::ConstantTimeEq is used in verify().)
        let s = svc();
        let issued = s.issue("u", "u@example.com", Some("ci"), None).unwrap();
        // Replace last char of body with a different hex digit
        let mut tampered = issued.raw_key.clone();
        let last = tampered.pop().unwrap();
        let swap = if last == '0' { '1' } else { '0' };
        tampered.push(swap);
        let err = s.verify(&tampered).unwrap_err();
        assert!(matches!(err, ApiKeyError::HashMismatch));
    }

    #[test]
    fn reissuing_after_revoke_returns_a_different_key_id() {
        let s = svc();
        let first = s.issue("u", "u@example.com", Some("ci"), None).unwrap();
        s.revoke(&first.key_id).unwrap();
        let second = s.issue("u", "u@example.com", Some("ci"), None).unwrap();
        assert_ne!(first.key_id, second.key_id);
    }

    #[test]
    fn multiple_keys_per_user_supported() {
        let s = svc();
        for i in 0..5 {
            s.issue(
                "user_alice",
                "alice@example.com",
                Some(&format!("key-{i}")),
                None,
            )
            .unwrap();
        }
        assert_eq!(s.list_for_user("user_alice").unwrap().len(), 5);
    }
}
