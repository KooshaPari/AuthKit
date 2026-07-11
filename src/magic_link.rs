//! Magic-link (passwordless) authentication (FR-006).
//!
//! Provides a [`MagicLinkService`] that issues single-use, time-limited
//! sign-in links delivered out-of-band (typically email). The link is the
//! only authority for the sign-in: no password is required at consumption
//! time, and the link is invalidated atomically on first use.
//!
//! ## Quick start
//!
//! ```ignore
//! use authkit::magic_link::{InMemoryMagicLinkStore, MagicLinkService};
//!
//! let store = InMemoryMagicLinkStore::new();
//! let svc = MagicLinkService::new(store);
//! let issued = svc.issue("alice@example.com", "https://app.example.com/login")?;
//! // ... email `issued.url` to alice ...
//! let user_id = svc.verify(&issued.token)?;
//! assert!(!user_id.is_empty());
//! ```
//!
//! ## Design
//!
//! Magic links are conceptually similar to password-reset tokens (single
//! use, time-limited, hex token) but differ in two important ways:
//!
//! 1. **User-bound, not email-bound**. A reset token validates an email
//!    that may or may not map to a live account; a magic link is *only*
//!    meaningful for an existing user. We require the caller to have
//!    already looked up the user id before issuing the link.
//! 2. **Login-callback semantics**. The link URL includes the original
//!    callback (e.g. the web-app login page) so consuming it returns the
//!    user back to the caller's surface rather than a generic auth page.
//!
//! The token is delivered to the user as the `?token=<raw>` query string
//! of the embedded callback URL.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default token TTL: 15 minutes. Tighter than password reset (1 hour)
/// because magic links grant live session access; OWASP recommends
/// ≤15 min lifetime for any one-shot sign-in channel.
pub const DEFAULT_MAGIC_LINK_TTL_SECS: u64 = 900;

/// Cryptographic randomness: 32 bytes = 256 bits, hex-encoded to 64 chars.
const TOKEN_BYTES: usize = 32;

/// Errors emitted by the magic-link service.
#[derive(Debug, Error)]
pub enum MagicLinkError {
    #[error("token not found or already consumed")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("token was issued for a different callback: expected {expected}, got {actual}")]
    WrongCallback { expected: String, actual: String },
    #[error("token was issued for a different user: expected {expected}, got {actual}")]
    WrongUser { expected: String, actual: String },
    #[error("user_id is empty")]
    EmptyUserId,
    #[error("callback_url is empty")]
    EmptyCallback,
    #[error("store lock poisoned")]
    Poisoned,
}

/// What the caller gets back when a magic link is issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLink {
    /// The raw token secret. Embed into the callback URL as `?token=<raw>`.
    pub token: String,
    /// The user_id the link authenticates as.
    pub user_id: String,
    /// The full URL the user receives via email — `callback_url?token=<raw>`.
    pub url: String,
    /// The callback URL component (without the token).
    pub callback_url: String,
    /// RFC 3339 timestamp of issuance.
    pub created_at: String,
    /// RFC 3339 timestamp at which this link stops being valid.
    pub expires_at: String,
}

/// Internal stored record (keyed by raw token).
#[derive(Debug, Clone)]
#[allow(dead_code)] // `callback_url` is retained for audit logging even when not consumed
struct StoredMagicLink {
    user_id: String,
    callback_url: String,
    expires_at: DateTime<Utc>,
    consumed: bool,
}

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Cryptographically random token (256 bits, hex-encoded to 64 chars).
fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// Append `?token=<raw>` to `callback_url` while preserving any existing
/// query string. If `callback_url` already has a `token` query parameter,
/// the new value overwrites it.
fn append_token(callback_url: &str, raw_token: &str) -> String {
    if callback_url.contains('?') {
        // Split on the first '?' — everything before is path, everything
        // after is the existing query. Existing query may be empty.
        let (path, query) = match callback_url.split_once('?') {
            Some((p, q)) => (p, q),
            None => (callback_url, ""),
        };
        // Strip any pre-existing token=… entry to avoid double-token URLs.
        let stripped = query
            .split('&')
            .filter(|kv| !kv.is_empty() && !kv.split('=').next().unwrap_or("").eq("token"))
            .collect::<Vec<_>>()
            .join("&");
        if stripped.is_empty() {
            format!("{}?token={}", path, raw_token)
        } else {
            format!("{}?{}&token={}", path, stripped, raw_token)
        }
    } else {
        format!("{}?token={}", callback_url, raw_token)
    }
}

/// Strip the `?token=<raw>` query parameter off a URL, returning
/// `callback_url` (without the token) and the raw token (if present).
///
/// Returns `(callback_url, None)` if no `token` parameter is present.
fn split_token(url: &str) -> Option<(String, String)> {
    let (_, query) = url.split_once('?')?;
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == "token" {
                let callback_url = url.split_once('?').map(|(p, _)| p).unwrap_or(url);
                return Some((callback_url.to_string(), v.to_string()));
            }
        }
    }
    None
}

/// Hexagonal port for magic-link storage.
pub trait MagicLinkStore: Send + Sync {
    /// Issue a new magic link for `user_id` with the given `callback_url`.
    /// Returns the [`MagicLink`] (with raw token) on success. If a previous
    /// unconsumed link for the same user exists it is revoked so the new
    /// one is the only valid link.
    fn issue(
        &self,
        user_id: &str,
        callback_url: &str,
        ttl_secs: Option<u64>,
    ) -> Result<MagicLink, MagicLinkError>;

    /// Atomically validate + invalidate the token against the expected
    /// user_id. Returns Ok(()) on success. The token is removed from the
    /// store as part of the call, so a second `verify` (or a stolen-then-
    /// replayed URL) returns [`MagicLinkError::InvalidToken`].
    fn verify(&self, raw_token: &str, expected_user_id: &str) -> Result<(), MagicLinkError>;

    /// Number of unconsumed links currently held. For tests + metrics.
    fn pending_count(&self) -> Result<usize, MagicLinkError>;
}

/// Thread-safe in-memory [`MagicLinkStore`].
#[derive(Debug)]
pub struct InMemoryMagicLinkStore {
    links: Mutex<HashMap<String, StoredMagicLink>>,
    default_ttl_secs: u64,
}

impl InMemoryMagicLinkStore {
    /// New store with the default 15-minute TTL.
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_MAGIC_LINK_TTL_SECS)
    }

    /// New store with a custom default TTL (in seconds). Set to 0 for
    /// "links expire immediately" — useful only in tests.
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            links: Mutex::new(HashMap::new()),
            default_ttl_secs: ttl_secs,
        }
    }

    /// True when no links are held.
    pub fn is_empty(&self) -> bool {
        self.links.lock().map(|m| m.is_empty()).unwrap_or(true)
    }

    fn evict_expired(map: &mut HashMap<String, StoredMagicLink>) {
        let now = Utc::now();
        map.retain(|_, t| t.expires_at > now);
    }
}

impl Default for InMemoryMagicLinkStore {
    fn default() -> Self {
        Self::new()
    }
}

fn validate<'a>(
    map: &'a HashMap<String, StoredMagicLink>,
    raw_token: &'a str,
    expected_user_id: &'a str,
) -> Result<&'a StoredMagicLink, MagicLinkError> {
    let stored = map.get(raw_token).ok_or(MagicLinkError::InvalidToken)?;
    if stored.consumed {
        return Err(MagicLinkError::InvalidToken);
    }
    if stored.expires_at <= Utc::now() {
        return Err(MagicLinkError::TokenExpired);
    }
    if stored.user_id != expected_user_id {
        return Err(MagicLinkError::WrongUser {
            expected: expected_user_id.to_string(),
            actual: stored.user_id.clone(),
        });
    }
    Ok(stored)
}

impl MagicLinkStore for InMemoryMagicLinkStore {
    fn issue(
        &self,
        user_id: &str,
        callback_url: &str,
        ttl_secs: Option<u64>,
    ) -> Result<MagicLink, MagicLinkError> {
        let user_id = user_id.trim();
        let callback_url = callback_url.trim();
        if user_id.is_empty() {
            return Err(MagicLinkError::EmptyUserId);
        }
        if callback_url.is_empty() {
            return Err(MagicLinkError::EmptyCallback);
        }

        let mut links = self.links.lock().map_err(|_| MagicLinkError::Poisoned)?;
        Self::evict_expired(&mut links);

        // Revoke any existing unconsumed links for this user so the new
        // one is the sole valid link.
        links.retain(|_, l| l.user_id != user_id || l.consumed);

        let ttl = ttl_secs.unwrap_or(self.default_ttl_secs);
        let now = Utc::now();
        let expires = now + Duration::seconds(ttl as i64);
        let raw = generate_token();
        let url = append_token(callback_url, &raw);

        links.insert(
            raw.clone(),
            StoredMagicLink {
                user_id: user_id.to_string(),
                callback_url: callback_url.to_string(),
                expires_at: expires,
                consumed: false,
            },
        );

        Ok(MagicLink {
            token: raw,
            user_id: user_id.to_string(),
            url,
            callback_url: callback_url.to_string(),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        })
    }

    fn verify(&self, raw_token: &str, expected_user_id: &str) -> Result<(), MagicLinkError> {
        let mut links = self.links.lock().map_err(|_| MagicLinkError::Poisoned)?;

        // First, peek via validate — preserves 401 vs 410 semantics in
        // audit logs (InvalidToken vs TokenExpired).
        let _ = validate(&links, raw_token, expected_user_id)?;

        // Atomically remove. Race-safe: if the link was consumed by
        // another thread between validate() and now, it will have been
        // removed, so we return InvalidToken (which is the correct 401
        // semantics for a double-submit).
        let stored = links
            .remove(raw_token)
            .ok_or(MagicLinkError::InvalidToken)?;

        // Final kind-check (defensive — validate() already covered the
        // user_id mismatch path, but a kind-equal record could be left
        // behind on a race).
        if stored.user_id != expected_user_id {
            let wrong_user = stored.user_id.clone();
            links.insert(raw_token.to_string(), stored);
            return Err(MagicLinkError::WrongUser {
                expected: expected_user_id.to_string(),
                actual: wrong_user,
            });
        }
        Ok(())
    }

    fn pending_count(&self) -> Result<usize, MagicLinkError> {
        let links = self.links.lock().map_err(|_| MagicLinkError::Poisoned)?;
        let now = Utc::now();
        Ok(links
            .values()
            .filter(|l| !l.consumed && l.expires_at > now)
            .count())
    }
}

/// Service facade around a [`MagicLinkStore`]. Constructed once at app
/// boot, called on every login attempt. The store is owned by the
/// process; the service is a thin handle.
pub struct MagicLinkService<S: MagicLinkStore> {
    store: S,
}

impl<S: MagicLinkStore> MagicLinkService<S> {
    /// New service with the given store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Issue a magic link for `user_id` that will round-trip via
    /// `callback_url`. Returns the [`MagicLink`] with the full URL the
    /// caller should email to the user.
    pub fn issue(&self, user_id: &str, callback_url: &str) -> Result<MagicLink, MagicLinkError> {
        self.store.issue(user_id, callback_url, None)
    }

    /// Verify the token returned in `issued.url` is valid for `user_id`.
    /// Returns Ok(()) on success; the token is consumed atomically.
    pub fn verify(&self, raw_token: &str, expected_user_id: &str) -> Result<(), MagicLinkError> {
        self.store.verify(raw_token, expected_user_id)
    }

    /// Verify using the full URL the user clicked. Useful when the caller
    /// has the original link URL (e.g. from the auth callback) but not
    /// the raw token. Returns the parsed `user_id` from the link record.
    pub fn verify_url(&self, url: &str, expected_user_id: &str) -> Result<(), MagicLinkError> {
        let (_callback, raw_token) = split_token(url).ok_or(MagicLinkError::InvalidToken)?;
        self.store.verify(&raw_token, expected_user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> InMemoryMagicLinkStore {
        InMemoryMagicLinkStore::new()
    }

    #[test]
    fn issue_returns_full_url_with_token() {
        let store = fixture();
        let issued = store
            .issue("user-1", "https://app.example.com/login", None)
            .unwrap();
        assert_eq!(issued.user_id, "user-1");
        assert_eq!(issued.callback_url, "https://app.example.com/login");
        assert_eq!(issued.token.len(), TOKEN_BYTES * 2);
        assert!(issued.url.contains("token="));
        assert!(issued.url.contains("https://app.example.com/login"));
    }

    #[test]
    fn issue_preserves_existing_query_params() {
        let store = fixture();
        let issued = store
            .issue("user-1", "https://app.example.com/login?from=email", None)
            .unwrap();
        assert!(issued.url.contains("from=email"));
        assert!(issued.url.contains("&token="));
    }

    #[test]
    fn issue_overwrites_existing_token_param() {
        let store = fixture();
        let issued = store
            .issue("user-1", "https://app.example.com/login?token=stolen", None)
            .unwrap();
        // Single token= parameter; the old "stolen" must be gone.
        let token_count = issued.url.matches("token=").count();
        assert_eq!(token_count, 1);
        assert!(!issued.url.contains("token=stolen"));
    }

    #[test]
    fn verify_invalidates_token() {
        let store = fixture();
        let issued = store
            .issue("user-1", "https://app.example.com/login", None)
            .unwrap();
        store.verify(&issued.token, "user-1").unwrap();
        // Second verify fails.
        let err = store.verify(&issued.token, "user-1").unwrap_err();
        assert!(matches!(err, MagicLinkError::InvalidToken));
    }

    #[test]
    fn verify_unknown_token_fails() {
        let store = fixture();
        let err = store.verify("not-a-real-token", "user-1").unwrap_err();
        assert!(matches!(err, MagicLinkError::InvalidToken));
    }

    #[test]
    fn verify_expired_token_fails() {
        let store = InMemoryMagicLinkStore::with_ttl(1);
        let issued = store
            .issue("user-1", "https://app.example.com/login", Some(1))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let err = store.verify(&issued.token, "user-1").unwrap_err();
        assert!(matches!(err, MagicLinkError::TokenExpired));
    }

    #[test]
    fn verify_wrong_user_fails() {
        let store = fixture();
        let issued = store
            .issue("user-1", "https://app.example.com/login", None)
            .unwrap();
        let err = store.verify(&issued.token, "user-2").unwrap_err();
        assert!(matches!(err, MagicLinkError::WrongUser { .. }));
    }

    #[test]
    fn reissuing_for_same_user_revokes_previous() {
        let store = fixture();
        let first = store
            .issue("user-1", "https://app.example.com/login", None)
            .unwrap();
        let second = store
            .issue("user-1", "https://app.example.com/login", None)
            .unwrap();
        assert_ne!(first.token, second.token);
        // Old token should be revoked.
        let err = store.verify(&first.token, "user-1").unwrap_err();
        assert!(matches!(err, MagicLinkError::InvalidToken));
        // New token still valid.
        store.verify(&second.token, "user-1").unwrap();
    }

    #[test]
    fn different_users_have_independent_links() {
        let store = fixture();
        let a = store
            .issue("user-1", "https://app.example.com/login", None)
            .unwrap();
        let b = store
            .issue("user-2", "https://app.example.com/login", None)
            .unwrap();
        assert_ne!(a.token, b.token);
        // Each user's link can only be verified against the same user.
        store.verify(&a.token, "user-1").unwrap();
        store.verify(&b.token, "user-2").unwrap();
    }

    #[test]
    fn empty_user_id_is_rejected() {
        let store = fixture();
        let err = store
            .issue("", "https://app.example.com/login", None)
            .unwrap_err();
        assert!(matches!(err, MagicLinkError::EmptyUserId));
    }

    #[test]
    fn empty_callback_is_rejected() {
        let store = fixture();
        let err = store.issue("user-1", "", None).unwrap_err();
        assert!(matches!(err, MagicLinkError::EmptyCallback));
    }

    #[test]
    fn whitespace_user_id_is_rejected() {
        let store = fixture();
        let err = store
            .issue("   ", "https://app.example.com/login", None)
            .unwrap_err();
        assert!(matches!(err, MagicLinkError::EmptyUserId));
    }

    #[test]
    fn new_store_is_empty() {
        let store = fixture();
        assert!(store.is_empty());
        assert_eq!(store.pending_count().unwrap(), 0);
    }

    #[test]
    fn pending_count_excludes_consumed() {
        let store = fixture();
        let a = store
            .issue("user-1", "https://app.example.com/login", None)
            .unwrap();
        let _b = store
            .issue("user-2", "https://app.example.com/login", None)
            .unwrap();
        assert_eq!(store.pending_count().unwrap(), 2);
        store.verify(&a.token, "user-1").unwrap();
        assert_eq!(store.pending_count().unwrap(), 1);
    }

    #[test]
    fn magic_link_service_roundtrip() {
        let store = fixture();
        let svc = MagicLinkService::new(store);
        let issued = svc
            .issue("user-1", "https://app.example.com/login")
            .unwrap();
        svc.verify(&issued.token, "user-1").unwrap();
    }

    #[test]
    fn magic_link_service_verify_url_roundtrip() {
        let store = fixture();
        let svc = MagicLinkService::new(store);
        let issued = svc
            .issue("user-1", "https://app.example.com/login")
            .unwrap();
        // Pass the full URL the user clicked — service parses out the token.
        svc.verify_url(&issued.url, "user-1").unwrap();
    }

    #[test]
    fn magic_link_service_verify_url_no_token_fails() {
        let store = fixture();
        let svc = MagicLinkService::new(store);
        let err = svc
            .verify_url("https://app.example.com/login?other=1", "user-1")
            .unwrap_err();
        assert!(matches!(err, MagicLinkError::InvalidToken));
    }

    #[test]
    fn zero_ttl_link_issuable_within_same_tick() {
        let store = fixture();
        let issued = store
            .issue("user-1", "https://app.example.com/login", Some(0))
            .unwrap();
        assert!(!issued.token.is_empty());
    }

    #[test]
    fn append_token_handles_no_query() {
        let url = append_token("https://app/x", "abc");
        assert_eq!(url, "https://app/x?token=abc");
    }

    #[test]
    fn append_token_handles_empty_query() {
        let url = append_token("https://app/x?", "abc");
        assert_eq!(url, "https://app/x?token=abc");
    }

    #[test]
    fn split_token_round_trip() {
        let url = append_token("https://app/x?foo=1", "abc");
        let (callback, token) = split_token(&url).unwrap();
        assert_eq!(callback, "https://app/x");
        assert_eq!(token, "abc");
    }
}
