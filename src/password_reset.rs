//! Password reset + email verification tokens (FR-004 / AUT-SOTA-004d).
//!
//! Provides a [`TokenStore`] port that issues single-use, time-limited
//! tokens for two distinct flows:
//!
//! - **Password reset** — issued by `/forgot-password`, emailed to the
//!   user, consumed by `/reset-password`. The token itself is the only
//!   authority for the reset; the user's existing password is never
//!   required to consume it.
//! - **Email verification** — issued at sign-up, emailed to the user,
//!   consumed by `/verify-email`. No password change involved.
//!
//! Both flows share the same token shape and TTL plumbing but are kept
//! distinct via [`TokenKind`] so a reset token can't be replayed against
//! the email-verification endpoint (or vice versa).
//!
//! Delivery is the caller's responsibility: this crate returns the
//! [`ResetToken`] struct with the raw token string and the consumer
//! hands it to whatever mailer they use. Keeping the transport out of
//! the crate means AuthKit stays SMTP / SES / Postmark / Resend-agnostic.
//!
//! ## Quick start
//!
//! ```ignore
//! use authkit::password_reset::{InMemoryTokenStore, TokenKind, TokenStore};
//!
//! let store = InMemoryTokenStore::new();
//! let issued = store.issue("alice@example.com", TokenKind::PasswordReset, None)?;
//! // ... email `issued.token` to alice ...
//! let email = store.consume(&issued.token, TokenKind::PasswordReset)?;
//! assert_eq!(email, "alice@example.com");
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default token TTL: 1 hour. Matches the OWASP "Authentication Cheat
/// Sheet" recommendation for password-reset link lifetime.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;

/// Cryptographic randomness: 32 bytes = 256 bits, hex-encoded to 64 chars.
const TOKEN_BYTES: usize = 32;

/// Distinguishes reset tokens from email-verification tokens so a token
/// issued for one flow cannot be replayed against the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    /// Password reset (issued by `/forgot-password`, consumed by `/reset-password`).
    PasswordReset,
    /// Email verification (issued at sign-up, consumed by `/verify-email`).
    EmailVerification,
}

impl TokenKind {
    /// Stable string identifier suitable for storage / audit logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenKind::PasswordReset => "password_reset",
            TokenKind::EmailVerification => "email_verification",
        }
    }
}

/// Error type for token issuance / verification / consumption.
#[derive(Debug, Error)]
pub enum PasswordResetError {
    #[error("token not found or already consumed")]
    InvalidToken,
    #[error("token expired")]
    TokenExpired,
    #[error("token issued for a different flow: expected {expected}, got {actual}")]
    WrongFlow {
        expected: &'static str,
        actual: String,
    },
    #[error("store lock poisoned")]
    Poisoned,
}

/// What the caller gets back when a token is issued. The raw `token`
/// string is the secret that must be transported to the user; the rest
/// is metadata that may be persisted at the caller's discretion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetToken {
    pub token: String,
    pub email: String,
    pub kind: TokenKind,
    pub created_at: String,
    pub expires_at: String,
}

/// Internal stored record. Token map is keyed by the raw token string
/// (hex); collisions on a 256-bit space are not a practical concern.
///
/// `created_at` is intentionally not stored internally: the issued
/// [`ResetToken`] already carries an RFC 3339 string, and storing the
/// raw `DateTime<Utc>` here as well would duplicate it without any
/// consumer. The TTL is enforced via `expires_at` alone; anything past
/// that point is treated as expired on the next operation regardless.
#[derive(Debug, Clone)]
struct StoredToken {
    email: String,
    kind: TokenKind,
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

/// Hexagonal port for password-reset / email-verification token storage.
pub trait TokenStore: Send + Sync {
    /// Issue a new token for `email` of the given `kind`. Returns the
    /// [`ResetToken`] (with raw token) on success. If a previous
    /// unconsumed token for the same (email, kind) pair exists it is
    /// revoked so the new one is the only valid token.
    fn issue(
        &self,
        email: &str,
        kind: TokenKind,
        ttl_secs: Option<u64>,
    ) -> Result<ResetToken, PasswordResetError>;

    /// Peek at the email associated with a token without consuming it.
    /// Used by `/forgot-password?token=...` validation pages that want
    /// to render a "Hi alice@example.com" greeting before the user has
    /// pressed "submit new password".
    fn peek(&self, token: &str, kind: TokenKind) -> Result<String, PasswordResetError>;

    /// Atomically validate + invalidate a token. Returns the email on
    /// success. The token is removed from the store as part of the
    /// call, so a second `consume` (or a stolen-then-replayed URL)
    /// returns [`PasswordResetError::InvalidToken`].
    fn consume(&self, token: &str, kind: TokenKind) -> Result<String, PasswordResetError>;

    /// Revoke a token without consuming it. Used when:
    ///   - the user successfully signed in via another channel and the
    ///     reset is no longer needed;
    ///   - the user clicks "I didn't request this" on the email;
    ///   - a higher-security session is established and all in-flight
    ///     reset tokens for the email should be invalidated.
    fn revoke(&self, token: &str) -> Result<(), PasswordResetError>;

    /// Number of unconsumed tokens currently held. For tests + metrics.
    fn pending_count(&self) -> Result<usize, PasswordResetError>;
}

/// Thread-safe in-memory [`TokenStore`].
#[derive(Debug)]
pub struct InMemoryTokenStore {
    tokens: Mutex<HashMap<String, StoredToken>>,
    default_ttl_secs: u64,
}

impl InMemoryTokenStore {
    /// New store with the default 1-hour TTL.
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TOKEN_TTL_SECS)
    }

    /// New store with a custom default TTL (in seconds). Set to 0 for
    /// "tokens expire immediately" — useful only in tests; in production
    /// use [`DEFAULT_TOKEN_TTL_SECS`] (1 hour).
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            default_ttl_secs: ttl_secs,
        }
    }

    /// True when no tokens are held.
    pub fn is_empty(&self) -> bool {
        self.tokens.lock().map(|m| m.is_empty()).unwrap_or(true)
    }

    fn evict_expired(map: &mut HashMap<String, StoredToken>) {
        let now = Utc::now();
        map.retain(|_, t| t.expires_at > now);
    }
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

fn validate<'a>(
    map: &'a HashMap<String, StoredToken>,
    token: &str,
    kind: TokenKind,
) -> Result<&'a StoredToken, PasswordResetError> {
    let stored = map.get(token).ok_or(PasswordResetError::InvalidToken)?;
    if stored.kind != kind {
        return Err(PasswordResetError::WrongFlow {
            expected: kind.as_str(),
            actual: stored.kind.as_str().to_string(),
        });
    }
    if stored.consumed {
        return Err(PasswordResetError::InvalidToken);
    }
    if stored.expires_at <= Utc::now() {
        return Err(PasswordResetError::TokenExpired);
    }
    Ok(stored)
}

impl TokenStore for InMemoryTokenStore {
    fn issue(
        &self,
        email: &str,
        kind: TokenKind,
        ttl_secs: Option<u64>,
    ) -> Result<ResetToken, PasswordResetError> {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(PasswordResetError::InvalidToken);
        }
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| PasswordResetError::Poisoned)?;
        Self::evict_expired(&mut tokens);

        // Revoke any existing unconsumed tokens for this (email, kind)
        // pair so the new one is the sole valid token.
        tokens.retain(|_, t| !(t.email == email && t.kind == kind && !t.consumed));

        let ttl = ttl_secs.unwrap_or(self.default_ttl_secs);
        let now = Utc::now();
        let expires = now + Duration::seconds(ttl as i64);
        let raw = generate_token();
        let email_clone = email.clone();
        tokens.insert(
            raw.clone(),
            StoredToken {
                email: email_clone,
                kind,
                expires_at: expires,
                consumed: false,
            },
        );

        Ok(ResetToken {
            token: raw,
            email,
            kind,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        })
    }

    fn peek(&self, token: &str, kind: TokenKind) -> Result<String, PasswordResetError> {
        let tokens = self
            .tokens
            .lock()
            .map_err(|_| PasswordResetError::Poisoned)?;
        let stored = validate(&tokens, token, kind)?;
        Ok(stored.email.clone())
    }

    fn consume(&self, token: &str, kind: TokenKind) -> Result<String, PasswordResetError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| PasswordResetError::Poisoned)?;

        // Validate first (returns InvalidToken / TokenExpired / WrongFlow
        // as appropriate) so a 401-vs-410 distinction is preserved in
        // audit logs. We deliberately do NOT pre-evict expired entries
        // here — validate() needs to see an expired entry to return
        // TokenExpired rather than InvalidToken. The next issue() call
        // sweeps them.
        let _ = validate(&tokens, token, kind)?;

        // Atomically remove + re-check kind against a same-token kind
        // swap that could have raced between validate() and now.
        let stored = tokens
            .remove(token)
            .ok_or(PasswordResetError::InvalidToken)?;
        if stored.kind != kind {
            let wrong_kind = stored.kind.as_str().to_string();
            tokens.insert(token.to_string(), stored);
            return Err(PasswordResetError::WrongFlow {
                expected: kind.as_str(),
                actual: wrong_kind,
            });
        }
        Ok(stored.email)
    }

    fn revoke(&self, token: &str) -> Result<(), PasswordResetError> {
        let mut tokens = self
            .tokens
            .lock()
            .map_err(|_| PasswordResetError::Poisoned)?;
        if tokens.remove(token).is_none() {
            return Err(PasswordResetError::InvalidToken);
        }
        Ok(())
    }

    fn pending_count(&self) -> Result<usize, PasswordResetError> {
        let tokens = self
            .tokens
            .lock()
            .map_err(|_| PasswordResetError::Poisoned)?;
        let now = Utc::now();
        Ok(tokens
            .values()
            .filter(|t| !t.consumed && t.expires_at > now)
            .count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> InMemoryTokenStore {
        InMemoryTokenStore::new()
    }

    #[test]
    fn issue_token_returns_email_and_raw_token() {
        let store = fixture();
        let issued = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        assert_eq!(issued.email, "alice@example.com");
        assert_eq!(issued.kind, TokenKind::PasswordReset);
        assert_eq!(issued.token.len(), TOKEN_BYTES * 2);
        assert!(!issued.token.is_empty());
    }

    #[test]
    fn peek_returns_email_without_consuming() {
        let store = fixture();
        let issued = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        let peeked = store.peek(&issued.token, TokenKind::PasswordReset).unwrap();
        assert_eq!(peeked, "alice@example.com");
        // Token is still valid after peek.
        assert!(store.peek(&issued.token, TokenKind::PasswordReset).is_ok());
    }

    #[test]
    fn consume_returns_email_and_invalidates_token() {
        let store = fixture();
        let issued = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        let consumed = store
            .consume(&issued.token, TokenKind::PasswordReset)
            .unwrap();
        assert_eq!(consumed, "alice@example.com");
        // Second consume fails.
        let err = store
            .consume(&issued.token, TokenKind::PasswordReset)
            .unwrap_err();
        assert!(matches!(err, PasswordResetError::InvalidToken));
    }

    #[test]
    fn consume_unknown_token_fails() {
        let store = fixture();
        let err = store
            .consume("not-a-real-token", TokenKind::PasswordReset)
            .unwrap_err();
        assert!(matches!(err, PasswordResetError::InvalidToken));
    }

    #[test]
    fn consume_expired_token_fails() {
        let store = InMemoryTokenStore::with_ttl(1);
        let issued = store
            .issue("alice@example.com", TokenKind::PasswordReset, Some(1))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let err = store
            .consume(&issued.token, TokenKind::PasswordReset)
            .unwrap_err();
        assert!(matches!(err, PasswordResetError::TokenExpired));
    }

    #[test]
    fn consume_wrong_flow_fails() {
        let store = fixture();
        let issued = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        let err = store
            .consume(&issued.token, TokenKind::EmailVerification)
            .unwrap_err();
        assert!(matches!(err, PasswordResetError::WrongFlow { .. }));
    }

    #[test]
    fn revoke_unknown_token_fails() {
        let store = fixture();
        let err = store.revoke("never-issued").unwrap_err();
        assert!(matches!(err, PasswordResetError::InvalidToken));
    }

    #[test]
    fn revoke_issued_token_succeeds() {
        let store = fixture();
        let issued = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        store.revoke(&issued.token).unwrap();
        let err = store
            .consume(&issued.token, TokenKind::PasswordReset)
            .unwrap_err();
        assert!(matches!(err, PasswordResetError::InvalidToken));
    }

    #[test]
    fn reissuing_for_same_email_revokes_previous() {
        let store = fixture();
        let first = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        let second = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        assert_ne!(first.token, second.token);
        // Old token should be revoked.
        let err = store
            .consume(&first.token, TokenKind::PasswordReset)
            .unwrap_err();
        assert!(matches!(err, PasswordResetError::InvalidToken));
        // New token still valid.
        let consumed = store
            .consume(&second.token, TokenKind::PasswordReset)
            .unwrap();
        assert_eq!(consumed, "alice@example.com");
    }

    #[test]
    fn tokens_for_different_kinds_dont_collide() {
        let store = fixture();
        let reset = store
            .issue("alice@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        let verify = store
            .issue("alice@example.com", TokenKind::EmailVerification, None)
            .unwrap();
        assert_ne!(reset.token, verify.token);
        // Each token is consumable only by its own kind.
        assert!(store
            .consume(&reset.token, TokenKind::PasswordReset)
            .is_ok());
        assert!(store
            .consume(&verify.token, TokenKind::EmailVerification)
            .is_ok());
    }

    #[test]
    fn empty_email_is_rejected() {
        let store = fixture();
        let err = store
            .issue("   ", TokenKind::PasswordReset, None)
            .unwrap_err();
        assert!(matches!(err, PasswordResetError::InvalidToken));
    }

    #[test]
    fn zero_ttl_token_still_issuable_within_same_tick() {
        let store = fixture();
        // TTL of 0 means expires_at == now(). The issued token is
        // still returned (issue is synchronous) and *may* be consumable
        // immediately if the consume path runs before wall-clock advances
        // past expires_at. We only assert that issuance doesn't error.
        let issued = store
            .issue("alice@example.com", TokenKind::PasswordReset, Some(0))
            .unwrap();
        assert!(!issued.token.is_empty());
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
            .issue("a@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        let _b = store
            .issue("b@example.com", TokenKind::PasswordReset, None)
            .unwrap();
        assert_eq!(store.pending_count().unwrap(), 2);
        store.consume(&a.token, TokenKind::PasswordReset).unwrap();
        assert_eq!(store.pending_count().unwrap(), 1);
    }

    #[test]
    fn token_kind_as_str_roundtrip() {
        assert_eq!(TokenKind::PasswordReset.as_str(), "password_reset");
        assert_eq!(TokenKind::EmailVerification.as_str(), "email_verification");
    }

    #[test]
    fn email_is_lowercased_at_issue() {
        let store = fixture();
        let issued = store
            .issue("Alice@Example.COM", TokenKind::PasswordReset, None)
            .unwrap();
        assert_eq!(issued.email, "alice@example.com");
        let consumed = store
            .consume(&issued.token, TokenKind::PasswordReset)
            .unwrap();
        assert_eq!(consumed, "alice@example.com");
    }
}
