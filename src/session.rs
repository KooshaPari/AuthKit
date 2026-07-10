//! Session management — create, validate, expire sessions (AUT-SOTA-004b).
//!
//! Provides a `SessionManager` that issues opaque bearer session tokens,
//! stores them keyed by a SHA-256 hash of the token, and supports
//! expiration-based cleanup.
//!
//! ## Quick start
//!
//! ```ignore
//! use authkit::session::SessionManager;
//!
//! let mgr = SessionManager::new();
//! let session = mgr.create_session("user-id-123", None)?;
//! assert!(mgr.validate_session(&session.token)?.is_some());
//! mgr.expire_session(&session.token)?;
//! assert!(mgr.validate_session(&session.token)?.is_none());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// Default session TTL: 24 hours.
const DEFAULT_SESSION_TTL_SECS: u64 = 86_400;

/// Errors emitted by the session manager.
#[derive(Debug, Error)]
pub enum SessionManagerError {
    #[error("session not found")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,

    #[error("store lock poisoned")]
    Poisoned,
}

/// A user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    /// The opaque bearer token (only returned on creation).
    pub token: String,
    pub created_at: String,
    pub expires_at: String,
    /// Whether the session has been explicitly expired.
    pub expired: bool,
}

/// Internal stored session (keyed by SHA-256 of token).
#[derive(Debug, Clone)]
struct StoredSession {
    user_id: String,
    token_hash: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    expired: bool,
}

/// SHA-256 hex digest of a token.
fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    format!("{:x}", hash)
}

/// Generate a cryptographically random session token.
fn generate_token() -> String {
    let bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).expect("getrandom failed");
        b
    };
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Thread-safe session manager.
#[derive(Debug)]
pub struct SessionManager {
    sessions: Mutex<HashMap<String, StoredSession>>,
    ttl_secs: u64,
}

impl SessionManager {
    /// Create a new session manager with the default 24h TTL.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ttl_secs: DEFAULT_SESSION_TTL_SECS,
        }
    }

    /// Create a session manager with a custom TTL.
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            ttl_secs: ttl_secs.max(60), // minimum 60s
        }
    }

    /// Create a new session for a user. Returns the `Session` with the
    /// raw bearer token. If `ttl_secs` is `None`, uses the manager default.
    pub fn create_session(
        &self,
        user_id: &str,
        ttl_secs: Option<u64>,
    ) -> Result<Session, SessionManagerError> {
        let ttl = ttl_secs.unwrap_or(self.ttl_secs);
        let token = generate_token();
        let hash = token_hash(&token);
        let session_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::seconds(ttl as i64);

        let stored = StoredSession {
            user_id: user_id.to_string(),
            token_hash: hash,
            created_at: now,
            expires_at: expires,
            expired: false,
        };

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionManagerError::Poisoned)?;
        sessions.insert(session_id.clone(), stored);

        Ok(Session {
            id: session_id,
            user_id: user_id.to_string(),
            token,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            expired: false,
        })
    }

    /// Validate a session token. Returns the session if valid and not expired.
    /// Expired sessions are automatically cleaned up on lookup.
    pub fn validate_session(&self, token: &str) -> Result<Option<Session>, SessionManagerError> {
        let hash = token_hash(token);
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionManagerError::Poisoned)?;
        let now = chrono::Utc::now();

        // Find the session by token hash (linear scan).
        // In production, index by token_hash.
        let session_id = sessions
            .iter()
            .find(|(_, s)| s.token_hash == hash)
            .map(|(id, _)| id.clone());

        let Some(sid) = session_id else {
            return Ok(None);
        };

        let stored = sessions.get(&sid).unwrap();

        if stored.expired {
            sessions.remove(&sid);
            return Ok(None);
        }

        if now > stored.expires_at {
            sessions.remove(&sid);
            return Ok(None);
        }

        Ok(Some(Session {
            id: sid,
            user_id: stored.user_id.clone(),
            token: token.to_string(),
            created_at: stored.created_at.to_rfc3339(),
            expires_at: stored.expires_at.to_rfc3339(),
            expired: false,
        }))
    }

    /// Expire a session (logout).
    pub fn expire_session(&self, token: &str) -> Result<(), SessionManagerError> {
        let hash = token_hash(token);
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionManagerError::Poisoned)?;

        let session_id = sessions
            .iter()
            .find(|(_, s)| s.token_hash == hash)
            .map(|(id, _)| id.clone());

        let Some(sid) = session_id else {
            return Err(SessionManagerError::SessionNotFound);
        };

        sessions.remove(&sid);
        Ok(())
    }

    /// List all active sessions for a user.
    pub fn list_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, SessionManagerError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionManagerError::Poisoned)?;
        let now = chrono::Utc::now();

        Ok(sessions
            .iter()
            .filter(|(_, s)| s.user_id == user_id && !s.expired && now <= s.expires_at)
            .map(|(id, s)| Session {
                id: id.clone(),
                user_id: s.user_id.clone(),
                token: "(hidden)".to_string(),
                created_at: s.created_at.to_rfc3339(),
                expires_at: s.expires_at.to_rfc3339(),
                expired: false,
            })
            .collect())
    }

    /// Return the number of active (non-expired) sessions.
    pub fn active_count(&self) -> Result<usize, SessionManagerError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionManagerError::Poisoned)?;
        let now = chrono::Utc::now();
        Ok(sessions
            .values()
            .filter(|s| !s.expired && now <= s.expires_at)
            .count())
    }

    /// Clean up all expired sessions.
    pub fn cleanup_expired(&self) -> Result<usize, SessionManagerError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionManagerError::Poisoned)?;
        let now = chrono::Utc::now();
        let before = sessions.len();
        sessions.retain(|_, s| !s.expired && now <= s.expires_at);
        Ok(before - sessions.len())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SessionManager {
        SessionManager::with_ttl(3600) // 1 hour
    }

    #[test]
    fn create_session_returns_token() {
        let mgr = fixture();
        let session = mgr.create_session("user-1", None).unwrap();
        assert_eq!(session.user_id, "user-1");
        assert!(!session.token.is_empty());
        assert!(!session.token.contains("(hidden)"));
    }

    #[test]
    fn validate_session_with_valid_token() {
        let mgr = fixture();
        let session = mgr.create_session("user-1", None).unwrap();
        let found = mgr
            .validate_session(&session.token)
            .unwrap()
            .expect("session should be valid");
        assert_eq!(found.user_id, "user-1");
    }

    #[test]
    fn validate_session_with_invalid_token() {
        let mgr = fixture();
        let result = mgr.validate_session("invalid-token").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn expire_session_removes_it() {
        let mgr = fixture();
        let session = mgr.create_session("user-1", None).unwrap();
        mgr.expire_session(&session.token).unwrap();
        let result = mgr.validate_session(&session.token).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn expire_session_twice_fails() {
        let mgr = fixture();
        let session = mgr.create_session("user-1", None).unwrap();
        mgr.expire_session(&session.token).unwrap();
        let err = mgr.expire_session(&session.token).unwrap_err();
        assert!(matches!(err, SessionManagerError::SessionNotFound));
    }

    #[test]
    fn expired_session_by_ttl_is_rejected() {
        let mgr = SessionManager::with_ttl(1); // 1 second TTL
        let session = mgr.create_session("user-1", Some(1)).unwrap();

        // Sleep briefly to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let result = mgr.validate_session(&session.token).unwrap();
        assert!(result.is_none(), "expired session should be rejected");
    }

    #[test]
    fn list_user_sessions_returns_active_only() {
        let mgr = fixture();
        mgr.create_session("user-1", None).unwrap();
        mgr.create_session("user-1", None).unwrap();
        mgr.create_session("user-2", None).unwrap();

        let sessions = mgr.list_user_sessions("user-1").unwrap();
        assert_eq!(sessions.len(), 2);

        let sessions2 = mgr.list_user_sessions("user-2").unwrap();
        assert_eq!(sessions2.len(), 1);
    }

    #[test]
    fn list_user_sessions_hides_tokens() {
        let mgr = fixture();
        let s = mgr.create_session("user-1", None).unwrap();
        let sessions = mgr.list_user_sessions("user-1").unwrap();
        assert_eq!(sessions[0].token, "(hidden)");
        // But the original session still has its token
        assert!(s.token.len() > 10);
    }

    #[test]
    fn active_count_tracks_active_sessions() {
        let mgr = fixture();
        assert_eq!(mgr.active_count().unwrap(), 0);
        mgr.create_session("user-1", None).unwrap();
        assert_eq!(mgr.active_count().unwrap(), 1);
        mgr.create_session("user-2", None).unwrap();
        assert_eq!(mgr.active_count().unwrap(), 2);
    }

    #[test]
    fn cleanup_expired_removes_old_sessions() {
        let mgr = SessionManager::with_ttl(1);
        mgr.create_session("user-1", Some(1)).unwrap();
        mgr.create_session("user-2", Some(3600)).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let cleaned = mgr.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);
        assert_eq!(mgr.active_count().unwrap(), 1);
    }

    #[test]
    fn session_uuids_are_unique() {
        let mgr = fixture();
        let s1 = mgr.create_session("user-1", None).unwrap();
        let s2 = mgr.create_session("user-1", None).unwrap();
        assert_ne!(s1.id, s2.id);
        assert_ne!(s1.token, s2.token);
    }

    #[test]
    fn custom_ttl_per_session() {
        let mgr = SessionManager::with_ttl(3600);
        let session = mgr.create_session("user-1", Some(2)).unwrap();
        // 2-second TTL - should still be valid immediately
        let found = mgr.validate_session(&session.token).unwrap();
        assert!(found.is_some());

        // Wait for expiry
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let result = mgr.validate_session(&session.token).unwrap();
        assert!(result.is_none());
    }
}
