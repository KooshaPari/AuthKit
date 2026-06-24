//! PKCE OAuth state to session binding port.
//!
//! Hexagonal port (trait) for binding OAuth `state` tokens to server-side
//! session identifiers. The `enforce_pkce_state_session` middleware uses
//! this port to gate OAuth callbacks. In-memory adapter is provided for
//! tests; production adapters (Redis, Postgres) can implement the trait.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{Duration, Utc};

/// Result alias for the session-state binding port.
pub type Result<T> = std::result::Result<T, SessionStoreError>;

/// Errors emitted by the session-state store.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("session store lock poisoned")]
    Poisoned,
}

#[derive(Debug, Clone)]
struct Entry {
    session_id: String,
    expires_at: chrono::DateTime<Utc>,
}

/// Hexagonal port for binding OAuth `state` values to server-side sessions.
pub trait SessionStore: Send + Sync {
    /// Bind an OAuth state token to a server session identifier.
    fn bind_state(&self, state_token: &str, session_id: &str) -> Result<()>;

    /// Verify that a state token is bound to the supplied session identifier.
    fn verify_state(&self, state_token: &str, session_id: &str) -> Result<bool>;

    /// Remove a state binding.
    fn revoke_state(&self, state_token: &str) -> Result<()>;
}

/// Thread-safe in-memory `SessionStore` implementation with TTL eviction.
#[derive(Debug)]
pub struct InMemorySessionStore {
    inner: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
}

impl InMemorySessionStore {
    /// Create a store with the default 15 minute binding TTL.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a store with a custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self { inner: Mutex::new(HashMap::new()), ttl }
    }

    fn evict_expired(map: &mut HashMap<String, Entry>) {
        let now = Utc::now();
        map.retain(|_, entry| entry.expires_at > now);
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::with_ttl(Duration::minutes(15))
    }
}

impl SessionStore for InMemorySessionStore {
    fn bind_state(&self, state_token: &str, session_id: &str) -> Result<()> {
        let mut map = self.inner.lock().map_err(|_| SessionStoreError::Poisoned)?;
        Self::evict_expired(&mut map);
        map.insert(
            state_token.to_owned(),
            Entry { session_id: session_id.to_owned(), expires_at: Utc::now() + self.ttl },
        );
        Ok(())
    }

    fn verify_state(&self, state_token: &str, session_id: &str) -> Result<bool> {
        let mut map = self.inner.lock().map_err(|_| SessionStoreError::Poisoned)?;
        Self::evict_expired(&mut map);
        Ok(map.get(state_token).map(|entry| entry.session_id == session_id).unwrap_or(false))
    }

    fn revoke_state(&self, state_token: &str) -> Result<()> {
        let mut map = self.inner.lock().map_err(|_| SessionStoreError::Poisoned)?;
        map.remove(state_token);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expired_store() -> InMemorySessionStore {
        InMemorySessionStore::with_ttl(Duration::seconds(-1))
    }

    #[test]
    fn bind_and_verify_state_succeeds() {
        let store = InMemorySessionStore::new();
        store.bind_state("state-1", "session-1").unwrap();
        assert!(store.verify_state("state-1", "session-1").unwrap());
    }

    #[test]
    fn verify_wrong_session_fails() {
        let store = InMemorySessionStore::new();
        store.bind_state("state-1", "session-1").unwrap();
        assert!(!store.verify_state("state-1", "session-2").unwrap());
    }

    #[test]
    fn verify_missing_state_fails() {
        let store = InMemorySessionStore::new();
        assert!(!store.verify_state("missing-state", "session-1").unwrap());
    }

    #[test]
    fn revoke_state_removes_binding() {
        let store = InMemorySessionStore::new();
        store.bind_state("state-1", "session-1").unwrap();
        store.revoke_state("state-1").unwrap();
        assert!(!store.verify_state("state-1", "session-1").unwrap());
    }

    #[test]
    fn expired_state_is_rejected() {
        let store = expired_store();
        store.bind_state("state-1", "session-1").unwrap();
        assert!(!store.verify_state("state-1", "session-1").unwrap());
    }

    #[test]
    fn rebinding_state_overwrites_previous_session() {
        let store = InMemorySessionStore::new();
        store.bind_state("state-1", "session-1").unwrap();
        store.bind_state("state-1", "session-2").unwrap();
        assert!(!store.verify_state("state-1", "session-1").unwrap());
        assert!(store.verify_state("state-1", "session-2").unwrap());
    }
}
