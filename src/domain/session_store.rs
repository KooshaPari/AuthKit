//! PKCE OAuth state to session binding port.
//!
//! Hexagonal port (trait) for binding OAuth `state` tokens to server-side
//! session identifiers. The `enforce_pkce_state_session` middleware uses
//! this port to gate OAuth callbacks. In-memory adapter is provided for
//! tests; production adapters (Redis, Postgres) can implement the trait.

use std::collections::HashMap;
use std::sync::Mutex;

use subtle::ConstantTimeEq;

use chrono::{Duration, Utc};

/// Result alias for the session-state binding port.
pub type Result<T> = std::result::Result<T, SessionStoreError>;

/// Errors emitted by the session-state store.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("session store lock poisoned")]
    Poisoned,
    /// The store has reached its configured `max_entries` ceiling.  Callers
    /// should surface a 503 to the OAuth callback or rotate to a backend
    /// with bounded memory.
    #[error("session store at capacity (max_entries={0})")]
    AtCapacity(usize),
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

/// Default capacity for the in-memory store when the caller does not pick
/// one.  Sized to fit a few thousand pending OAuth callbacks without
/// ballooning — see L25 in the v37 audit.
pub const DEFAULT_MAX_ENTRIES: usize = 65_536;

/// Thread-safe in-memory `SessionStore` implementation with TTL eviction.
#[derive(Debug)]
pub struct InMemorySessionStore {
    inner: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
    max_entries: usize,
}

impl InMemorySessionStore {
    /// Create a store with the default 15 minute binding TTL and
    /// [`DEFAULT_MAX_ENTRIES`] capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a store with a custom TTL and the default capacity.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_MAX_ENTRIES)
    }

    /// Create a store with a custom TTL and a hard capacity ceiling.
    ///
    /// `max_entries == 0` is treated as unbounded — useful for tests that
    /// want to opt out of the cap without rewriting call sites.
    pub fn with_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Current entry count.  Primarily for tests and metrics.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// `true` when no entries are currently bound.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn evict_expired(map: &mut HashMap<String, Entry>) {
        let now = Utc::now();
        map.retain(|_, entry| entry.expires_at > now);
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::with_capacity(Duration::minutes(15), DEFAULT_MAX_ENTRIES)
    }
}

impl SessionStore for InMemorySessionStore {
    fn bind_state(&self, state_token: &str, session_id: &str) -> Result<()> {
        let mut map = self.inner.lock().map_err(|_| SessionStoreError::Poisoned)?;
        Self::evict_expired(&mut map);
        if self.max_entries != 0
            && map.len() >= self.max_entries
            && !map.contains_key(state_token)
        {
            return Err(SessionStoreError::AtCapacity(self.max_entries));
        }
        map.insert(
            state_token.to_owned(),
            Entry {
                session_id: session_id.to_owned(),
                expires_at: Utc::now() + self.ttl,
            },
        );
        Ok(())
    }

    fn verify_state(&self, state_token: &str, session_id: &str) -> Result<bool> {
        let mut map = self.inner.lock().map_err(|_| SessionStoreError::Poisoned)?;
        Self::evict_expired(&mut map);
        Ok(map
            .get(state_token)
            .map(|entry| {
                entry
                    .session_id
                    .as_bytes()
                    .ct_eq(session_id.as_bytes())
                    .into()
            })
            .unwrap_or(false))
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

    /// Constant-time compare: a session id of the same byte-length as the
    /// stored one but differing in content must be rejected.  This exercises
    /// the `ConstantTimeEq` branch and guards against a regression to `==`.
    #[test]
    fn constant_time_compare_rejects_same_length_wrong_session() {
        let store = InMemorySessionStore::new();
        // Both ids are 12 bytes; only identical bytes should pass.
        store.bind_state("state-x", "aaaaaaaaaaaa").unwrap();
        assert!(!store.verify_state("state-x", "bbbbbbbbbbbb").unwrap());
        assert!(store.verify_state("state-x", "aaaaaaaaaaaa").unwrap());
    }

    #[test]
    fn new_store_is_empty() {
        let store = InMemorySessionStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn capacity_rejects_overflow_but_allows_rebind() {
        // Bound the store at exactly 2 entries so we can hit the ceiling
        // without spinning through DEFAULT_MAX_ENTRIES.
        let store = InMemorySessionStore::with_capacity(Duration::minutes(15), 2);
        store.bind_state("s1", "sess-1").unwrap();
        store.bind_state("s2", "sess-2").unwrap();
        assert_eq!(store.len(), 2);

        // Third distinct key must be rejected with AtCapacity — protects the
        // server from an unbounded callback flood.
        match store.bind_state("s3", "sess-3") {
            Err(SessionStoreError::AtCapacity(2)) => {}
            other => panic!("expected AtCapacity(2), got {other:?}"),
        }

        // Rebinding an existing key must still be allowed even at the
        // ceiling (it's a replace, not a new allocation).
        store.bind_state("s1", "sess-1-rebound").unwrap();
        assert!(store.verify_state("s1", "sess-1-rebound").unwrap());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn capacity_zero_means_unbounded() {
        // `0` is the documented opt-out sentinel for tests.
        let store = InMemorySessionStore::with_capacity(Duration::minutes(15), 0);
        for i in 0..128 {
            store.bind_state(&format!("s{i}"), &format!("sess-{i}")).unwrap();
        }
        assert_eq!(store.len(), 128);
    }
}
