//! In-memory [`RevocationStore`] adapter with TTL-based eviction.
//!
//! Revoked JTIs are stored alongside their token expiry timestamp.  On every
//! [`revoke`] call the store prunes entries whose `exp` is already in the past,
//! bounding the deny-list to only live tokens.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;

use phenotype_authvault_domain::ports::RevocationStore;

/// Entry stored for each revoked JTI.
#[derive(Debug)]
struct Entry {
    /// Unix-timestamp expiry carried from the JWT `exp` claim.
    exp: i64,
}

/// Thread-safe in-memory revocation store.
///
/// Memory is bounded: every [`revoke`] call evicts all entries whose token has
/// already expired, so the map never holds more entries than there are currently
/// live (non-expired) tokens that have been explicitly revoked.
#[derive(Debug, Default)]
pub struct InMemoryRevocationStore {
    inner: Mutex<HashMap<String, Entry>>,
}

impl InMemoryRevocationStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove all entries whose `exp` is in the past.
    fn evict_expired(map: &mut HashMap<String, Entry>) {
        let now = Utc::now().timestamp();
        map.retain(|_, entry| entry.exp > now);
    }
}

impl RevocationStore for InMemoryRevocationStore {
    fn revoke(&self, jti: &str, exp: i64) {
        let mut map = self.inner.lock().expect("revocation store lock poisoned");
        Self::evict_expired(&mut map);
        map.insert(jti.to_owned(), Entry { exp });
    }

    fn is_revoked(&self, jti: &str) -> bool {
        let map = self.inner.lock().expect("revocation store lock poisoned");
        map.contains_key(jti)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use super::*;

    fn future_exp(secs: i64) -> i64 {
        (Utc::now() + Duration::seconds(secs)).timestamp()
    }

    fn past_exp(secs: i64) -> i64 {
        (Utc::now() - Duration::seconds(secs)).timestamp()
    }

    // --- RevocationStore unit tests ---

    #[test]
    fn revoke_then_is_revoked_returns_true() {
        let store = InMemoryRevocationStore::new();
        let jti = "test-jti-001";
        store.revoke(jti, future_exp(3600));
        assert!(store.is_revoked(jti));
    }

    #[test]
    fn unrevoked_jti_is_not_revoked() {
        let store = InMemoryRevocationStore::new();
        store.revoke("other-jti", future_exp(3600));
        assert!(!store.is_revoked("unrelated-jti"));
    }

    #[test]
    fn expired_entries_are_evicted_on_next_revoke() {
        let store = InMemoryRevocationStore::new();
        let expired_jti = "expired-jti";

        // Insert an already-expired entry directly via revoke (exp in the past)
        store.revoke(expired_jti, past_exp(10));

        // Trigger eviction by revoking a fresh token
        store.revoke("fresh-jti", future_exp(3600));

        // The expired JTI should have been evicted
        assert!(!store.is_revoked(expired_jti));
    }

    #[test]
    fn fresh_revoked_entry_survives_eviction_pass() {
        let store = InMemoryRevocationStore::new();
        let live_jti = "live-jti";
        store.revoke(live_jti, future_exp(3600));
        // Trigger eviction pass
        store.revoke("another-jti", future_exp(7200));
        assert!(store.is_revoked(live_jti));
    }

    #[test]
    fn multiple_distinct_jtis_tracked_independently() {
        let store = InMemoryRevocationStore::new();
        store.revoke("jti-a", future_exp(3600));
        store.revoke("jti-b", future_exp(7200));
        assert!(store.is_revoked("jti-a"));
        assert!(store.is_revoked("jti-b"));
        assert!(!store.is_revoked("jti-c"));
    }
}
