//! In-memory [`RefreshTokenStore`] adapter with per-family rotation tracking.
//!
//! Each token family is identified by a stable UUID.  The store records the
//! *current* refresh-token JTI for the family; on rotation the old JTI must
//! match, otherwise reuse/compromise is signalled.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;

use phenotype_authvault_domain::ports::RefreshTokenStore;

/// Per-family state.
#[derive(Debug)]
struct FamilyEntry {
    /// JTI of the token that is currently valid for this family.
    current_jti: String,
    /// Unix-timestamp expiry of the current refresh token.
    exp: i64,
}

/// Thread-safe in-memory refresh-token rotation store.
///
/// Expired families are lazily evicted on each write operation so memory is
/// bounded to currently-live token families.
#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenStore {
    inner: Mutex<HashMap<String, FamilyEntry>>,
}

impl InMemoryRefreshTokenStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn evict_expired(map: &mut HashMap<String, FamilyEntry>) {
        let now = Utc::now().timestamp();
        map.retain(|_, e| e.exp > now);
    }
}

impl RefreshTokenStore for InMemoryRefreshTokenStore {
    fn insert_family(&self, family_id: &str, refresh_jti: &str, exp: i64) {
        let mut map = self.inner.lock().expect("refresh store lock poisoned");
        Self::evict_expired(&mut map);
        map.insert(family_id.to_owned(), FamilyEntry { current_jti: refresh_jti.to_owned(), exp });
    }

    fn rotate(
        &self,
        family_id: &str,
        old_jti: &str,
        new_jti: &str,
        new_exp: i64,
    ) -> Result<(), bool> {
        let mut map = self.inner.lock().expect("refresh store lock poisoned");
        match map.get(family_id) {
            Some(entry) if entry.current_jti == old_jti => {
                map.insert(
                    family_id.to_owned(),
                    FamilyEntry { current_jti: new_jti.to_owned(), exp: new_exp },
                );
                Ok(())
            }
            Some(_) => Err(true), // JTI mismatch → reuse/compromise
            None => Err(false),   // family not found or already evicted
        }
    }

    fn revoke_family(&self, family_id: &str) {
        let mut map = self.inner.lock().expect("refresh store lock poisoned");
        map.remove(family_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_exp(secs: i64) -> i64 {
        (chrono::Utc::now() + chrono::Duration::seconds(secs)).timestamp()
    }

    #[test]
    fn insert_then_rotate_succeeds_with_correct_old_jti() {
        let store = InMemoryRefreshTokenStore::new();
        store.insert_family("family-1", "jti-a", future_exp(3600));
        let result = store.rotate("family-1", "jti-a", "jti-b", future_exp(3600));
        assert!(result.is_ok());
    }

    #[test]
    fn rotate_with_wrong_old_jti_returns_compromise() {
        let store = InMemoryRefreshTokenStore::new();
        store.insert_family("family-1", "jti-a", future_exp(3600));
        // Simulate first rotation.
        store.rotate("family-1", "jti-a", "jti-b", future_exp(3600)).unwrap();
        // Replay old JTI → reuse.
        let result = store.rotate("family-1", "jti-a", "jti-c", future_exp(3600));
        assert_eq!(result, Err(true));
    }

    #[test]
    fn rotate_unknown_family_returns_not_found() {
        let store = InMemoryRefreshTokenStore::new();
        let result = store.rotate("nonexistent", "any-jti", "new-jti", future_exp(3600));
        assert_eq!(result, Err(false));
    }

    #[test]
    fn revoke_family_removes_entry() {
        let store = InMemoryRefreshTokenStore::new();
        store.insert_family("family-1", "jti-a", future_exp(3600));
        store.revoke_family("family-1");
        let result = store.rotate("family-1", "jti-a", "jti-b", future_exp(3600));
        assert_eq!(result, Err(false));
    }

    #[test]
    fn expired_families_are_evicted_on_next_insert() {
        let store = InMemoryRefreshTokenStore::new();
        // Insert already-expired family.
        store.insert_family("old-family", "jti-x", future_exp(-10));
        // Trigger eviction by inserting a fresh family.
        store.insert_family("new-family", "jti-y", future_exp(3600));
        // Old family is gone.
        let result = store.rotate("old-family", "jti-x", "jti-z", future_exp(3600));
        assert_eq!(result, Err(false));
    }

    #[test]
    fn multiple_families_tracked_independently() {
        let store = InMemoryRefreshTokenStore::new();
        store.insert_family("fam-a", "jti-1", future_exp(3600));
        store.insert_family("fam-b", "jti-2", future_exp(3600));
        assert!(store.rotate("fam-a", "jti-1", "jti-1b", future_exp(3600)).is_ok());
        assert!(store.rotate("fam-b", "jti-2", "jti-2b", future_exp(3600)).is_ok());
    }
}
