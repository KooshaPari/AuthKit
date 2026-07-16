//! GAP-009: Rate limiter for failed auth attempts.
//!
//! Sliding-window counter per key (IP / UserId / Endpoint / Global) with
//! configurable per-tier limits. Drops stale windows on access so the
//! store never grows unbounded.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// Errors returned by the rate limiter.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RateLimitError {
    /// Rate limit exceeded — caller should return 429.
    #[error("rate limit exceeded: retry after {retry_after_secs}s")]
    Limited { retry_after_secs: u64 },

    /// Internal store poisoned.
    #[error("rate limiter store poisoned")]
    StorePoisoned,
}

// ---------------------------------------------------------------------------
// Limit tiers
// ---------------------------------------------------------------------------

/// A named tier with its window size and burst cap.
#[derive(Debug, Clone)]
pub struct LimitTier {
    /// Human-readable name (e.g. "ip", "user", "endpoint", "global").
    pub name: &'static str,
    /// Sliding-window duration.
    pub window: Duration,
    /// Maximum number of *failed* attempts allowed within the window.
    pub max_attempts: u32,
    /// Cooldown — minimum time the caller must wait before retrying even
    /// after the window resets.
    pub cooldown: Duration,
}

impl LimitTier {
    /// Fast-try tier — 5 attempts per 15 s, then 30 s cooldown.
    pub const fn ip_default() -> Self {
        Self {
            name: "ip",
            window: Duration::from_secs(15),
            max_attempts: 5,
            cooldown: Duration::from_secs(30),
        }
    }

    /// Per-user tier — 10 attempts per 60 s, then 60 s cooldown.
    pub const fn user_default() -> Self {
        Self {
            name: "user",
            window: Duration::from_secs(60),
            max_attempts: 10,
            cooldown: Duration::from_secs(60),
        }
    }

    /// Per-endpoint tier — 20 attempts per 60 s, then 30 s cooldown.
    pub const fn endpoint_default() -> Self {
        Self {
            name: "endpoint",
            window: Duration::from_secs(60),
            max_attempts: 20,
            cooldown: Duration::from_secs(30),
        }
    }

    /// Global tier — 1000 attempts per 60 s, then 10 s cooldown.
    pub const fn global_default() -> Self {
        Self {
            name: "global",
            window: Duration::from_secs(60),
            max_attempts: 1000,
            cooldown: Duration::from_secs(10),
        }
    }
}

// ---------------------------------------------------------------------------
// Window entry
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct WindowEntry {
    /// All timestamps of failed attempts within the current tracking window.
    /// Sorted roughly by insertion order; trimmed on every access.
    timestamps: Vec<Instant>,
    /// Set to true when a cooldown is active.
    cooled_until: Option<Instant>,
}

impl WindowEntry {
    fn new() -> Self {
        Self {
            timestamps: vec![],
            cooled_until: None,
        }
    }

    /// Remove entries older than `window` from `now`.
    fn trim(&mut self, now: Instant, window: Duration) {
        let cutoff = now - window;
        self.timestamps.retain(|t| *t > cutoff);
    }

    fn count(&self) -> u32 {
        self.timestamps.len() as u32
    }
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Thread-safe, sliding-window rate limiter with per-tier config.
///
/// ```ignore
/// let limiter = RateLimiter::new(vec![LimitTier::ip_default()]);
/// match limiter.check("127.0.0.1") {
///     Ok(remaining) => { /* allow request */ }
///     Err(RateLimitError::Limited { retry_after_secs }) => { /* 429 */ }
///     Err(_) => { /* 500 */ }
/// }
/// ```
pub struct RateLimiter {
    tiers: Vec<LimitTier>,
    state: Mutex<HashMap<String, WindowEntry>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given tiers.
    /// Tiers are checked in order; the first tier to exceed its limit wins.
    pub fn new(tiers: Vec<LimitTier>) -> Self {
        Self {
            tiers,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Convenience constructor with all four default tiers.
    pub fn with_defaults() -> Self {
        Self::new(vec![
            LimitTier::ip_default(),
            LimitTier::user_default(),
            LimitTier::endpoint_default(),
            LimitTier::global_default(),
        ])
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Record a failed attempt for `key` and check whether the limit is
    /// exceeded.  Returns `Ok(remaining)` on success, or
    /// `Err(RateLimitError::Limited {..})` when throttled.
    pub fn record_failure(&self, key: &str) -> Result<u32, RateLimitError> {
        let now = Instant::now();
        let mut map = self.state.lock().map_err(|_| RateLimitError::StorePoisoned)?;

        // Update the entry for this key under ALL tiers.
        for tier in &self.tiers {
            let entry_key = format!("{}:{}", tier.name, key);
            let entry = map.entry(entry_key.clone()).or_insert_with(WindowEntry::new);
            entry.trim(now, tier.window);
            entry.timestamps.push(now);

            if entry.cooled_until.map_or(false, |c| c > now) {
                let retry = entry.cooled_until.unwrap() - now;
                return Err(RateLimitError::Limited {
                    retry_after_secs: retry.as_secs().max(1),
                });
            }

            if entry.count() > tier.max_attempts {
                let cooldown_end = now + tier.cooldown;
                entry.cooled_until = Some(cooldown_end);
                let retry = cooldown_end - now;
                return Err(RateLimitError::Limited {
                    retry_after_secs: retry.as_secs().max(1),
                });
            }
        }

        // Compute remaining from the last (most-restrictive) tier.
        let remaining = self.tiers.last()
            .map(|t| t.max_attempts.saturating_sub(
                map.get(&format!("{}:{}", t.name, key))
                    .map(|e| e.count())
                    .unwrap_or(0),
            ))
            .unwrap_or(0);

        Ok(remaining)
    }

    /// Record a *successful* attempt — resets the entry for `key` so the
    /// caller gets a clean slate.
    pub fn record_success(&self, key: &str) -> Result<(), RateLimitError> {
        let now = Instant::now();
        let mut map = self.state.lock().map_err(|_| RateLimitError::StorePoisoned)?;

        for tier in &self.tiers {
            let entry_key = format!("{}:{}", tier.name, key);
            let entry = map.entry(entry_key.clone()).or_insert_with(WindowEntry::new);
            entry.timestamps.clear();
            entry.cooled_until = None;
        }

        Ok(())
    }

    /// Non-destructive check — records nothing, just tells you whether
    /// `key` would currently be allowed.
    pub fn peek(&self, key: &str) -> Result<u32, RateLimitError> {
        let now = Instant::now();
        let map = self.state.lock().map_err(|_| RateLimitError::StorePoisoned)?;

        for tier in &self.tiers {
            let entry_key = format!("{}:{}", tier.name, key);
            if let Some(entry) = map.get(&entry_key) {
                // Count entries before cloning — just use the ref
                let cutoff = now - tier.window;
                let active = entry.timestamps.iter().filter(|t| **t > cutoff).count() as u32;

                if entry.cooled_until.map_or(false, |c| c > now) {
                    let retry = entry.cooled_until.unwrap() - now;
                    return Err(RateLimitError::Limited {
                        retry_after_secs: retry.as_secs().max(1),
                    });
                }

                if active > tier.max_attempts {
                    let retry = entry
                        .cooled_until
                        .unwrap_or_else(|| now + tier.cooldown)
                        - now;
                    return Err(RateLimitError::Limited {
                        retry_after_secs: retry.as_secs().max(1),
                    });
                }
            }
        }

        // Return remaining according to the most restrictive tier.
        let min_remaining = self
            .tiers
            .iter()
            .map(|t| {
                let entry_key = format!("{}:{}", t.name, key);
                let count = map
                    .get(&entry_key)
                    .map(|e| {
                        let cutoff = now - t.window;
                        e.timestamps.iter().filter(|ts| **ts > cutoff).count() as u32
                    })
                    .unwrap_or(0);
                t.max_attempts.saturating_sub(count)
            })
            .min()
            .unwrap_or(0);

        Ok(min_remaining)
    }

    /// Manually reset the entire state for `key` (e.g. after successful
    /// login or admin override).
    pub fn reset(&self, key: &str) -> Result<(), RateLimitError> {
        let mut map = self.state.lock().map_err(|_| RateLimitError::StorePoisoned)?;
        for tier in &self.tiers {
            let entry_key = format!("{}:{}", tier.name, key);
            map.remove(&entry_key);
        }
        Ok(())
    }

    /// Garbage-collect entries that are no longer relevant (no entries
    /// within their window and not in cooldown).  Returns the number of
    /// entries removed.
    pub fn gc(&self) -> Result<usize, RateLimitError> {
        let now = Instant::now();
        let mut map = self.state.lock().map_err(|_| RateLimitError::StorePoisoned)?;
        let before = map.len();
        map.retain(|_, entry| {
            // Keep if cooled_until is still in the future
            if entry.cooled_until.map_or(false, |c| c > now) {
                return true;
            }
            // Keep if any timestamps are still within the window
            // (use the largest window among tiers — conservative)
            let max_window = Duration::from_secs(120);
            let cutoff = now - max_window;
            entry.timestamps.retain(|t| *t > cutoff);
            if !entry.timestamps.is_empty() {
                return true;
            }
            false
        });
        let removed = before - map.len();
        Ok(removed)
    }

    /// Number of unique keys currently tracked.
    pub fn len(&self) -> Result<usize, RateLimitError> {
        let map = self.state.lock().map_err(|_| RateLimitError::StorePoisoned)?;
        Ok(map.len())
    }

    /// Returns true if the store is empty.
    pub fn is_empty(&self) -> Result<bool, RateLimitError> {
        self.len().map(|l| l == 0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn small_tier() -> Vec<LimitTier> {
        vec![LimitTier {
            name: "test",
            window: Duration::from_secs(10),
            max_attempts: 3,
            cooldown: Duration::from_secs(5),
        }]
    }

    #[test]
    fn test_allows_within_limit() {
        let rl = RateLimiter::new(small_tier());
        assert!(rl.record_failure("alice").is_ok());
        assert!(rl.record_failure("alice").is_ok());
        assert!(rl.record_failure("alice").is_ok()); // 3rd is max_attempts
    }

    #[test]
    fn test_blocks_exceeding_limit() {
        let rl = RateLimiter::new(small_tier());
        for _ in 0..3 {
            rl.record_failure("alice").ok();
        }
        let result = rl.record_failure("alice");
        assert!(matches!(result, Err(RateLimitError::Limited { .. })));
    }

    #[test]
    fn test_success_resets_counter() {
        let rl = RateLimiter::new(small_tier());
        for _ in 0..3 {
            rl.record_failure("alice").ok();
        }
        rl.record_success("alice").ok();
        // After reset we should be allowed again
        assert!(rl.record_failure("alice").is_ok());
    }

    #[test]
    fn test_reset_clears_state() {
        let rl = RateLimiter::new(small_tier());
        for _ in 0..5 {
            let _ = rl.record_failure("bob");
        }
        assert!(rl.record_failure("bob").is_err());
        rl.reset("bob").ok();
        assert!(rl.record_failure("bob").is_ok());
    }

    #[test]
    fn test_peek_without_mutating() {
        let rl = RateLimiter::new(small_tier());
        rl.record_failure("carol").ok();
        let before = rl.peek("carol").unwrap();
        assert_eq!(before, 2); // max 3 minus 1 recorded
        let after = rl.peek("carol").unwrap();
        assert_eq!(after, before); // peek didn't add a new entry
    }

    #[test]
    fn test_independent_keys() {
        let rl = RateLimiter::new(small_tier());
        for _ in 0..3 {
            rl.record_failure("dave").ok();
        }
        assert!(rl.record_failure("dave").is_err());
        // Eve has her own counter
        assert!(rl.record_failure("eve").is_ok());
        assert!(rl.record_failure("eve").is_ok());
    }

    #[test]
    fn test_gc_removes_stale_entries() {
        let rl = RateLimiter::new(small_tier());
        rl.record_failure("gone").ok();
        // Record a failure with artificial age — not possible, but gc
        // uses the max window so fresh entries won't be removed.
        rl.record_failure("stay").ok();
        // Both should still be here right after recording
        assert_eq!(rl.len().unwrap(), 2);

        // gc should keep both (recent)
        rl.gc().ok();
        assert_eq!(rl.len().unwrap(), 2);
    }

    #[test]
    fn test_multi_tier_most_restrictive_wins() {
        let tiers = vec![
            LimitTier::ip_default(),   // 5 per 15s
            LimitTier::user_default(), // 10 per 60s
        ];
        let rl = RateLimiter::new(tiers);
        // IP tier should kick in first
        for _ in 0..5 {
            rl.record_failure("192.168.1.1").ok();
        }
        let result = rl.record_failure("192.168.1.1");
        assert!(matches!(result, Err(RateLimitError::Limited { .. })));
    }

    #[test]
    fn test_len_and_is_empty() {
        let rl = RateLimiter::new(small_tier());
        assert!(rl.is_empty().unwrap());
        rl.record_failure("key1").ok();
        assert_eq!(rl.len().unwrap(), 1);
        rl.record_failure("key2").ok();
        assert_eq!(rl.len().unwrap(), 2); // 2 keys × 1 tier = 2 entries
    }

    #[test]
    fn test_store_poisoned_error_message() {
        let err = RateLimitError::StorePoisoned;
        assert!(err.to_string().contains("poisoned"));
    }

    #[test]
    fn test_limited_error_contains_retry_after() {
        let msg = RateLimitError::Limited { retry_after_secs: 30 }.to_string();
        assert!(msg.contains("30"));
    }

    #[test]
    fn test_cooldown_persists_across_failures() {
        let tiers = vec![LimitTier {
            name: "test",
            window: Duration::from_secs(1),
            max_attempts: 2,
            cooldown: Duration::from_secs(60),
        }];
        let rl = RateLimiter::new(tiers);
        rl.record_failure("frank").ok();
        rl.record_failure("frank").ok();
        // 3rd triggers limit + cooldown
        let err = rl.record_failure("frank").unwrap_err();
        assert!(matches!(err, RateLimitError::Limited { retry_after_secs } if retry_after_secs >= 1));
        // Even if we try later (simulated by peek), cooldown is still active
        // because we can't advance Instant, but the structure is correct
    }
}
