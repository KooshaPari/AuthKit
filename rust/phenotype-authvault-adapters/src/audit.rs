//! Audit-sink adapters.
//!
//! Two built-in implementations of [`AuditSink`]:
//!
//! - [`InMemoryAuditSink`] — accumulates events in a `Vec` behind a `Mutex`;
//!   intended for **testing** (spy pattern) and in-process inspection.
//! - [`TracingAuditSink`] — emits each event as a structured `tracing::info!`
//!   span; suitable for production use with any `tracing-subscriber` backend.

use std::sync::Mutex;

use phenotype_authvault_domain::ports::{AuditEvent, AuditSink};

// ── In-memory spy sink ────────────────────────────────────────────────────────

/// An [`AuditSink`] that stores all events in memory.
///
/// Designed for unit-test use (spy / fake pattern).  Call [`events`] to
/// inspect what was recorded.
///
/// # Thread safety
/// All methods are `Send + Sync` via an internal `Mutex<Vec<AuditEvent>>`.
#[derive(Default)]
pub struct InMemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl InMemoryAuditSink {
    /// Create an empty in-memory sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a clone of all recorded events in insertion order.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().expect("mutex poisoned").clone()
    }

    /// Drain all events and return them.
    pub fn drain(&self) -> Vec<AuditEvent> {
        let mut guard = self.events.lock().expect("mutex poisoned");
        std::mem::take(&mut *guard)
    }
}

impl AuditSink for InMemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        self.events.lock().expect("mutex poisoned").push(event);
    }
}

// ── Tracing-backed sink ───────────────────────────────────────────────────────

/// An [`AuditSink`] that emits each event as a structured `tracing` log record
/// at the `INFO` level.
///
/// Fields emitted:
/// - `audit.timestamp` — RFC 3339 timestamp
/// - `audit.actor`     — optional caller identity
/// - `audit.subject`   — resource identifier (jti, vault key name, …)
/// - `audit.action`    — action variant name
/// - `audit.outcome`   — `"success"` or `"failure"`
/// - `audit.reason`    — optional failure reason (never contains secret material)
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: AuditEvent) {
        let action = format!("{:?}", event.action);
        let outcome = format!("{:?}", event.outcome).to_lowercase();
        let actor = event.actor.as_deref().unwrap_or("-");
        let reason = event.reason.as_deref().unwrap_or("");
        tracing::info!(
            audit.timestamp = %event.timestamp.to_rfc3339(),
            audit.actor     = %actor,
            audit.subject   = %event.subject,
            audit.action    = %action,
            audit.outcome   = %outcome,
            audit.reason    = %reason,
            "audit event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phenotype_authvault_domain::ports::{AuditAction, AuditOutcome};

    // ── InMemoryAuditSink ─────────────────────────────────────────────────────

    #[test]
    fn in_memory_sink_records_events() {
        let sink = InMemoryAuditSink::new();
        let ev = AuditEvent::success(Some("user-1".into()), "jti-abc", AuditAction::TokenIssued);
        sink.record(ev);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::TokenIssued);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(events[0].subject, "jti-abc");
        assert_eq!(events[0].actor.as_deref(), Some("user-1"));
        assert!(events[0].reason.is_none());
    }

    #[test]
    fn in_memory_sink_records_failure_with_reason() {
        let sink = InMemoryAuditSink::new();
        let ev = AuditEvent::failure(None, "sub-xyz", AuditAction::TokenRejected, "token expired");
        sink.record(ev);

        let events = sink.events();
        assert_eq!(events[0].outcome, AuditOutcome::Failure);
        assert_eq!(events[0].reason.as_deref(), Some("token expired"));
        assert!(events[0].actor.is_none());
    }

    #[test]
    fn in_memory_sink_drain_clears_events() {
        let sink = InMemoryAuditSink::new();
        sink.record(AuditEvent::success(None, "s", AuditAction::VaultRead));
        sink.record(AuditEvent::success(None, "s", AuditAction::VaultWrite));

        let drained = sink.drain();
        assert_eq!(drained.len(), 2);
        assert!(sink.events().is_empty(), "drain must clear the buffer");
    }

    #[test]
    fn in_memory_sink_multiple_events_in_order() {
        let sink = InMemoryAuditSink::new();
        let actions =
            [AuditAction::TokenIssued, AuditAction::TokenValidated, AuditAction::TokenRevoked];
        for action in actions.iter() {
            sink.record(AuditEvent::success(None, "s", action.clone()));
        }
        let events = sink.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].action, AuditAction::TokenIssued);
        assert_eq!(events[1].action, AuditAction::TokenValidated);
        assert_eq!(events[2].action, AuditAction::TokenRevoked);
    }

    // ── TracingAuditSink ──────────────────────────────────────────────────────

    #[test]
    fn tracing_sink_does_not_panic() {
        // The tracing sink just emits spans; verify it doesn't panic or error.
        let sink = TracingAuditSink;
        sink.record(AuditEvent::success(Some("svc".into()), "vault-key", AuditAction::VaultWrite));
        sink.record(AuditEvent::failure(
            None,
            "jti-fail",
            AuditAction::TokenRejected,
            "bad signature",
        ));
    }
}
