//! Session management: [`Session`] and [`SessionId`].
//!
//! A `Session` is a time-bounded active authentication state. It
//! carries a `SessionId` (`UUIDv4`), the `UserId` it belongs to, an
//! issued-at timestamp, and an absolute expiry timestamp. The
//! session can be `extend`ed (rolling forward) but only if it has
//! not yet `expired`.
//!
//! Sessions are intentionally minimal: no storage, no I/O. The
//! `SessionStore` port trait is defined separately (in
//! `phenotype-port-interfaces`) so consumers can plug in Redis,
//! Postgres, or any other backend.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::error::{AuthError, Result};
use crate::user::UserId;

/// UUIDv4-backed session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Generates a new random UUIDv4-backed session ID.
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parses a `SessionId` from its canonical string form.
    pub fn parse(s: &str) -> Result<Self> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| AuthError::InvalidSessionId(s.to_string()))
    }

    /// Returns the inner `Uuid`.
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for SessionId {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Time-bounded active authentication state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    id: SessionId,
    user_id: UserId,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl Session {
    /// Default session lifetime: 24 hours.
    pub const DEFAULT_TTL: Duration = Duration::hours(24);

    /// Constructs a new session that starts at `issued_at` and expires
    /// at `issued_at + ttl`. The TTL must be positive.
    #[instrument(skip_all, fields(session.id = tracing::field::Empty, session.user_id = %user_id))]
    pub fn new(user_id: UserId, issued_at: DateTime<Utc>, ttl: Duration) -> Self {
        let id = SessionId::new_v4();
        tracing::Span::current().record("session.id", tracing::field::display(&id));
        Self {
            id,
            user_id,
            issued_at,
            expires_at: issued_at + ttl,
        }
    }

    /// Constructs a session that starts now and expires after the
    /// default TTL (24 hours).
    pub fn new_default(user_id: UserId) -> Self {
        Self::new(user_id, Utc::now(), Self::DEFAULT_TTL)
    }

    /// Returns the session's `UUIDv4` ID.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Returns the user this session belongs to.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// Returns the issued-at timestamp.
    #[must_use]
    pub const fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    /// Returns the absolute expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Returns true if the session has expired relative to `now`.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }

    /// Returns true if the session has expired relative to `Utc::now()`.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    /// Extends the session by `additional` time. Returns
    /// `SessionExpired` if the session is already expired (we don't
    /// extend a dead session; the user must re-authenticate).
    #[instrument(skip(self, additional), fields(session.id = %self.id, additional_secs = additional.num_seconds()))]
    pub fn extend(&mut self, additional: Duration, now: DateTime<Utc>) -> Result<()> {
        if self.is_expired_at(now) {
            return Err(AuthError::SessionExpired(self.expires_at.to_rfc3339()));
        }
        self.expires_at += additional;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_not_expired() {
        let s = Session::new_default(UserId::new_v4());
        assert!(!s.is_expired());
    }

    #[test]
    fn session_with_zero_ttl_is_already_expired() {
        let now = Utc::now();
        let s = Session::new(UserId::new_v4(), now, Duration::seconds(0));
        assert!(s.is_expired_at(now));
    }

    #[test]
    fn extend_rolls_expiry_forward() {
        let now = Utc::now();
        let mut s = Session::new(UserId::new_v4(), now, Duration::hours(1));
        let original_expiry = s.expires_at();
        s.extend(Duration::hours(1), now).unwrap();
        assert!(s.expires_at() > original_expiry);
    }

    #[test]
    fn extend_on_expired_session_returns_error() {
        let now = Utc::now();
        let mut s = Session::new(UserId::new_v4(), now, Duration::seconds(0));
        let err = s.extend(Duration::hours(1), now).unwrap_err();
        assert!(matches!(err, AuthError::SessionExpired(_)));
    }

    #[test]
    fn session_id_round_trips() {
        let id = SessionId::new_v4();
        let s = id.to_string();
        let back = SessionId::parse(&s).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn session_id_parse_rejects_garbage() {
        let err = SessionId::parse("nope").unwrap_err();
        assert!(matches!(err, AuthError::InvalidSessionId(_)));
    }
}
