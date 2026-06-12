//! Session management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unique session identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    #[default]
    Active,
    Expired,
    Revoked,
    Refreshed,
}

/// Session entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique identifier.
    pub id: SessionId,
    /// User ID.
    pub user_id: String,
    /// Refresh token ID.
    pub refresh_token_id: Option<String>,
    /// Session state.
    pub state: SessionState,
    /// Created timestamp.
    pub created_at: DateTime<Utc>,
    /// Last activity.
    pub last_activity: DateTime<Utc>,
    /// Expires at.
    pub expires_at: DateTime<Utc>,
    /// IP address.
    pub ip_address: Option<String>,
    /// User agent.
    pub user_agent: Option<String>,
}

impl Session {
    /// Create a new session.
    pub fn new(user_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::new(),
            user_id: user_id.into(),
            refresh_token_id: None,
            state: SessionState::Active,
            created_at: now,
            last_activity: now,
            expires_at: now + chrono::Duration::hours(24),
            ip_address: None,
            user_agent: None,
        }
    }

    /// Set the refresh token ID.
    pub fn with_refresh_token(mut self, refresh_id: impl Into<String>) -> Self {
        self.refresh_token_id = Some(refresh_id.into());
        self
    }

    /// Set the IP address.
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set the user agent.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Set the expiration.
    pub fn with_expiry(mut self, duration: chrono::Duration) -> Self {
        self.expires_at = self.created_at + duration;
        self
    }

    /// Check if the session is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session is valid.
    pub fn is_valid(&self) -> bool {
        self.state == SessionState::Active && !self.is_expired()
    }

    /// Update last activity.
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Revoke the session.
    pub fn revoke(&mut self) {
        self.state = SessionState::Revoked;
    }

    /// Refresh the session, returning the old session ID for cleanup.
    pub fn refresh(&mut self) -> SessionId {
        let old_id = std::mem::take(&mut self.id);
        self.created_at = Utc::now();
        self.last_activity = Utc::now();
        self.expires_at = Utc::now() + chrono::Duration::hours(24);
        self.state = SessionState::Active;
        old_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new("user-123");
        assert_eq!(session.user_id, "user-123");
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_expiry() {
        let mut session = Session::new("user-123");
        session.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(session.is_expired());
        assert!(!session.is_valid());
    }

    #[test]
    fn test_session_refresh() {
        let mut session = Session::new("user-123");
        let old_id = session.id.clone();

        let returned_old_id = session.refresh();
        assert_eq!(returned_old_id, old_id);
        assert_ne!(session.id, old_id);
        assert!(session.is_valid());
    }
}
