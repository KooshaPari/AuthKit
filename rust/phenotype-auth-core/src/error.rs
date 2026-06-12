//! Error types for phenotype-auth-core.
//!
//! All fallible operations return [`Result<T, AuthError>`]. The error
//! variants are scoped to the auth domain (no `std::io::Error` leakage)
//! so FFI bindings can map them 1:1 to language-native error types.

use thiserror::Error;

/// Canonical auth error type.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    /// A user ID could not be parsed (e.g. not a valid UUID).
    #[error("invalid user id: {0}")]
    InvalidUserId(String),

    /// A session ID could not be parsed.
    #[error("invalid session id: {0}")]
    InvalidSessionId(String),

    /// A token could not be verified (signature mismatch, malformed,
    /// expired, etc.). The message is intentionally generic so we
    /// don't leak which check failed to a caller probing for
    /// timing-side channels.
    #[error("token verification failed")]
    TokenInvalid,

    /// A token has expired and can no longer be used.
    #[error("token expired at {0}")]
    TokenExpired(String),

    /// A token has been explicitly revoked (denylist hit).
    #[error("token revoked")]
    TokenRevoked,

    /// A role is not allowed to perform a specific permission.
    #[error("role {role:?} not authorized for {permission}")]
    NotAuthorized {
        /// The role that was checked.
        role: String,
        /// The permission that was denied.
        permission: String,
    },

    /// A session has expired and can no longer be extended.
    #[error("session expired at {0}")]
    SessionExpired(String),
}

/// Convenience Result alias.
pub type Result<T> = std::result::Result<T, AuthError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_user_id_message_includes_input() {
        let e = AuthError::InvalidUserId("not-a-uuid".to_string());
        assert!(e.to_string().contains("not-a-uuid"));
    }

    #[test]
    fn token_invalid_message_is_generic() {
        // Important: the message must NOT reveal which check failed
        // (signature, expiry, format) to avoid timing-based probing.
        let e = AuthError::TokenInvalid;
        assert_eq!(e.to_string(), "token verification failed");
    }

    #[test]
    fn not_authorized_carries_role_and_permission() {
        let e = AuthError::NotAuthorized {
            role: "Viewer".to_string(),
            permission: "users:write".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("Viewer"));
        assert!(s.contains("users:write"));
    }
}
