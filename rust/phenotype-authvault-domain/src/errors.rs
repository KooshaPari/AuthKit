//! Domain errors.

/// Authentication errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Token expired")]
    Expired,

    #[error("Bad token signature")]
    BadSignature,

    #[error("Token audience mismatch")]
    WrongAudience,

    #[error("Malformed token")]
    Malformed,

    #[error("Token has been revoked")]
    Revoked,

    #[error("Refresh token reuse detected — token family revoked")]
    CompromisedTokenFamily,

    #[error("Invalid refresh token")]
    InvalidRefreshToken,

    #[error("Token generation failed: {0}")]
    TokenGeneration(String),

    #[error("Token verification failed: {0}")]
    TokenVerification(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Session revoked")]
    SessionRevoked,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Access denied")]
    AccessDenied,

    #[error("Account locked")]
    AccountLocked,

    #[error("Account disabled")]
    AccountDisabled,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Password too weak: {0}")]
    PasswordTooWeak(String),

    #[error("Password hash error: {0}")]
    PasswordHashError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl serde::Serialize for AuthError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
