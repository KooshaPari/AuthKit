//! Port definitions - interfaces for external dependencies.

use super::{Session, SessionId, User, UserId};
use async_trait::async_trait;

/// Port for user storage.
#[async_trait]
pub trait UserStorage: Send + Sync {
    /// Create a user.
    async fn create(&self, user: &User) -> Result<(), String>;

    /// Get a user by ID.
    async fn get_by_id(&self, id: &UserId) -> Result<Option<User>, String>;

    /// Get a user by email.
    async fn get_by_email(&self, email: &str) -> Result<Option<User>, String>;

    /// Update a user.
    async fn update(&self, user: &User) -> Result<(), String>;

    /// Delete a user.
    async fn delete(&self, id: &UserId) -> Result<(), String>;

    /// List users.
    async fn list(&self) -> Result<Vec<User>, String>;
}

/// Port for session storage.
#[async_trait]
pub trait SessionStorage: Send + Sync {
    /// Create a session.
    async fn create(&self, session: &Session) -> Result<(), String>;

    /// Get a session by ID.
    async fn get_by_id(&self, id: &SessionId) -> Result<Option<Session>, String>;

    /// Update a session.
    async fn update(&self, session: &Session) -> Result<(), String>;

    /// Delete a session.
    async fn delete(&self, id: &SessionId) -> Result<(), String>;

    /// Delete all sessions for a user.
    async fn delete_by_user(&self, user_id: &str) -> Result<(), String>;

    /// Delete all expired sessions.
    async fn delete_expired(&self) -> Result<usize, String>;
}

/// Port for password hashing.
pub trait PasswordHasher: Send + Sync {
    /// Hash a password.
    fn hash(&self, password: &str) -> Result<String, String>;

    /// Verify a password against a hash.
    fn verify(&self, password: &str, hash: &str) -> bool;
}
