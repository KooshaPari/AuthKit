//! Authentication application service.

use crate::domain::{
    errors::AuthError, Authenticator, Claims, PasswordHasher, PolicyEngine, Session, SessionId,
    SessionStorage, User, UserId, UserStorage,
};
use std::sync::Arc;

/// Authentication application service.
pub struct AuthService {
    authenticator: Authenticator,
    user_storage: Arc<dyn UserStorage>,
    session_storage: Arc<dyn SessionStorage>,
    hasher: Arc<dyn PasswordHasher>,
    policy_engine: PolicyEngine,
}

impl AuthService {
    /// Create a new auth service.
    pub fn new(
        secret: impl Into<String>,
        user_storage: Arc<dyn UserStorage>,
        session_storage: Arc<dyn SessionStorage>,
        hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            authenticator: Authenticator::new(secret),
            user_storage,
            session_storage,
            hasher,
            policy_engine: PolicyEngine::new(),
        }
    }

    /// Register a new user.
    pub async fn register(
        &self,
        email: impl Into<String>,
        password: &str,
    ) -> Result<User, AuthError> {
        let email = email.into();

        // Check if user exists
        if self
            .user_storage
            .get_by_email(&email)
            .await
            .map_err(AuthError::StorageError)?
            .is_some()
        {
            return Err(AuthError::UserAlreadyExists);
        }

        // Hash password
        let password_hash = self
            .hasher
            .hash(password)
            .map_err(AuthError::PasswordHashError)?;

        // Create user
        let user = User::new(email).with_password_hash(password_hash);

        self.user_storage
            .create(&user)
            .await
            .map_err(AuthError::StorageError)?;

        Ok(user)
    }

    /// Authenticate a user with email and password.
    pub async fn login(&self, email: &str, password: &str) -> Result<(String, Session), AuthError> {
        // Get user
        let user = self
            .user_storage
            .get_by_email(email)
            .await
            .map_err(AuthError::StorageError)?
            .ok_or(AuthError::InvalidCredentials)?;

        // Check if user is active
        if !user.active {
            return Err(AuthError::AccountDisabled);
        }

        // Verify password
        if let Some(ref hash) = user.password_hash {
            if !self.hasher.verify(password, hash) {
                return Err(AuthError::InvalidCredentials);
            }
        } else {
            return Err(AuthError::InvalidCredentials);
        }

        // Generate token
        let token = self.authenticator.generate_token(&user.id, &user.roles)?;

        // Create session
        let mut session = Session::new(user.id.to_string());
        session = session.with_refresh_token(uuid::Uuid::new_v4().to_string());

        self.session_storage
            .create(&session)
            .await
            .map_err(AuthError::StorageError)?;

        Ok((token, session))
    }

    /// Verify a token and return claims.
    pub fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        self.authenticator.verify_token(token)
    }

    /// Refresh a token.
    pub fn refresh_token(&self, token: &str) -> Result<String, AuthError> {
        self.authenticator.refresh_token(token)
    }

    /// Logout (revoke session).
    pub async fn logout(&self, session_id: &SessionId) -> Result<(), AuthError> {
        let mut session = self
            .session_storage
            .get_by_id(session_id)
            .await
            .map_err(AuthError::StorageError)?
            .ok_or(AuthError::SessionNotFound)?;

        session.revoke();

        self.session_storage
            .update(&session)
            .await
            .map_err(AuthError::StorageError)?;

        self.session_storage
            .delete(session_id)
            .await
            .map_err(AuthError::StorageError)?;

        Ok(())
    }

    /// Logout all sessions for a user.
    pub async fn logout_all(&self, user_id: &str) -> Result<(), AuthError> {
        self.session_storage
            .delete_by_user(user_id)
            .await
            .map_err(AuthError::StorageError)?;

        Ok(())
    }

    /// Check authorization.
    pub fn authorize(
        &self,
        claims: &Claims,
        resource: &str,
        action: &str,
    ) -> Result<(), AuthError> {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert("user_id".to_string(), serde_json::json!(&claims.sub));
        attributes.insert("roles".to_string(), serde_json::json!(&claims.roles));

        if self.policy_engine.evaluate(resource, action, &attributes) {
            Ok(())
        } else {
            Err(AuthError::AccessDenied)
        }
    }

    /// Get a user by ID.
    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, AuthError> {
        self.user_storage
            .get_by_id(user_id)
            .await
            .map_err(AuthError::StorageError)
    }
}
