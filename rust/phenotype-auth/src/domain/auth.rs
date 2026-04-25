//! Authentication logic.

use super::errors::AuthError;
use super::{Role, UserId};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// Authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    #[default]
    Password,
    Jwt,
    ApiKey,
    OAuth2,
    Session,
}

/// JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Expiration time.
    pub exp: i64,
    /// Issued at.
    pub iat: i64,
    /// Not before.
    pub nbf: i64,
    /// JWT ID.
    pub jti: String,
    /// User roles.
    pub roles: Vec<String>,
    /// Custom claims.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

impl Claims {
    /// Create new claims.
    pub fn new(user_id: &UserId, roles: &[Role]) -> Self {
        let now = Utc::now();
        Self {
            sub: user_id.to_string(),
            iss: "authkit".to_string(),
            aud: "authkit".to_string(),
            exp: (now + Duration::hours(24)).timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            roles: roles.iter().map(|r| r.name.clone()).collect(),
            extra: std::collections::HashMap::new(),
        }
    }

    /// Create with custom expiration.
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        let now = Utc::now();
        self.exp = (now + duration).timestamp();
        self
    }

    /// Add extra claims.
    pub fn with_claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Check if the token is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Check if the token is not yet valid.
    pub fn is_not_yet_valid(&self) -> bool {
        Utc::now().timestamp() < self.nbf
    }

    /// Get the user ID.
    pub fn user_id(&self) -> UserId {
        UserId::from_string(&self.sub)
    }
}

/// Authenticator for generating and verifying tokens.
pub struct Authenticator {
    secret: String,
    issuer: String,
    audience: String,
}

impl Authenticator {
    /// Create a new authenticator.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            issuer: "authkit".to_string(),
            audience: "authkit".to_string(),
        }
    }

    /// Create with custom issuer and audience.
    pub fn with_issuer(mut self, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self.audience = audience.into();
        self
    }

    /// Generate a JWT token for a user.
    pub fn generate_token(&self, user_id: &UserId, roles: &[Role]) -> Result<String, AuthError> {
        let mut claims = Claims::new(user_id, roles);
        claims.iss = self.issuer.clone();
        claims.aud = self.audience.clone();

        let key = jsonwebtoken::EncodingKey::from_secret(self.secret.as_bytes());
        let header = jsonwebtoken::Header::default();

        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AuthError::TokenGeneration(e.to_string()))
    }

    /// Generate a token with custom expiration.
    pub fn generate_token_with_expiry(
        &self,
        user_id: &UserId,
        roles: &[Role],
        expiry: Duration,
    ) -> Result<String, AuthError> {
        let claims = Claims::new(user_id, roles).with_expiration(expiry);

        let key = jsonwebtoken::EncodingKey::from_secret(self.secret.as_bytes());
        let header = jsonwebtoken::Header::default();

        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AuthError::TokenGeneration(e.to_string()))
    }

    /// Verify and decode a JWT token.
    pub fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        let key = jsonwebtoken::DecodingKey::from_secret(self.secret.as_bytes());
        let mut validation = jsonwebtoken::Validation::default();
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = jsonwebtoken::decode::<Claims>(token, &key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidToken => AuthError::InvalidToken,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::InvalidSignature,
                _ => AuthError::TokenVerification(e.to_string()),
            }
        })?;

        Ok(token_data.claims)
    }

    /// Refresh a token (generate new with same claims).
    pub fn refresh_token(&self, token: &str) -> Result<String, AuthError> {
        let claims = self.verify_token(token)?;
        let user_id = UserId::from_string(&claims.sub);
        let roles: Vec<Role> = claims.roles.iter().map(Role::new).collect();
        self.generate_token(&user_id, &roles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_token() {
        let auth = Authenticator::new("secret");
        let user_id = UserId::new();
        let roles = vec![Role::new("admin")];

        let token = auth.generate_token(&user_id, &roles).unwrap();
        let claims = auth.verify_token(&token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.roles.contains(&"admin".to_string()));
    }

    #[test]
    fn test_expired_token() {
        let auth = Authenticator::new("secret");
        let user_id = UserId::new();
        let roles = vec![];

        // Generate token with expiration far in the past
        let token = auth.generate_token_with_expiry(&user_id, &roles, Duration::days(-30));

        // Token generation may succeed but verification should fail
        if let Ok(token) = token {
            let result = auth.verify_token(&token);
            assert!(result.is_err(), "Token should be expired");
        }
    }

    #[test]
    fn test_invalid_token() {
        let auth = Authenticator::new("secret");
        let result = auth.verify_token("invalid.token.here");
        assert!(result.is_err());
    }
}
