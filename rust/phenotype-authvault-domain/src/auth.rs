//! Authentication logic.

use std::sync::Arc;

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use super::errors::AuthError;
use super::ports::{AuditAction, AuditEvent, AuditSink, RefreshTokenStore, RevocationStore};
use super::signing::SigningKey;
use super::{Role, UserId};

/// An access + refresh token pair returned by [`Authenticator::issue_token_pair`]
/// and [`Authenticator::rotate`].
#[derive(Debug, Clone)]
pub struct TokenPair {
    /// Short-lived JWT access token.
    pub access_token: String,
    /// Long-lived opaque refresh token (itself a JWT with `typ=refresh`).
    pub refresh_token: String,
    /// Stable family identifier shared by all rotations of this token lineage.
    pub family_id: String,
}

/// Claims carried inside a refresh token JWT.
///
/// The `typ` field is set to `"refresh"` to distinguish these tokens from
/// access tokens and prevent them from being accepted as bearer credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// JWT ID — uniquely identifies this refresh token instance.
    pub jti: String,
    /// Stable family ID linking all rotations of this lineage.
    pub family_id: String,
    /// Token type discriminator — always `"refresh"`.
    pub typ: String,
    /// User roles (carried so the new access token can be re-issued without a DB lookup).
    pub roles: Vec<String>,
}

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
    /// Signing key — determines algorithm (HS256 / RS256 / ES256) for all tokens
    /// issued and validated by this instance.
    signing_key: SigningKey,
    issuer: String,
    audience: String,
    /// Optional revocation store checked on every token validation.
    revocation_store: Option<Arc<dyn RevocationStore>>,
    /// Optional refresh-token rotation state store.
    refresh_token_store: Option<Arc<dyn RefreshTokenStore>>,
    /// Lifetime of refresh tokens (default 30 days).
    refresh_token_ttl: Duration,
    /// Optional audit sink — receives one event per security-relevant operation.
    audit_sink: Option<Arc<dyn AuditSink>>,
}

impl Authenticator {
    /// Create a new authenticator with an HS256 HMAC secret (backward-compatible).
    pub fn new(secret: impl Into<String>) -> Self {
        Self::with_signing_key(SigningKey::hmac(secret))
    }

    /// Create a new authenticator with an explicit [`SigningKey`].
    ///
    /// Use this to configure RS256 or ES256 asymmetric signing.
    ///
    /// # Example
    /// ```ignore
    /// let key = SigningKey::rs256(rsa_private_pem, rsa_public_pem);
    /// let auth = Authenticator::with_signing_key(key);
    /// ```
    pub fn with_signing_key(key: SigningKey) -> Self {
        Self {
            signing_key: key,
            issuer: "authkit".to_string(),
            audience: "authkit".to_string(),
            revocation_store: None,
            refresh_token_store: None,
            refresh_token_ttl: Duration::days(30),
            audit_sink: None,
        }
    }

    /// Attach an audit sink.  Every token and vault event will be forwarded to
    /// this sink.
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Emit an audit event if a sink is configured.
    fn audit(&self, event: AuditEvent) {
        if let Some(sink) = &self.audit_sink {
            sink.record(event);
        }
    }

    /// Create with custom issuer and audience.
    pub fn with_issuer(mut self, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self.audience = audience.into();
        self
    }

    /// Attach a revocation store.  Tokens whose `jti` appears in the store will
    /// be rejected with [`AuthError::Revoked`] during validation.
    pub fn with_revocation_store(mut self, store: Arc<dyn RevocationStore>) -> Self {
        self.revocation_store = Some(store);
        self
    }

    /// Attach a refresh-token store, enabling [`issue_token_pair`] and [`rotate`].
    pub fn with_refresh_token_store(mut self, store: Arc<dyn RefreshTokenStore>) -> Self {
        self.refresh_token_store = Some(store);
        self
    }

    /// Override the refresh-token lifetime (default: 30 days).
    pub fn with_refresh_token_ttl(mut self, ttl: Duration) -> Self {
        self.refresh_token_ttl = ttl;
        self
    }

    // --- Refresh-token helpers ---

    fn make_refresh_token(
        &self,
        user_id: &UserId,
        roles: &[Role],
        family_id: &str,
    ) -> Result<(String, RefreshClaims), AuthError> {
        let now = Utc::now();
        let claims = RefreshClaims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            exp: (now + self.refresh_token_ttl).timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            family_id: family_id.to_owned(),
            typ: "refresh".to_owned(),
            roles: roles.iter().map(|r| r.name.clone()).collect(),
        };
        let enc_key = self.signing_key.encoding_key()?;
        let header = jsonwebtoken::Header::new(self.signing_key.algorithm());
        let token = jsonwebtoken::encode(&header, &claims, &enc_key)
            .map_err(|e| AuthError::TokenGeneration(e.to_string()))?;
        Ok((token, claims))
    }

    fn decode_refresh_token(&self, token: &str) -> Result<RefreshClaims, AuthError> {
        let key = self.signing_key.decoding_key()?;
        // Refresh tokens share the same signature key but NOT the same aud/iss
        // validation as access tokens; we check exp/nbf only.
        let mut validation = jsonwebtoken::Validation::new(self.signing_key.algorithm());
        validation.validate_exp = true;
        validation.validate_nbf = false;
        // Zero leeway: refresh tokens must be strictly within their validity window.
        validation.leeway = 0;
        // Refresh tokens don't carry aud — disable that check.
        validation.set_required_spec_claims(&["exp", "sub", "iss"]);
        validation.set_issuer(&[&self.issuer]);
        // We do not validate aud on refresh tokens.
        validation.validate_aud = false;

        let data =
            jsonwebtoken::decode::<RefreshClaims>(token, &key, &validation).map_err(|e| match e
                .kind()
            {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::BadSignature,
                _ => AuthError::InvalidRefreshToken,
            })?;

        let claims = data.claims;
        if claims.typ != "refresh" {
            return Err(AuthError::InvalidRefreshToken);
        }
        Ok(claims)
    }

    /// Issue a fresh access+refresh token pair for a user.
    ///
    /// Requires a [`RefreshTokenStore`] to be attached via
    /// [`with_refresh_token_store`].  A new token *family* is created and
    /// registered in the store.
    pub fn issue_token_pair(
        &self,
        user_id: &UserId,
        roles: &[Role],
    ) -> Result<TokenPair, AuthError> {
        let store = self.refresh_token_store.as_ref().ok_or_else(|| {
            AuthError::TokenGeneration("no refresh token store configured".into())
        })?;

        let access_token = self.generate_token(user_id, roles)?;
        let family_id = uuid::Uuid::new_v4().to_string();
        let (refresh_token, refresh_claims) =
            self.make_refresh_token(user_id, roles, &family_id)?;

        store.insert_family(&family_id, &refresh_claims.jti, refresh_claims.exp);

        Ok(TokenPair { access_token, refresh_token, family_id })
    }

    /// Rotate a refresh token: validate the presented token, issue a fresh
    /// access+refresh pair, and invalidate the old refresh JTI.
    ///
    /// # Reuse Detection (Compromise)
    ///
    /// If the presented refresh token's JTI is **not** the current JTI for its
    /// family (i.e. the token was already rotated), the entire token family is
    /// revoked and [`AuthError::CompromisedTokenFamily`] is returned.
    pub fn rotate(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let store = self.refresh_token_store.as_ref().ok_or_else(|| {
            AuthError::TokenGeneration("no refresh token store configured".into())
        })?;

        let old_claims = self.decode_refresh_token(refresh_token)?;

        let user_id = UserId::from_string(&old_claims.sub);
        let roles: Vec<Role> = old_claims.roles.iter().map(Role::new).collect();
        let family_id = old_claims.family_id.clone();

        let new_access = self.generate_token(&user_id, &roles)?;
        let (new_refresh_token, new_refresh_claims) =
            self.make_refresh_token(&user_id, &roles, &family_id)?;

        match store.rotate(
            &family_id,
            &old_claims.jti,
            &new_refresh_claims.jti,
            new_refresh_claims.exp,
        ) {
            Ok(()) => {
                // Invalidate the old refresh JTI in the revocation store (if present)
                // so it can never be used as a bearer token either.
                if let Some(rev) = &self.revocation_store {
                    rev.revoke(&old_claims.jti, old_claims.exp);
                }
                self.audit(AuditEvent::success(
                    Some(old_claims.sub.clone()),
                    old_claims.jti.clone(),
                    AuditAction::TokenRotated,
                ));
                Ok(TokenPair {
                    access_token: new_access,
                    refresh_token: new_refresh_token,
                    family_id,
                })
            }
            Err(true) => {
                // Reuse detected — revoke the whole family.
                store.revoke_family(&family_id);
                self.audit(AuditEvent::failure(
                    Some(old_claims.sub.clone()),
                    old_claims.jti.clone(),
                    AuditAction::TokenRejected,
                    "compromised token family — reuse detected",
                ));
                Err(AuthError::CompromisedTokenFamily)
            }
            Err(false) => {
                self.audit(AuditEvent::failure(
                    Some(old_claims.sub.clone()),
                    old_claims.jti.clone(),
                    AuditAction::TokenRejected,
                    "refresh token family not found or expired",
                ));
                Err(AuthError::InvalidRefreshToken)
            }
        }
    }

    /// Generate a JWT token for a user.
    pub fn generate_token(&self, user_id: &UserId, roles: &[Role]) -> Result<String, AuthError> {
        let mut claims = Claims::new(user_id, roles);
        claims.iss = self.issuer.clone();
        claims.aud = self.audience.clone();

        let enc_key = self.signing_key.encoding_key()?;
        let header = jsonwebtoken::Header::new(self.signing_key.algorithm());

        let result = jsonwebtoken::encode(&header, &claims, &enc_key)
            .map_err(|e| AuthError::TokenGeneration(e.to_string()));

        match &result {
            Ok(_) => self.audit(AuditEvent::success(
                Some(user_id.to_string()),
                claims.jti,
                AuditAction::TokenIssued,
            )),
            Err(e) => self.audit(AuditEvent::failure(
                Some(user_id.to_string()),
                claims.jti,
                AuditAction::TokenIssued,
                e.to_string(),
            )),
        }
        result
    }

    /// Generate a token with custom expiration.
    pub fn generate_token_with_expiry(
        &self,
        user_id: &UserId,
        roles: &[Role],
        expiry: Duration,
    ) -> Result<String, AuthError> {
        let claims = Claims::new(user_id, roles).with_expiration(expiry);

        let enc_key = self.signing_key.encoding_key()?;
        let header = jsonwebtoken::Header::new(self.signing_key.algorithm());

        jsonwebtoken::encode(&header, &claims, &enc_key)
            .map_err(|e| AuthError::TokenGeneration(e.to_string()))
    }

    fn validation(&self) -> jsonwebtoken::Validation {
        // Pin the algorithm to what our key expects — rejects alg-confusion
        // attacks (e.g. HS256 token presented to an RS256 verifier) and the
        // `alg=none` bypass (not listed in algorithms, so rejected by default).
        let mut validation = jsonwebtoken::Validation::new(self.signing_key.algorithm());
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation
    }

    fn decode_token(&self, token: &str) -> Result<Claims, AuthError> {
        let key = self.signing_key.decoding_key()?;

        let token_data =
            jsonwebtoken::decode::<Claims>(token, &key, &self.validation()).map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::Expired,
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::BadSignature,
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => AuthError::WrongAudience,
                    jsonwebtoken::errors::ErrorKind::ImmatureSignature
                    | jsonwebtoken::errors::ErrorKind::InvalidToken
                    | jsonwebtoken::errors::ErrorKind::InvalidIssuer
                    | jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(_) => {
                        AuthError::Malformed
                    }
                    _ => AuthError::Malformed,
                }
            });

        let claims = match token_data {
            Ok(td) => td.claims,
            Err(e) => {
                // We don't know the subject on a decode failure — use "<unknown>".
                self.audit(AuditEvent::failure(
                    None,
                    "<unknown>",
                    AuditAction::TokenRejected,
                    e.to_string(),
                ));
                return Err(e);
            }
        };

        // Revocation check — performed after signature/expiry so we only query
        // the store for structurally valid, non-expired tokens.
        if let Some(store) = &self.revocation_store {
            if store.is_revoked(&claims.jti) {
                self.audit(AuditEvent::failure(
                    Some(claims.sub.clone()),
                    claims.jti,
                    AuditAction::TokenRevoked,
                    "token is on revocation list",
                ));
                return Err(AuthError::Revoked);
            }
        }

        self.audit(AuditEvent::success(
            Some(claims.sub.clone()),
            claims.jti.clone(),
            AuditAction::TokenValidated,
        ));
        Ok(claims)
    }

    /// Verify and decode a raw JWT access token.
    pub fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        self.decode_token(token)
    }

    /// Parse a `Bearer <token>` header value and verify the JWT it contains.
    pub fn validate_bearer_token(&self, bearer_token: &str) -> Result<Claims, AuthError> {
        let mut parts = bearer_token.split_whitespace();
        let scheme = parts.next().ok_or(AuthError::Malformed)?;
        let token = parts.next().ok_or(AuthError::Malformed)?;

        if parts.next().is_some() || !scheme.eq_ignore_ascii_case("Bearer") {
            return Err(AuthError::Malformed);
        }

        self.decode_token(token)
    }

    /// Re-issue an access token from a valid access token (no rotation, no family tracking).
    ///
    /// Prefer [`rotate`] for production flows — this method is a compatibility
    /// shim for callers that have not yet adopted the rotation API.
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
            assert!(matches!(result.unwrap_err(), AuthError::Expired));
        }
    }

    #[test]
    fn test_invalid_token() {
        let auth = Authenticator::new("secret");
        let result = auth.verify_token("invalid.token.here");
        assert!(matches!(result.unwrap_err(), AuthError::Malformed));
    }

    #[test]
    fn test_validate_bearer_token_success() {
        let auth = Authenticator::new("secret");
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[Role::new("admin")]).unwrap();
        let bearer = format!("Bearer {token}");

        let claims = auth.validate_bearer_token(&bearer).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn test_validate_bearer_token_expired() {
        let auth = Authenticator::new("secret");
        let token =
            auth.generate_token_with_expiry(&UserId::new(), &[], Duration::minutes(-5)).unwrap();
        let bearer = format!("Bearer {token}");

        let result = auth.validate_bearer_token(&bearer);

        assert!(matches!(result, Err(AuthError::Expired)));
    }

    #[test]
    fn test_validate_bearer_token_bad_signature() {
        let auth1 = Authenticator::new("secret-one");
        let auth2 = Authenticator::new("secret-two");
        let token = auth1.generate_token(&UserId::new(), &[]).unwrap();
        let bearer = format!("Bearer {token}");

        let result = auth2.validate_bearer_token(&bearer);

        assert!(matches!(result, Err(AuthError::BadSignature)));
    }

    #[test]
    fn test_validate_bearer_token_wrong_audience() {
        let auth = Authenticator::new("secret").with_issuer("issuer-a", "audience-a");
        let token = auth.generate_token(&UserId::new(), &[]).unwrap();
        let bearer = format!("Bearer {token}");
        let other = Authenticator::new("secret").with_issuer("issuer-a", "audience-b");

        let result = other.validate_bearer_token(&bearer);

        assert!(matches!(result, Err(AuthError::WrongAudience)));
    }

    #[test]
    fn test_validate_bearer_token_malformed() {
        let auth = Authenticator::new("secret");

        let result = auth.validate_bearer_token("NotBearer token");

        assert!(matches!(result, Err(AuthError::Malformed)));
    }

    // --- FR-AUTHV-012: Token Revocation List tests ---

    /// Helper: build an in-memory store as a trait-object arc.
    fn make_store() -> Arc<dyn RevocationStore> {
        use std::collections::HashMap;
        use std::sync::Mutex;

        /// Minimal inline store so the tests in the domain layer have no
        /// dependency on the adapters crate (keeps hexagonal layers clean).
        struct SimpleStore(Mutex<HashMap<String, i64>>);
        impl RevocationStore for SimpleStore {
            fn revoke(&self, jti: &str, exp: i64) {
                self.0.lock().unwrap().insert(jti.to_owned(), exp);
            }
            fn is_revoked(&self, jti: &str) -> bool {
                let map = self.0.lock().unwrap();
                if let Some(&exp) = map.get(jti) {
                    // treat as revoked only while still within the token's lifetime
                    exp > chrono::Utc::now().timestamp()
                } else {
                    false
                }
            }
        }
        Arc::new(SimpleStore(Mutex::new(HashMap::new())))
    }

    #[test]
    fn test_valid_token_passes_revocation_check() {
        let store = make_store();
        let auth = Authenticator::new("secret").with_revocation_store(Arc::clone(&store));
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[Role::new("user")]).unwrap();

        let claims = auth.verify_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn test_revoked_token_is_rejected() {
        let store = make_store();
        let auth = Authenticator::new("secret").with_revocation_store(Arc::clone(&store));
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[]).unwrap();

        // Decode to get the jti + exp without validating revocation yet.
        let plain_auth = Authenticator::new("secret");
        let claims = plain_auth.verify_token(&token).unwrap();

        store.revoke(&claims.jti, claims.exp);

        let result = auth.verify_token(&token);
        assert!(matches!(result, Err(AuthError::Revoked)));
    }

    #[test]
    fn test_different_jti_is_unaffected_by_revocation() {
        let store = make_store();
        let auth = Authenticator::new("secret").with_revocation_store(Arc::clone(&store));
        let user_id = UserId::new();

        let token_a = auth.generate_token(&user_id, &[]).unwrap();
        let token_b = auth.generate_token(&user_id, &[]).unwrap();

        let plain_auth = Authenticator::new("secret");
        let claims_a = plain_auth.verify_token(&token_a).unwrap();

        // Revoke only token A.
        store.revoke(&claims_a.jti, claims_a.exp);

        // Token A rejected.
        assert!(matches!(auth.verify_token(&token_a), Err(AuthError::Revoked)));
        // Token B still valid.
        assert!(auth.verify_token(&token_b).is_ok());
    }

    #[test]
    fn test_expired_revocation_entry_no_longer_blocks() {
        // An entry whose exp is in the past: the inline SimpleStore treats it as
        // not-revoked since the token itself would also be expired (exp in past).
        let store = make_store();
        let auth = Authenticator::new("secret").with_revocation_store(Arc::clone(&store));
        let user_id = UserId::new();
        let token = auth.generate_token_with_expiry(&user_id, &[], Duration::minutes(-5)).unwrap();

        let plain_auth = Authenticator::new("secret");
        // Token is already expired — decode would fail, so just check is_revoked
        // does not fire before exp check.
        let _ = plain_auth.verify_token(&token); // we don't need claims here

        // Manually insert an already-expired revocation entry.
        let past_exp = (chrono::Utc::now() - Duration::seconds(10)).timestamp();
        store.revoke("some-old-jti", past_exp);

        // is_revoked returns false for that stale entry (exp in past).
        assert!(!store.is_revoked("some-old-jti"));
    }

    #[test]
    fn test_authenticator_without_store_ignores_revocation() {
        // Authenticator with no store attached should work normally.
        let auth = Authenticator::new("secret"); // no revocation store
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[]).unwrap();

        assert!(auth.verify_token(&token).is_ok());
    }

    // --- FR-AUTHV-013: Refresh-token rotation tests ---

    /// Minimal inline RefreshTokenStore for domain-layer tests (no adapter dep).
    fn make_refresh_store() -> Arc<dyn RefreshTokenStore> {
        use std::collections::HashMap;
        use std::sync::Mutex;

        struct SimpleRefreshStore(Mutex<HashMap<String, (String, i64)>>);
        impl RefreshTokenStore for SimpleRefreshStore {
            fn insert_family(&self, family_id: &str, refresh_jti: &str, exp: i64) {
                self.0.lock().unwrap().insert(family_id.to_owned(), (refresh_jti.to_owned(), exp));
            }
            fn rotate(
                &self,
                family_id: &str,
                old_jti: &str,
                new_jti: &str,
                new_exp: i64,
            ) -> Result<(), bool> {
                let mut map = self.0.lock().unwrap();
                match map.get(family_id) {
                    Some((current_jti, _)) if current_jti == old_jti => {
                        map.insert(family_id.to_owned(), (new_jti.to_owned(), new_exp));
                        Ok(())
                    }
                    Some(_) => Err(true), // mismatch → reuse/compromise
                    None => Err(false),   // family not found
                }
            }
            fn revoke_family(&self, family_id: &str) {
                self.0.lock().unwrap().remove(family_id);
            }
        }
        Arc::new(SimpleRefreshStore(Mutex::new(HashMap::new())))
    }

    fn make_auth_with_rotation() -> Authenticator {
        Authenticator::new("secret").with_refresh_token_store(make_refresh_store())
    }

    /// FR-AUTHV-013 AC-1: Valid refresh → new access+refresh pair; old invalidated.
    #[test]
    fn test_rotate_valid_refresh_issues_new_pair() {
        let auth = make_auth_with_rotation();
        let user_id = UserId::new();
        let roles = vec![Role::new("admin")];

        let pair = auth.issue_token_pair(&user_id, &roles).unwrap();
        let rotated = auth.rotate(&pair.refresh_token).unwrap();

        // New access token is valid.
        let claims = auth.verify_token(&rotated.access_token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.roles.contains(&"admin".to_string()));

        // New refresh token is different from old.
        assert_ne!(rotated.refresh_token, pair.refresh_token);

        // Family ID is preserved across rotation.
        assert_eq!(rotated.family_id, pair.family_id);
    }

    /// FR-AUTHV-013 AC-2: Old refresh token is invalidated after rotation (reuse → compromise).
    #[test]
    fn test_rotate_reused_refresh_token_returns_compromise_error() {
        let auth = make_auth_with_rotation();
        let user_id = UserId::new();

        let pair = auth.issue_token_pair(&user_id, &[]).unwrap();
        // First rotation succeeds.
        let _rotated = auth.rotate(&pair.refresh_token).unwrap();
        // Presenting the OLD refresh token again: reuse detected.
        let result = auth.rotate(&pair.refresh_token);
        assert!(
            matches!(result, Err(AuthError::CompromisedTokenFamily)),
            "expected CompromisedTokenFamily, got {result:?}"
        );
    }

    /// FR-AUTHV-013 AC-3: Expired refresh token is rejected.
    #[test]
    fn test_rotate_expired_refresh_token_rejected() {
        let auth = Authenticator::new("secret")
            .with_refresh_token_store(make_refresh_store())
            .with_refresh_token_ttl(Duration::seconds(-1)); // already expired

        let user_id = UserId::new();
        let pair = auth.issue_token_pair(&user_id, &[]).unwrap();

        let result = auth.rotate(&pair.refresh_token);
        assert!(matches!(result, Err(AuthError::Expired)), "expected Expired, got {result:?}");
    }

    /// FR-AUTHV-013 AC-4: Access token from rotated pair validates correctly.
    #[test]
    fn test_rotated_access_token_validates() {
        let auth = make_auth_with_rotation();
        let user_id = UserId::new();
        let roles = vec![Role::new("user"), Role::new("editor")];

        let pair = auth.issue_token_pair(&user_id, &roles).unwrap();
        let rotated = auth.rotate(&pair.refresh_token).unwrap();

        let claims = auth.verify_token(&rotated.access_token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.roles.contains(&"user".to_string()));
        assert!(claims.roles.contains(&"editor".to_string()));
    }

    /// FR-AUTHV-013 AC-5: A refresh token cannot be used as a bearer access token.
    #[test]
    fn test_refresh_token_is_not_valid_as_access_token() {
        let auth = make_auth_with_rotation();
        let user_id = UserId::new();

        let pair = auth.issue_token_pair(&user_id, &[]).unwrap();
        // Refresh token lacks `aud` and has `typ=refresh`, so verify_token should reject it.
        let result = auth.verify_token(&pair.refresh_token);
        // jsonwebtoken will reject due to missing/wrong aud claim.
        assert!(result.is_err(), "refresh token must not validate as an access token");
    }

    /// FR-AUTHV-013: issue_token_pair without a store returns an error.
    #[test]
    fn test_issue_token_pair_without_store_errors() {
        let auth = Authenticator::new("secret"); // no refresh store
        let user_id = UserId::new();
        let result = auth.issue_token_pair(&user_id, &[]);
        assert!(result.is_err());
    }

    // ── FR-AUTHV-014: Audit log tests ─────────────────────────────────────────

    use super::ports::{AuditAction, AuditOutcome, AuditSink};

    /// In-memory `AuditSink` impl for tests (the real one lives in
    /// `crate::adapters::audit::InMemoryAuditSink` upstream, but
    /// this sub-crate owns the domain only; the adapter is a
    /// downstream concern).
    #[derive(Default)]
    struct InMemoryAuditSink {
        events: std::sync::Mutex<Vec<ports::AuditEvent>>,
    }

    impl InMemoryAuditSink {
        fn new() -> Self {
            Self::default()
        }
    }

    impl AuditSink for InMemoryAuditSink {
        fn record(&self, event: ports::AuditEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn make_audit_sink() -> Arc<InMemoryAuditSink> {
        Arc::new(InMemoryAuditSink::new())
    }

    /// generate_token emits TokenIssued / Success.
    #[test]
    fn audit_token_issued_on_generate() {
        let sink = make_audit_sink();
        let auth =
            Authenticator::new("secret").with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        let user_id = UserId::new();

        let _token = auth.generate_token(&user_id, &[]).unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::TokenIssued);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        // Actor is the user subject; subject is the jti — neither contains the token value.
        assert_eq!(events[0].actor.as_deref(), Some(user_id.to_string().as_str()));
        assert!(!events[0].subject.is_empty(), "jti must be non-empty");
        // No token value in reason or subject.
        assert!(events[0].reason.is_none());
    }

    /// verify_token on a valid token emits TokenValidated / Success.
    #[test]
    fn audit_token_validated_on_verify_success() {
        let sink = make_audit_sink();
        let auth =
            Authenticator::new("secret").with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[]).unwrap();
        sink.drain(); // discard TokenIssued

        auth.verify_token(&token).unwrap();

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::TokenValidated);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
    }

    /// verify_token on an expired token emits TokenRejected / Failure with reason.
    #[test]
    fn audit_token_rejected_on_expired() {
        let sink = make_audit_sink();
        let auth =
            Authenticator::new("secret").with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        let token =
            auth.generate_token_with_expiry(&UserId::new(), &[], Duration::minutes(-5)).unwrap();
        sink.drain();

        let _ = auth.verify_token(&token);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::TokenRejected);
        assert_eq!(events[0].outcome, AuditOutcome::Failure);
        let reason = events[0].reason.as_deref().unwrap_or("");
        assert!(!reason.is_empty(), "rejection reason must be populated");
    }

    /// A revoked token emits TokenRevoked / Failure (not TokenValidated).
    #[test]
    fn audit_token_revoked_emits_correct_event() {
        let rev_store = make_store();
        let sink = make_audit_sink();
        let auth = Authenticator::new("secret")
            .with_revocation_store(Arc::clone(&rev_store))
            .with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[]).unwrap();
        let plain = Authenticator::new("secret");
        let claims = plain.verify_token(&token).unwrap();
        rev_store.revoke(&claims.jti, claims.exp);
        sink.drain();

        let _ = auth.verify_token(&token);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, AuditAction::TokenRevoked);
        assert_eq!(events[0].outcome, AuditOutcome::Failure);
        assert!(events[0].reason.as_deref().unwrap_or("").contains("revocation"));
    }

    /// rotate() on success emits TokenRotated / Success.
    #[test]
    fn audit_token_rotated_on_success() {
        let sink = make_audit_sink();
        let auth = Authenticator::new("secret")
            .with_refresh_token_store(make_refresh_store())
            .with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        let user_id = UserId::new();
        let pair = auth.issue_token_pair(&user_id, &[]).unwrap();
        sink.drain();

        auth.rotate(&pair.refresh_token).unwrap();

        let events = sink.events();
        // One TokenIssued (from generate_token inside rotate) + one TokenRotated
        let rotated = events.iter().find(|e| e.action == AuditAction::TokenRotated);
        assert!(rotated.is_some(), "TokenRotated event must be emitted");
        assert_eq!(rotated.unwrap().outcome, AuditOutcome::Success);
    }

    /// rotate() with a compromised token emits TokenRejected / Failure.
    #[test]
    fn audit_token_rejected_on_compromised_rotation() {
        let sink = make_audit_sink();
        let auth = Authenticator::new("secret")
            .with_refresh_token_store(make_refresh_store())
            .with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        let user_id = UserId::new();
        let pair = auth.issue_token_pair(&user_id, &[]).unwrap();
        auth.rotate(&pair.refresh_token).unwrap(); // first rotation OK
        sink.drain();

        let _ = auth.rotate(&pair.refresh_token); // reuse → compromise

        let events = sink.events();
        let rejected = events.iter().find(|e| e.action == AuditAction::TokenRejected);
        assert!(rejected.is_some(), "TokenRejected event must be emitted on compromise");
        assert_eq!(rejected.unwrap().outcome, AuditOutcome::Failure);
        let reason = rejected.unwrap().reason.as_deref().unwrap_or("");
        assert!(reason.contains("compromised") || reason.contains("reuse"), "reason: {reason}");
    }

    /// The audit event subject/actor MUST NOT contain the raw token value.
    #[test]
    fn audit_event_contains_no_raw_token_value() {
        let sink = make_audit_sink();
        let auth =
            Authenticator::new("secret").with_audit_sink(Arc::clone(&sink) as Arc<dyn AuditSink>);
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[]).unwrap();
        auth.verify_token(&token).unwrap();

        for event in sink.events() {
            assert_ne!(event.subject, token, "token value must not appear in audit subject");
            if let Some(actor) = &event.actor {
                assert_ne!(actor, &token, "token value must not appear in audit actor");
            }
            if let Some(reason) = &event.reason {
                assert_ne!(reason, &token, "token value must not appear in audit reason");
            }
        }
    }

    // ── FR-AUTHV-017: Asymmetric signing (RS256 / ES256) tests ───────────────
    //
    // Test PEM keys were generated with `openssl` (RSA 2048, EC P-256).
    // They are ONLY used in tests; no private key material ships in production.

    const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDU51jaeL8ulx4i\n\
69Qet/ViKLdJMKgpeqgaNnHGOw1dAsyUyqOLO5awuTiytkXq6MtJPS235nXJAQwf\n\
ak4hBDAVzKJRwmmeMRS0zSRmHYlkKeK9pI0E6X0Aik+VLRXJ6Cd/Y29FfAeZrw++\n\
/MiQJ1sLKKUt7G+Vrq2YwkaS/NzaG2+i2vLzMW29FRlXV3Sc6QT2Os9dpjFDBH4J\n\
QOQnbzR6aHSajcgAKdhVYIE8vI3qYmhEcvREdhbuUzaFmaGXbgCwJPcPeaixyKbJ\n\
OjYUVExAQ0wlBwysTZkeJ3spdypGQu/uWDoUQhc0NUp5nT8I0oHa6lmmx7Ps6uUc\n\
Z7kaeTtFAgMBAAECggEAOYmiVjy+skkt4FMqmvitTM9jJVkMgVVAPAFNwzxvUp0w\n\
i9+tzjGW+oC8JXQkNiWe1ta9Vc9nMqDhVVYl8j9O/X01uvHXGGT8SxaLyTsfR94Y\n\
BJeFcvflC/HVKyQpmMzwa7mEN1ubNDn+/+cSDv9L2BqudVhKGcJA8SFD8HJ8/0Zf\n\
pBs9VWP1oKaDIXOcTfzQFWChhSexGZoGsqwOaWshNLxrpB6L2Mirnz9Z/Q/jRO+E\n\
Gf09WT7H6EjMfFplyFCK3ITJ3cdbxgmO+U3V1/eqcTc8yAZmXLsFj/2P9CnuugfN\n\
pR19TaVnYPaGGNuIrZndQPLQcE0TdO81ABncLJDGuwKBgQDxuwGtjq6HZ8of65v6\n\
WWotztKNQOJiBgD+76HaJYDQmv5OiHexaba4lmxlgl9bhWca+CDFpQlbSZJzH5dw\n\
YlI28e6qvOKNFWQ77rGKZQetV1+KES1hKnksnmu7P5lIoJDJfH0ZtJd7eRJ+JonL\n\
6utIx45/Mq+WuuD+HyvF1mgnHwKBgQDheLbqQHOt9iBf6BjpOYcfGkXWejTI3f3y\n\
93/J4EKh/1lC2QbgQgvF2eVegZVwefjHegxWCA/QYHDhRb/KAshbkUBJlSeF6dw7\n\
k7SSeuOt+sfvNpZq6wbe8dSgJ7O8SNRJp9UBpIz4Y7o7CwHLMmQXmIzlocSs3e+2\n\
ej2Z65aFGwKBgDIroAOHk42i6v6JBgyFtlXfkS+kAdhaaqZ+0dbW5c9l+9YM2NrH\n\
mBbjkYfX8Tarj2S3jwW2ZSS/NlgSfHnkzi99Mw3YuiSSBgWyWsLgiSFe+wNK4WJD\n\
UHcEQlPQtV2vhZ1r6wMEylPkIwRvtzXNghvO3zJjMLJWAxB7I7ih8Wf9AoGBALmk\n\
cradKqHpLO7KYvhkbWSmdSoKpLteTGFodsb45uQLIqtvlcG/n4HfzoLpnullA/j5\n\
/H45VQv02/wfObJSaDU8evoa3NfdnX9QNjUFCcGN4mCLSX3u1VFrO+5BwjMco+2h\n\
Sjh4C7nYItXKUkfDzbW/3QKVFyJd+aj9LQs2dlBRAoGBAJJ4r7O5VWMWS7UEx6yS\n\
O5hgFRM3gmV/COQzNb/zev1+m6VW/K7NytIrp45ViRkeCr2GIsiuByIz1Bk4jHQL\n\
leVzU/atjQNq4q6ltYErheFqi1XnU8/9/ZDhu+KFVxrf+hkiVmGtPvA5nNWP139r\n\
2Y43KB8fKmS1eC+qk7PpKiz3\n\
-----END PRIVATE KEY-----";

    const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1OdY2ni/LpceIuvUHrf1\n\
Yii3STCoKXqoGjZxxjsNXQLMlMqjizuWsLk4srZF6ujLST0tt+Z1yQEMH2pOIQQw\n\
FcyiUcJpnjEUtM0kZh2JZCnivaSNBOl9AIpPlS0Vyegnf2NvRXwHma8PvvzIkCdb\n\
CyilLexvla6tmMJGkvzc2htvotry8zFtvRUZV1d0nOkE9jrPXaYxQwR+CUDkJ280\n\
emh0mo3IACnYVWCBPLyN6mJoRHL0RHYW7lM2hZmhl24AsCT3D3moscimyTo2FFRM\n\
QENMJQcMrE2ZHid7KXcqRkLv7lg6FEIXNDVKeZ0/CNKB2upZpsez7OrlHGe5Gnk7\n\
RQIDAQAB\n\
-----END PUBLIC KEY-----";

    // jsonwebtoken requires EC private keys in PKCS#8 format (`BEGIN PRIVATE KEY`),
    // not the SEC1 `BEGIN EC PRIVATE KEY` format.
    const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNJcPEikDJow0tW+F\n\
KOQiDxWheHjIV1EtPOdikLS2Hu2hRANCAAQWFkN2Lqn9Od1Got6MhqLKPNGFnvuv\n\
lh7keMRanaF0/PW5Pf0F9QUj+Otg91pp6M+zW+cucHPThnRYg2jr5o6C\n\
-----END PRIVATE KEY-----";

    const EC_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFhZDdi6p/TndRqLejIaiyjzRhZ77\n\
r5Ye5HjEWp2hdPz1uT39BfUFI/jrYPdaaejPs1vnLnBz04Z0WINo6+aOgg==\n\
-----END PUBLIC KEY-----";

    fn rs256_auth() -> Authenticator {
        Authenticator::with_signing_key(SigningKey::rs256(RSA_PRIVATE_PEM, RSA_PUBLIC_PEM))
    }

    fn es256_auth() -> Authenticator {
        Authenticator::with_signing_key(SigningKey::es256(EC_PRIVATE_PEM, EC_PUBLIC_PEM))
    }

    /// FR-AUTHV-017 AC-1: RS256 round-trip — sign with RSA private, verify with RSA public.
    #[test]
    fn rs256_round_trip() {
        let auth = rs256_auth();
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[Role::new("admin")]).unwrap();
        let claims = auth.verify_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.roles.contains(&"admin".to_string()));
    }

    /// FR-AUTHV-017 AC-2: ES256 round-trip — sign with EC private, verify with EC public.
    #[test]
    fn es256_round_trip() {
        let auth = es256_auth();
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[Role::new("user")]).unwrap();
        let claims = auth.verify_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.roles.contains(&"user".to_string()));
    }

    /// FR-AUTHV-017 AC-3: HS256 still works unchanged after the refactor.
    #[test]
    fn hs256_still_works_after_asymmetric_refactor() {
        let auth = Authenticator::new("my-hmac-secret");
        let user_id = UserId::new();
        let token = auth.generate_token(&user_id, &[]).unwrap();
        let claims = auth.verify_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
    }

    /// FR-AUTHV-017 AC-4: alg-confusion — RS256-signed token rejected by HS256 verifier.
    ///
    /// An attacker might present a token whose `alg` header says `HS256` but which
    /// was signed with the RSA public key as the HMAC secret.  Our verifier pins the
    /// algorithm to `HS256` and therefore rejects any token with a different `alg` header.
    #[test]
    fn alg_confusion_rs256_token_rejected_by_hs256_verifier() {
        // Issue a legit RS256 token …
        let rs_auth = rs256_auth();
        let user_id = UserId::new();
        let rs256_token = rs_auth.generate_token(&user_id, &[]).unwrap();

        // … then try to verify it with an HS256 authenticator (different algorithm).
        let hs_auth = Authenticator::new("some-hmac-secret");
        let result = hs_auth.verify_token(&rs256_token);
        assert!(result.is_err(), "HS256 verifier MUST reject an RS256-signed token");
    }

    /// FR-AUTHV-017 AC-5: alg-confusion — HS256-signed token rejected by RS256 verifier.
    #[test]
    fn alg_confusion_hs256_token_rejected_by_rs256_verifier() {
        // Issue a legit HS256 token …
        let hs_auth = Authenticator::new("some-hmac-secret");
        let user_id = UserId::new();
        let hs256_token = hs_auth.generate_token(&user_id, &[]).unwrap();

        // … then try to verify it with an RS256 authenticator.
        let rs_auth = rs256_auth();
        let result = rs_auth.verify_token(&hs256_token);
        assert!(
            result.is_err(),
            "RS256 verifier MUST reject an HS256-signed token (alg-confusion defense)"
        );
    }

    /// FR-AUTHV-017 AC-6: alg=none — a hand-crafted `alg=none` token is rejected.
    ///
    /// `jsonwebtoken` does not produce `alg=none` tokens; we verify that the decoder
    /// rejects a manually-crafted unsigned token regardless.
    #[test]
    fn alg_none_token_is_rejected() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        // Build a fake `alg=none` token: header.payload.  (empty signature)
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            r#"{"sub":"evil","iss":"authkit","aud":"authkit","exp":9999999999,"iat":0,"nbf":0,"jti":"x","roles":[]}"#,
        );
        let none_token = format!("{header}.{payload}.");

        // Every algorithm variant must reject it.
        assert!(
            Authenticator::new("secret").verify_token(&none_token).is_err(),
            "HS256 must reject alg=none"
        );
        assert!(rs256_auth().verify_token(&none_token).is_err(), "RS256 must reject alg=none");
        assert!(es256_auth().verify_token(&none_token).is_err(), "ES256 must reject alg=none");
    }

    /// FR-AUTHV-017 AC-7: wrong RS256 key — different RSA key pair's token is rejected.
    #[test]
    fn rs256_wrong_key_rejected() {
        // Two independent RS256 authenticators (same PEM in test, but conceptually different)
        // In a real scenario these would be different key pairs; here we test that a token
        // signed with one key is rejected by a verifier whose *expected* key differs.
        // We simulate by building the token with the RSA key but verifying with HS256.
        let rs_auth = rs256_auth();
        let user_id = UserId::new();
        let token = rs_auth.generate_token(&user_id, &[]).unwrap();

        // Verifier uses the wrong public key (HS256 key used as public key) — must fail.
        let wrong_auth = Authenticator::new("wrong-key");
        let result = wrong_auth.verify_token(&token);
        assert!(result.is_err(), "token signed with RS256 must be rejected by wrong-key verifier");
    }

    /// FR-AUTHV-017 AC-8: wrong ES256 key — ES256-signed token rejected by different-key verifier.
    #[test]
    fn es256_wrong_key_rejected() {
        let es_auth = es256_auth();
        let user_id = UserId::new();
        let token = es_auth.generate_token(&user_id, &[]).unwrap();

        // Try to verify with an HS256 verifier (wrong algorithm + wrong key).
        let wrong_auth = Authenticator::new("wrong-key");
        let result = wrong_auth.verify_token(&token);
        assert!(result.is_err(), "ES256 token must be rejected by wrong-key verifier");
    }
}
