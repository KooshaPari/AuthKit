//! OpenID Connect Discovery 1.0 + JWKS fetch (AUT-SOTA-001).
//!
//! Implements OIDC Discovery (RFC-defined `/.well-known/openid-configuration`
//! document) and JWKS (JSON Web Key Set) fetching. Used by AuthKit to:
//!
//! - Bootstrap an OAuth2/OIDC client against an issuer URL (any IdP that
//!   advertises OIDC Discovery: Auth0, Okta, Keycloak, Azure AD, Google,
//!   Cognito, Dex, Logto, Zitadel, Authentik).
//! - Verify JWT signatures using the IdP's published JWKS, with
//!   in-memory caching (configurable TTL).
//!
//! ## Features
//!
//! Gated behind `feature = "oidc"` to keep the default build lightweight.
//! With the feature off, this module still compiles (it just exposes
//! nothing — `DiscoveryClient::discover` returns `Err(NotEnabled)`).
//!
//! ## Spec
//!
//! <https://openid.net/specs/openid-connect-discovery-1_0.html>
//! <https://datatracker.ietf.org/doc/html/rfc7517> (JWKS)
//!
//! DAG unit: AUT-SOTA-001.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "oidc")]
use std::sync::Mutex;

#[cfg(feature = "oidc")]
use url::Url;

#[cfg(feature = "oidc")]
use thiserror::Error;

/// OIDC Discovery document (RFC section 4.2).
///
/// We deserialize the fields we actually use; extra fields are tolerated
/// (`#[serde(default)]` on every field).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDoc {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    /// Space-separated list of response types the AS supports.
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// Space-separated list of subject types (always "public" or "pairwise").
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    /// Space-separated list of JWS signing algs for ID tokens.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Space-separated list of OAuth2 scopes the AS supports.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub claims_supported: Vec<String>,
}

/// JWKS document (RFC 7517).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksDoc {
    pub keys: Vec<Jwk>,
}

/// Single JWK entry (RFC 7517 sec 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    /// Key use: "sig" (signature) | "enc" (encryption).
    #[serde(default)]
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    /// EC curve (when kty = "EC").
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    /// Secret key (when kty = "oct").
    pub k: Option<String>,
    /// X.509 cert chain (PEM).
    #[serde(rename = "x5c", default)]
    pub x5c: Vec<String>,
}

/// Cached JWKS snapshot (kid -> Jwk).
#[derive(Debug, Clone)]
pub struct CachedJwks {
    pub fetched_at: Instant,
    pub by_kid: HashMap<String, Jwk>,
}

impl CachedJwks {
    pub fn lookup(&self, kid: &str) -> Option<&Jwk> {
        self.by_kid.get(kid)
    }

    pub fn is_fresh(&self, ttl: Duration) -> bool {
        self.fetched_at.elapsed() < ttl
    }
}

/// Discovery client errors. The feature-gated variant is more detailed.
#[cfg(feature = "oidc")]
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("oidc feature is not enabled on authkit")]
    NotEnabled,
    #[error("invalid issuer url: {0}")]
    InvalidIssuerUrl(String),
    #[error("failed to parse discovery url: {0}")]
    InvalidDiscoveryUrl(#[from] url::ParseError),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("issuer mismatch: discovery doc says {doc}, request used {req}")]
    IssuerMismatch { doc: String, req: String },
}

#[cfg(not(feature = "oidc"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    NotEnabled,
}

#[cfg(not(feature = "oidc"))]
impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnabled => write!(f, "oidc feature is not enabled on authkit"),
        }
    }
}

#[cfg(not(feature = "oidc"))]
impl std::error::Error for DiscoveryError {}

/// Discovery client. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct DiscoveryClient {
    /// HTTP client (feature-gated). When the feature is off, the client
    /// can still be cloned but every call returns `Err(NotEnabled)`.
    #[cfg(feature = "oidc")]
    inner: Arc<DiscoveryClientInner>,
}

#[cfg(feature = "oidc")]
struct DiscoveryClientInner {
    http: reqwest::Client,
    user_agent: String,
    jwks_cache: Mutex<Option<CachedJwks>>,
    cache_ttl: Duration,
}

impl DiscoveryClient {
    /// Construct a new client with a default `reqwest::Client`.
    #[cfg(feature = "oidc")]
    pub fn new() -> Result<Self, DiscoveryError> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("authkit/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            inner: Arc::new(DiscoveryClientInner {
                http,
                user_agent: format!("authkit/{}", env!("CARGO_PKG_VERSION")),
                jwks_cache: Mutex::new(None),
                cache_ttl: Duration::from_secs(600), // 10 min default
            }),
        })
    }

    /// Stub constructor for the no-feature build.
    #[cfg(not(feature = "oidc"))]
    pub fn new() -> Result<Self, DiscoveryError> {
        Ok(Self {})
    }

    /// Fetch the OIDC Discovery document for an issuer.
    ///
    /// `issuer` should be the canonical issuer URL (no trailing slash,
    /// no `.well-known/...` suffix). The function appends the well-known
    /// path and validates that the returned document's `issuer` field
    /// matches the request issuer (defends against discovery spoofing).
    #[cfg(feature = "oidc")]
    pub async fn discover(&self, issuer: &str) -> Result<DiscoveryDoc, DiscoveryError> {
        let issuer_url = Url::parse(issuer)
            .map_err(|e| DiscoveryError::InvalidIssuerUrl(format!("{e}: {issuer}")))?;
        // Per spec, discovery URL is {issuer}/.well-known/openid-configuration
        let mut discovery_url = issuer_url.clone();
        // Trim trailing slash on issuer path before appending.
        let path = issuer_url.path().trim_end_matches('/');
        discovery_url.set_path(&format!("{path}/.well-known/openid-configuration"));

        let doc: DiscoveryDoc = self
            .inner
            .http
            .get(discovery_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if doc.issuer != issuer {
            return Err(DiscoveryError::IssuerMismatch {
                doc: doc.issuer.clone(),
                req: issuer.to_string(),
            });
        }
        Ok(doc)
    }

    /// Stub discover for the no-feature build.
    #[cfg(not(feature = "oidc"))]
    pub async fn discover(&self, _issuer: &str) -> Result<DiscoveryDoc, DiscoveryError> {
        Err(DiscoveryError::NotEnabled)
    }

    /// Fetch JWKS from a JWKS URI, with in-memory caching.
    #[cfg(feature = "oidc")]
    pub async fn jwks(&self, jwks_uri: &str) -> Result<CachedJwks, DiscoveryError> {
        // Fast path: cache hit + still fresh.
        {
            let guard = self.inner.jwks_cache.lock().expect("jwks cache poisoned");
            if let Some(cached) = guard.as_ref() {
                if cached.is_fresh(self.inner.cache_ttl) {
                    return Ok(cached.clone());
                }
            }
        }
        let jwks: JwksDoc = self
            .inner
            .http
            .get(jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let by_kid: HashMap<String, Jwk> = jwks
            .keys
            .into_iter()
            .filter_map(|k| k.kid.clone().map(|kid| (kid, k)))
            .collect();
        let cached = CachedJwks {
            fetched_at: Instant::now(),
            by_kid,
        };
        *self.inner.jwks_cache.lock().expect("jwks cache poisoned") = Some(cached.clone());
        Ok(cached)
    }

    /// Override the JWKS cache TTL (default 600s).
    #[cfg(feature = "oidc")]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        let inner = Arc::make_mut(&mut self.inner);
        inner.cache_ttl = ttl;
        // Re-Arc it (cheap; Arc::make_mut is in-place if exclusive)
        self
    }
}

#[cfg(feature = "oidc")]
impl Default for DiscoveryClient {
    fn default() -> Self {
        Self::new().expect("default reqwest::Client builds successfully")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DiscoveryDoc deserializes from the canonical Auth0 example.
    #[test]
    fn discovery_doc_deserializes_canonical_example() {
        let json = r#"{
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/oauth/token",
            "jwks_uri": "https://example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"]
        }"#;
        let doc: DiscoveryDoc = serde_json::from_str(json).unwrap();
        assert_eq!(doc.issuer, "https://example.com");
        assert_eq!(
            doc.token_endpoint.as_deref(),
            Some("https://example.com/oauth/token")
        );
        assert!(doc.code_challenge_methods_supported.contains(&"S256".to_string()));
    }

    /// DiscoveryDoc tolerates extra unknown fields.
    #[test]
    fn discovery_doc_tolerates_extra_fields() {
        let json = r#"{
            "issuer": "https://example.com",
            "response_types_supported": ["code"],
            "frontchannel_logout_supported": true,
            "unknown_field_we_dont_know_about": [1,2,3]
        }"#;
        let doc: DiscoveryDoc = serde_json::from_str(json).unwrap();
        assert_eq!(doc.issuer, "https://example.com");
        assert!(doc.token_endpoint.is_none());
    }

    /// JwksDoc deserializes a single-RSA-key JWKS.
    #[test]
    fn jwks_doc_deserializes_rsa_key() {
        let json = r#"{
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-1",
                "alg": "RS256",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z",
                "e": "AQAB"
            }]
        }"#;
        let doc: JwksDoc = serde_json::from_str(json).unwrap();
        assert_eq!(doc.keys.len(), 1);
        let key = &doc.keys[0];
        assert_eq!(key.kty, "RSA");
        assert_eq!(key.kid.as_deref(), Some("test-key-1"));
        assert_eq!(key.alg.as_deref(), Some("RS256"));
    }

    /// CachedJwks lookup by kid.
    #[test]
    fn cached_jwks_lookup_by_kid() {
        let mut by_kid = HashMap::new();
        by_kid.insert(
            "kid-1".to_string(),
            Jwk {
                kty: "oct".to_string(),
                r#use: Some("sig".to_string()),
                kid: Some("kid-1".to_string()),
                alg: Some("HS256".to_string()),
                n: None,
                e: None,
                crv: None,
                x: None,
                y: None,
                k: Some("dGVzdA".to_string()),
                x5c: vec![],
            },
        );
        let cached = CachedJwks {
            fetched_at: Instant::now(),
            by_kid,
        };
        assert!(cached.lookup("kid-1").is_some());
        assert!(cached.lookup("kid-missing").is_none());
        assert!(cached.is_fresh(Duration::from_secs(60)));
    }

    /// No-feature build: discover returns NotEnabled.
    #[cfg(not(feature = "oidc"))]
    #[tokio::test]
    async fn no_feature_discover_returns_not_enabled() {
        let client = DiscoveryClient::new().unwrap();
        let err = client.discover("https://example.com").await.unwrap_err();
        assert_eq!(err, DiscoveryError::NotEnabled);
    }
}