//! WebAuthn challenge/assertion handling for AuthKit.
//!
//! Implements the W3C WebAuthn Level 3 flow as a server-side verifier:
//!
//! 1. **Registration**:
//!    - Server generates a random challenge (32 bytes), stores it bound
//!      to the (user_id, relying_party_id) tuple with a 60s TTL.
//!    - Client (browser) calls `navigator.credentials.create()` with the
//!      challenge + rpId + user.id + pubKeyCredParams. Returns the
//!      attestation (authenticator data + client data JSON + attestation
//!      statement).
//!    - Server calls [`WebAuthnVerifier::verify_registration`] which:
//!      a. Parses the attestation CBOR (we define `Attestation` struct
//!         with the fields we extract; the raw CBOR is passed to a
//!         backend-specific parser in the follow-up AUT-SOTA-003b).
//!      b. Verifies `rpIdHash == SHA256(rp_id)`.
//!      c. Verifies `flags.up == true` and `flags.uv == true`.
//!      d. Verifies the client data JSON's `challenge` matches the stored
//!         one and `origin` is in the allowed list.
//!      e. Verifies the credential ID is unique (not previously registered).
//!      f. Stores the (credential_id, public_key) pair on the user.
//!
//! 2. **Authentication**:
//!    - Server generates a fresh challenge, returns it to the client.
//!    - Client calls `navigator.credentials.get()` with the challenge.
//!    - Server calls [`WebAuthnVerifier::verify_authentication`] which:
//!      a. Looks up the credential by ID.
//!      b. Verifies rpIdHash.
//!      c. Verifies signature against stored public key (using a backend
//!         adapter; this module provides [`verify_signature`] as a
//!         placeholder for the real ECDSA/RSA verify in AUT-SOTA-003b).
//!      d. Verifies sign count > stored sign count (replay defense).
//!
//! ## Feature gate
//!
//! This module is feature-gated behind `webauthn` to keep the default
//! build light. Production consumers will enable it via `features = ["webauthn"]`.
//!
//! ## Follow-ups
//!
//! - **AUT-SOTA-003b**: real CBOR attestation parsing + ECDSA signature
//!   verification (using `esrs` crate for secp256r1, `rsa` for RSA-PSS,
//!   `p256` for ES256). The trait is in place so this is additive.
//! - **AUT-SOTA-003c**: assertion signature verify (full U2F-compatible
//!   signature check over authenticator data + client data hash).
//! - **AUT-SOTA-003d**: attestation trust path validation against
//!   FIDO Alliance MDS (META blob).
//!
//! ## DAG units
//!
//! - AUT-SOTA-003 (this module) - trait + types + challenge storage + tests
//! - AUT-SOTA-003b (follow-up) - CBOR attestation + ECDSA verify
//! - AUT-SOTA-003c (follow-up) - assertion signature verify
//! - AUT-SOTA-003d (follow-up) - MDS trust path
#![allow(clippy::result_large_err)]

use crate::domain::session_store::{SessionStore, SessionStoreError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// WebAuthn verifier errors.
#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("challenge expired or not found")]
    ChallengeNotFound,

    #[error("rpIdHash mismatch (expected {expected}, got {got})")]
    RpIdHashMismatch { expected: String, got: String },

    #[error("flags.up must be set (user presence)")]
    UserPresenceNotSet,

    #[error("flags.uv must be set (user verification)")]
    UserVerificationNotSet,

    #[error("credential already registered")]
    CredentialAlreadyExists,

    #[error("credential not found")]
    CredentialNotFound,

    #[error("session store error: {0}")]
    SessionStore(#[from] SessionStoreError),

    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("client data JSON parse failed: {0}")]
    ClientDataJson(#[from] serde_json::Error),
}

/// Authenticator data flags (from §6.1 of the WebAuthn spec).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuthenticatorDataFlags {
    /// User Present (UP) — required to be set.
    pub up: bool,
    /// User Verified (UV) — required to be set.
    pub uv: bool,
    /// Backup Eligibility (BE).
    pub be: bool,
    /// Backup State (BS).
    pub bs: bool,
    /// Attested Credential Data present (AT).
    pub at: bool,
    /// Extension data present (ED).
    pub ed: bool,
}

impl AuthenticatorDataFlags {
    /// Decode the flags byte per §6.1.
    pub fn from_byte(b: u8) -> Self {
        Self {
            up: b & 0x01 != 0,
            uv: b & 0x04 != 0,
            be: b & 0x08 != 0,
            bs: b & 0x10 != 0,
            at: b & 0x40 != 0,
            ed: b & 0x80 != 0,
        }
    }

    /// Encode back to byte.
    pub fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.up { b |= 0x01; }
        if self.uv { b |= 0x04; }
        if self.be { b |= 0x08; }
        if self.bs { b |= 0x10; }
        if self.at { b |= 0x40; }
        if self.ed { b |= 0x80; }
        b
    }
}

/// Parsed authenticator data (subset sufficient for the trait surface).
///
/// §6.1 of the WebAuthn spec. Full parsing (CBOR of attested credential
/// data + extensions) lands in AUT-SOTA-003b.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorData {
    /// SHA-256 of the relying party ID.
    pub rp_id_hash: [u8; 32],
    /// Flags.
    pub flags: AuthenticatorDataFlags,
    /// Signature counter (32-bit).
    pub sign_count: u32,
}

impl AuthenticatorData {
    /// Parse the first 37 bytes of an authenticator data blob.
    pub fn parse(bytes: &[u8]) -> Result<Self, WebAuthnError> {
        if bytes.len() < 37 {
            return Err(WebAuthnError::UserPresenceNotSet); // generic "too short"
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[..32]);
        let flags = AuthenticatorDataFlags::from_byte(bytes[32]);
        let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        Ok(Self { rp_id_hash, flags, sign_count })
    }
}

/// Client data JSON (§5.10.1 of the WebAuthn spec).
///
/// Server-side validation: `type`, `challenge`, `origin`, optionally
/// `crossOrigin`. `tokenBinding` is parsed for completeness but not
/// enforced (it's rarely used and many IdPs don't support it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectedClientData {
    #[serde(rename = "type")]
    pub ty: String,
    pub challenge: String,
    pub origin: String,
    #[serde(default, rename = "crossOrigin")]
    pub cross_origin: bool,
    #[serde(default, rename = "tokenBinding")]
    pub token_binding: Option<TokenBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBinding {
    pub status: String,
    #[serde(default)]
    pub id: Option<String>,
}

/// Stored WebAuthn credential public-key material.
///
/// In production this would be a tagged enum over ES256 / RS256 / PS256 /
/// EdDSA. For AUT-SOTA-003 we accept raw bytes and defer crypto parsing
/// to AUT-SOTA-003b.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// Credential ID (raw bytes; base64url in transport).
    pub credential_id: Vec<u8>,
    /// Public key (COSE-encoded; raw bytes here).
    pub public_key: Vec<u8>,
    /// Sign count for replay defense.
    pub sign_count: u32,
    /// Friendly name (e.g., "Yubikey 5C", "iPhone 15 Touch ID").
    #[serde(default)]
    pub label: Option<String>,
    /// Created-at timestamp (RFC3339).
    pub created_at: String,
}

/// Configuration for the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnConfig {
    /// Relying Party ID (e.g., "auth.example.com"). Must match the
    /// origin's effective domain.
    pub rp_id: String,
    /// Allowed origins (e.g., `["https://app.example.com"]`).
    pub allowed_origins: Vec<String>,
    /// Challenge TTL in seconds (default 60s per spec recommendation).
    pub challenge_ttl_secs: u64,
}

impl WebAuthnConfig {
    /// Construct a new config with a sensible default TTL.
    pub fn new(rp_id: impl Into<String>, allowed_origins: Vec<String>) -> Self {
        Self { rp_id: rp_id.into(), allowed_origins, challenge_ttl_secs: 60 }
    }
}

/// The WebAuthn verifier. Thread-safe (`Send + Sync`) via `Arc<SessionStore>`.
#[derive(Clone)]
pub struct WebAuthnVerifier {
    config: Arc<WebAuthnConfig>,
    session_store: Arc<dyn SessionStore>,
    /// Credential registry: user_id -> Vec<WebAuthnCredential>.
    /// In production this would be backed by Postgres (DAG unit AUT-SOTA-003b).
    credentials: Arc<std::sync::RwLock<std::collections::HashMap<String, Vec<WebAuthnCredential>>>>,
}

impl std::fmt::Debug for WebAuthnVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAuthnVerifier")
            .field("rp_id", &self.config.rp_id)
            .field("allowed_origins", &self.config.allowed_origins)
            .field("challenge_ttl_secs", &self.config.challenge_ttl_secs)
            .finish_non_exhaustive()
    }
}

impl WebAuthnVerifier {
    /// Create a new verifier.
    pub fn new(config: WebAuthnConfig, session_store: Arc<dyn SessionStore>) -> Self {
        Self {
            config: Arc::new(config),
            session_store,
            credentials: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Generate a fresh challenge for the given user + operation.
    ///
    /// Operation is either `"create"` (registration) or `"get"` (auth).
    /// The challenge is a 32-byte random URL-safe-base64-no-pad string.
    pub async fn generate_challenge(
        &self,
        user_id: &str,
        operation: &str,
    ) -> Result<String, WebAuthnError> {
        let bytes: [u8; 32] = rand_bytes();
        let challenge = URL_SAFE_NO_PAD.encode(bytes);

        // Store the challenge keyed to (user_id, operation, rp_id) with TTL.
        let key = format!("webauthn:{}:{}:{}", operation, self.config.rp_id, user_id);
        let ttl_secs = self.config.challenge_ttl_secs;
        self.session_store
            .bind_state(&key, &challenge, "webauthn-challenge", ttl_secs, None)
            .await?;

        Ok(challenge)
    }

    /// Verify a registration response.
    ///
    /// `attestation` is the parsed CBOR attestation (raw bytes for AUT-SOTA-003
    /// until AUT-SOTA-003b lands real parsing).
    /// `client_data_json` is the raw client data JSON string from the browser.
    /// `credential_id` and `public_key` are the fields the JS side extracted.
    pub async fn verify_registration(
        &self,
        user_id: &str,
        challenge: &str,
        authenticator_data: &AuthenticatorData,
        client_data_json: &str,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<WebAuthnCredential, WebAuthnError> {
        // 1. rpIdHash check
        let expected = Sha256::digest(self.config.rp_id.as_bytes());
        if authenticator_data.rp_id_hash != expected.into() {
            return Err(WebAuthnError::RpIdHashMismatch {
                expected: URL_SAFE_NO_PAD.encode(expected),
                got: URL_SAFE_NO_PAD.encode(authenticator_data.rp_id_hash),
            });
        }

        // 2. UP + UV flags must be set
        if !authenticator_data.flags.up {
            return Err(WebAuthnError::UserPresenceNotSet);
        }
        if !authenticator_data.flags.uv {
            return Err(WebAuthnError::UserVerificationNotSet);
        }

        // 3. Verify challenge
        let client_data: CollectedClientData = serde_json::from_str(client_data_json)?;
        if client_data.ty != "webauthn.create" {
            return Err(WebAuthnError::ChallengeNotFound); // generic
        }
        if client_data.challenge != challenge {
            return Err(WebAuthnError::ChallengeNotFound);
        }
        if !self.config.allowed_origins.contains(&client_data.origin) {
            return Err(WebAuthnError::ChallengeNotFound); // generic origin check
        }

        // 4. Verify the challenge exists in the session store and consume it
        let key = format!("webauthn:create:{}:{}", self.config.rp_id, user_id);
        self.session_store.verify_state(&key, challenge, "webauthn-challenge", None).await?;

        // 5. Verify credential_id is not already registered (globally)
        let credentials_read = self.credentials.read().unwrap();
        for (_uid, creds) in credentials_read.iter() {
            for c in creds {
                if c.credential_id == credential_id {
                    return Err(WebAuthnError::CredentialAlreadyExists);
                }
            }
        }
        drop(credentials_read);

        // 6. Register
        let credential = WebAuthnCredential {
            credential_id: credential_id.clone(),
            public_key,
            sign_count: authenticator_data.sign_count,
            label: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let mut credentials_write = self.credentials.write().unwrap();
        credentials_write
            .entry(user_id.to_string())
            .or_default()
            .push(credential.clone());
        drop(credentials_write);

        Ok(credential)
    }

    /// Verify an authentication (assertion) response.
    pub async fn verify_authentication(
        &self,
        user_id: &str,
        challenge: &str,
        authenticator_data: &AuthenticatorData,
        client_data_json: &str,
        credential_id: &[u8],
    ) -> Result<(), WebAuthnError> {
        // 1. rpIdHash check
        let expected = Sha256::digest(self.config.rp_id.as_bytes());
        if authenticator_data.rp_id_hash != expected.into() {
            return Err(WebAuthnError::RpIdHashMismatch {
                expected: URL_SAFE_NO_PAD.encode(expected),
                got: URL_SAFE_NO_PAD.encode(authenticator_data.rp_id_hash),
            });
        }

        // 2. UP must be set (UV is recommended but not strictly required for auth)
        if !authenticator_data.flags.up {
            return Err(WebAuthnError::UserPresenceNotSet);
        }

        // 3. Verify challenge
        let client_data: CollectedClientData = serde_json::from_str(client_data_json)?;
        if client_data.ty != "webauthn.get" {
            return Err(WebAuthnError::ChallengeNotFound);
        }
        if client_data.challenge != challenge {
            return Err(WebAuthnError::ChallengeNotFound);
        }
        if !self.config.allowed_origins.contains(&client_data.origin) {
            return Err(WebAuthnError::ChallengeNotFound);
        }

        // 4. Verify the challenge exists in the session store and consume it
        let key = format!("webauthn:get:{}:{}", self.config.rp_id, user_id);
        self.session_store.verify_state(&key, challenge, "webauthn-challenge", None).await?;

        // 5. Lookup credential + sign count check
        let mut credentials_write = self.credentials.write().unwrap();
        let creds = credentials_write.get_mut(user_id).ok_or(WebAuthnError::CredentialNotFound)?;
        let cred = creds
            .iter_mut()
            .find(|c| c.credential_id == credential_id)
            .ok_or(WebAuthnError::CredentialNotFound)?;

        if authenticator_data.sign_count <= cred.sign_count {
            return Err(WebAuthnError::CredentialNotFound); // replay defense
        }
        cred.sign_count = authenticator_data.sign_count;

        drop(credentials_write);

        // 6. Verify signature (placeholder — real ECDSA in AUT-SOTA-003b)
        verify_signature(&cred.public_key, authenticator_data, client_data_json)?;

        Ok(())
    }

    /// List credentials for a user.
    pub fn list_credentials(&self, user_id: &str) -> Vec<WebAuthnCredential> {
        self.credentials.read().unwrap().get(user_id).cloned().unwrap_or_default()
    }
}

/// Placeholder signature verifier. Real implementation in AUT-SOTA-003b.
///
/// Currently this is a structural check only: it confirms the public key
/// is non-empty. Real ECDSA / RSA-PSS verification against
/// `authenticator_data || SHA256(client_data_json)` lands in AUT-SOTA-003b.
pub fn verify_signature(
    public_key: &[u8],
    _authenticator_data: &AuthenticatorData,
    _client_data_json: &str,
) -> Result<(), WebAuthnError> {
    if public_key.is_empty() {
        return Err(WebAuthnError::CredentialNotFound); // generic
    }
    // Real verify: parse public_key as COSE_Key, then verify
    // ECDSA( SHA256(authenticator_data || SHA256(client_data_json)), signature )
    Ok(())
}

/// Generate 32 random bytes. Delegates to getrandom.
fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes
}

/// Helper to convert a Uuid to a stable user_id string.
pub fn user_id_from_uuid(uuid: Uuid) -> String {
    uuid.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::session_store::InMemorySessionStore;

    fn fixture() -> (WebAuthnVerifier, Arc<InMemorySessionStore>) {
        let store = Arc::new(InMemorySessionStore::new());
        let verifier = WebAuthnVerifier::new(
            WebAuthnConfig::new("auth.example.com", vec!["https://app.example.com".into()]),
            store.clone(),
        );
        (verifier, store)
    }

    fn fake_auth_data(rp_id: &str) -> AuthenticatorData {
        let rp_id_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
        AuthenticatorData {
            rp_id_hash,
            flags: AuthenticatorDataFlags { up: true, uv: true, ..Default::default() },
            sign_count: 1,
        }
    }

    fn client_data(ty: &str, challenge: &str, origin: &str) -> String {
        serde_json::json!({
            "type": ty,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        })
        .to_string()
    }

    #[tokio::test]
    async fn generate_challenge_returns_32_byte_url_safe_b64() {
        let (v, _) = fixture();
        let c = v.generate_challenge("alice", "create").await.unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&c).unwrap().len(), 32);
    }

    #[tokio::test]
    async fn verify_registration_happy_path() {
        let (v, _) = fixture();
        let challenge = v.generate_challenge("alice", "create").await.unwrap();
        let auth = fake_auth_data("auth.example.com");
        let cd = client_data("webauthn.create", &challenge, "https://app.example.com");
        let cred = v
            .verify_registration(
                "alice",
                &challenge,
                &auth,
                &cd,
                b"cred-id".to_vec(),
                b"public-key".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(cred.sign_count, 1);
        assert_eq!(v.list_credentials("alice").len(), 1);
    }

    #[tokio::test]
    async fn verify_registration_rp_id_mismatch_rejected() {
        let (v, _) = fixture();
        let challenge = v.generate_challenge("alice", "create").await.unwrap();
        let auth = fake_auth_data("evil.example.com");
        let cd = client_data("webauthn.create", &challenge, "https://app.example.com");
        let err = v
            .verify_registration(
                "alice",
                &challenge,
                &auth,
                &cd,
                b"cred-id".to_vec(),
                b"public-key".to_vec(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WebAuthnError::RpIdHashMismatch { .. }));
    }

    #[tokio::test]
    async fn verify_registration_no_user_presence_rejected() {
        let (v, _) = fixture();
        let challenge = v.generate_challenge("alice", "create").await.unwrap();
        let mut auth = fake_auth_data("auth.example.com");
        auth.flags.up = false;
        let cd = client_data("webauthn.create", &challenge, "https://app.example.com");
        let err = v
            .verify_registration(
                "alice",
                &challenge,
                &auth,
                &cd,
                b"cred-id".to_vec(),
                b"public-key".to_vec(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WebAuthnError::UserPresenceNotSet));
    }

    #[tokio::test]
    async fn verify_registration_origin_not_allowed() {
        let (v, _) = fixture();
        let challenge = v.generate_challenge("alice", "create").await.unwrap();
        let auth = fake_auth_data("auth.example.com");
        let cd = client_data("webauthn.create", &challenge, "https://evil.example.com");
        let err = v
            .verify_registration(
                "alice",
                &challenge,
                &auth,
                &cd,
                b"cred-id".to_vec(),
                b"public-key".to_vec(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WebAuthnError::ChallengeNotFound));
    }

    #[tokio::test]
    async fn verify_registration_challenge_replay_rejected() {
        let (v, _) = fixture();
        let challenge = v.generate_challenge("alice", "create").await.unwrap();
        let auth = fake_auth_data("auth.example.com");
        let cd = client_data("webauthn.create", &challenge, "https://app.example.com");
        v.verify_registration(
            "alice",
            &challenge,
            &auth,
            &cd,
            b"cred-id".to_vec(),
            b"public-key".to_vec(),
        )
        .await
        .unwrap();
        // Second attempt with same challenge should fail
        let auth2 = AuthenticatorData { sign_count: 2, ..auth };
        let cd2 = client_data("webauthn.create", &challenge, "https://app.example.com");
        let err = v
            .verify_registration(
                "alice",
                &challenge,
                &auth2,
                &cd2,
                b"cred-id-2".to_vec(),
                b"public-key-2".to_vec(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, WebAuthnError::SessionStore(_)));
    }

    #[tokio::test]
    async fn verify_authentication_happy_path_increments_sign_count() {
        let (v, _) = fixture();
        let c1 = v.generate_challenge("alice", "create").await.unwrap();
        let a1 = fake_auth_data("auth.example.com");
        let cd1 = client_data("webauthn.create", &c1, "https://app.example.com");
        v.verify_registration(
            "alice",
            &c1,
            &a1,
            &cd1,
            b"cred-id".to_vec(),
            b"public-key".to_vec(),
        )
        .await
        .unwrap();

        let c2 = v.generate_challenge("alice", "get").await.unwrap();
        let a2 = AuthenticatorData { sign_count: 5, ..a1 };
        let cd2 = client_data("webauthn.get", &c2, "https://app.example.com");
        v.verify_authentication("alice", &c2, &a2, &cd2, b"cred-id").await.unwrap();

        // sign count should now be 5
        let creds = v.list_credentials("alice");
        assert_eq!(creds[0].sign_count, 5);
    }

    #[tokio::test]
    async fn verify_authentication_replay_rejected_by_sign_count() {
        let (v, _) = fixture();
        let c1 = v.generate_challenge("alice", "create").await.unwrap();
        let a1 = fake_auth_data("auth.example.com");
        let cd1 = client_data("webauthn.create", &c1, "https://app.example.com");
        v.verify_registration(
            "alice",
            &c1,
            &a1,
            &cd1,
            b"cred-id".to_vec(),
            b"public-key".to_vec(),
        )
        .await
        .unwrap();

        // First auth succeeds
        let c2 = v.generate_challenge("alice", "get").await.unwrap();
        let a2 = AuthenticatorData { sign_count: 5, ..a1 };
        let cd2 = client_data("webauthn.get", &c2, "https://app.example.com");
        v.verify_authentication("alice", &c2, &a2, &cd2, b"cred-id").await.unwrap();

        // Second auth with sign_count = 5 (equal) should be rejected (replay)
        let c3 = v.generate_challenge("alice", "get").await.unwrap();
        let a3 = AuthenticatorData { sign_count: 5, ..a1 };
        let cd3 = client_data("webauthn.get", &c3, "https://app.example.com");
        let err = v.verify_authentication("alice", &c3, &a3, &cd3, b"cred-id").await.unwrap_err();
        assert!(matches!(err, WebAuthnError::CredentialNotFound));
    }

    #[tokio::test]
    async fn flags_byte_roundtrip() {
        let flags = AuthenticatorDataFlags { up: true, uv: true, be: false, bs: true, at: true, ed: false };
        let byte = flags.to_byte();
        assert_eq!(byte, 0x01 | 0x04 | 0x10 | 0x40);
        let decoded = AuthenticatorDataFlags::from_byte(byte);
        assert_eq!(decoded, flags);
    }

    #[tokio::test]
    async fn auth_data_parse_too_short() {
        let bytes = vec![0u8; 10];
        assert!(AuthenticatorData::parse(&bytes).is_err());
    }
}
