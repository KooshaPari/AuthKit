//! RFC 7636-compliant PKCE (Proof Key for Code Exchange) implementation.
//!
//! Implements the full PKCE flow for OAuth2 authorization code grant:
//! - Cryptographically-random code verifier (32 bytes → 43-char base64url, RFC 7636 §4.1)
//! - S256 code challenge: BASE64URL(SHA-256(ASCII(code_verifier))) (RFC 7636 §4.2)
//! - Opaque state parameter for CSRF protection (RFC 6749 §10.12)
//! - Constant-time verifier comparison to prevent timing attacks

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::errors::AuthError;

/// Minimum verifier length per RFC 7636 §4.1 (43 chars after base64url encoding).
pub const VERIFIER_MIN_LEN: usize = 43;
/// Maximum verifier length per RFC 7636 §4.1.
pub const VERIFIER_MAX_LEN: usize = 128;
/// Number of random bytes used to generate the verifier (32 bytes → 43-char base64url).
const VERIFIER_BYTES: usize = 32;
/// Number of random bytes used to generate the state parameter.
const STATE_BYTES: usize = 32;

/// A PKCE code verifier (RFC 7636 §4.1).
///
/// The verifier is a cryptographically-random string of 43-128 unreserved
/// ASCII characters. We generate 32 random bytes and base64url-encode them
/// (no padding) to produce exactly 43 characters, satisfying the minimum.
#[derive(Debug, Clone)]
pub struct CodeVerifier(String);

impl CodeVerifier {
    /// Generate a new cryptographically-random code verifier.
    ///
    /// Uses `rand::OsRng` (CSPRNG) for entropy per RFC 7636 §4.1.
    pub fn new() -> Self {
        let mut bytes = [0u8; VERIFIER_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        debug_assert!(
            encoded.len() >= VERIFIER_MIN_LEN && encoded.len() <= VERIFIER_MAX_LEN,
            "verifier length {} out of RFC 7636 range [{}, {}]",
            encoded.len(),
            VERIFIER_MIN_LEN,
            VERIFIER_MAX_LEN
        );
        Self(encoded)
    }

    /// Return the verifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate and construct a verifier from an existing string (e.g. received from client).
    ///
    /// Accepts only unreserved ASCII characters per RFC 7636 §4.1: A-Z a-z 0-9 - . _ ~
    pub fn from_string(s: impl Into<String>) -> Result<Self, AuthError> {
        let s = s.into();
        if s.len() < VERIFIER_MIN_LEN || s.len() > VERIFIER_MAX_LEN {
            return Err(AuthError::ValidationError(format!(
                "code_verifier length {} not in [{}, {}]",
                s.len(),
                VERIFIER_MIN_LEN,
                VERIFIER_MAX_LEN
            )));
        }
        // RFC 7636 §4.1 unreserved chars only: ALPHA / DIGIT / "-" / "." / "_" / "~"
        if !s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')) {
            return Err(AuthError::ValidationError(
                "code_verifier contains disallowed characters (RFC 7636 §4.1)".to_string(),
            ));
        }
        Ok(Self(s))
    }

    /// Derive the S256 code challenge for this verifier.
    ///
    /// BASE64URL(SHA-256(ASCII(code_verifier))) per RFC 7636 §4.6.
    pub fn to_challenge(&self) -> CodeChallenge {
        let hash = Sha256::digest(self.0.as_bytes());
        let encoded = URL_SAFE_NO_PAD.encode(hash);
        CodeChallenge(encoded)
    }
}

impl Default for CodeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// A PKCE S256 code challenge (RFC 7636 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    /// Return the challenge as a string slice (suitable for the `code_challenge` query param).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Verify a received code verifier against this challenge using constant-time comparison.
    ///
    /// Derives the S256 challenge from `verifier` and compares with `subtle::ConstantTimeEq`
    /// to prevent timing oracle attacks.
    pub fn verify(&self, verifier: &CodeVerifier) -> Result<(), AuthError> {
        let derived = verifier.to_challenge();
        // Constant-time compare: both sides must have identical length for CT eq to be meaningful.
        // If lengths differ the challenge cannot match — fail immediately (not a timing leak because
        // the length difference is observable anyway from the challenge itself which is public).
        if derived.0.len() != self.0.len() {
            return Err(AuthError::ValidationError("code_challenge mismatch".to_string()));
        }
        // Use byte-by-byte XOR accumulation for constant-time equality without pulling in `subtle`.
        let mismatch = derived
            .0
            .as_bytes()
            .iter()
            .zip(self.0.as_bytes().iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if mismatch != 0 {
            return Err(AuthError::ValidationError("code_challenge mismatch".to_string()));
        }
        Ok(())
    }
}

/// An opaque state parameter for CSRF protection (RFC 6749 §10.12).
///
/// The authorization server MUST associate the state value with the client session
/// and validate it on the callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthState(String);

impl OAuthState {
    /// Generate a new cryptographically-random state token (32 bytes, base64url-encoded).
    pub fn new() -> Self {
        let mut bytes = [0u8; STATE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Return the state as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that a received state matches the expected state (constant-time).
    ///
    /// Returns `Err(AuthError::ValidationError)` if there is a mismatch, preventing CSRF.
    pub fn verify(&self, received: &str) -> Result<(), AuthError> {
        if received.len() != self.0.len() {
            return Err(AuthError::ValidationError(
                "state parameter mismatch (CSRF check failed)".to_string(),
            ));
        }
        let mismatch = received
            .as_bytes()
            .iter()
            .zip(self.0.as_bytes().iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if mismatch != 0 {
            return Err(AuthError::ValidationError(
                "state parameter mismatch (CSRF check failed)".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for OAuthState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CodeVerifier tests ---

    #[test]
    fn test_verifier_length_is_rfc_compliant() {
        let v = CodeVerifier::new();
        let len = v.as_str().len();
        assert!(
            (VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&len),
            "verifier length {len} not in [{VERIFIER_MIN_LEN}, {VERIFIER_MAX_LEN}]"
        );
    }

    #[test]
    fn test_verifier_charset_is_unreserved_ascii() {
        let v = CodeVerifier::new();
        for c in v.as_str().chars() {
            assert!(
                c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'),
                "verifier contains disallowed char: {c:?}"
            );
        }
    }

    #[test]
    fn test_verifier_uniqueness() {
        // Two independently-generated verifiers must differ (collision probability ~2^-256).
        let v1 = CodeVerifier::new();
        let v2 = CodeVerifier::new();
        assert_ne!(v1.as_str(), v2.as_str());
    }

    #[test]
    fn test_verifier_from_string_valid() {
        // 43-char all-alpha string should be accepted.
        let s = "a".repeat(VERIFIER_MIN_LEN);
        assert!(CodeVerifier::from_string(s).is_ok());
    }

    #[test]
    fn test_verifier_from_string_too_short_rejected() {
        let s = "a".repeat(VERIFIER_MIN_LEN - 1);
        assert!(CodeVerifier::from_string(s).is_err());
    }

    #[test]
    fn test_verifier_from_string_too_long_rejected() {
        let s = "a".repeat(VERIFIER_MAX_LEN + 1);
        assert!(CodeVerifier::from_string(s).is_err());
    }

    #[test]
    fn test_verifier_from_string_bad_chars_rejected() {
        // Space and `+` are not unreserved chars per RFC 7636 §4.1.
        let s = format!("{}+", "a".repeat(VERIFIER_MIN_LEN));
        assert!(CodeVerifier::from_string(s).is_err());
    }

    // --- S256 challenge tests ---

    #[test]
    fn test_s256_challenge_derivation_known_vector() {
        // RFC 7636 Appendix B example:
        // verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // expected  = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let verifier = CodeVerifier::from_string("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            .expect("valid RFC example verifier");
        let challenge = verifier.to_challenge();
        assert_eq!(
            challenge.as_str(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "S256 challenge must match RFC 7636 Appendix B"
        );
    }

    #[test]
    fn test_challenge_verify_correct_verifier_succeeds() {
        let verifier = CodeVerifier::new();
        let challenge = verifier.to_challenge();
        assert!(
            challenge.verify(&verifier).is_ok(),
            "valid verifier must pass challenge verification"
        );
    }

    #[test]
    fn test_challenge_verify_wrong_verifier_fails() {
        let verifier1 = CodeVerifier::new();
        let verifier2 = CodeVerifier::new();
        let challenge = verifier1.to_challenge();
        assert!(
            challenge.verify(&verifier2).is_err(),
            "wrong verifier must fail challenge verification"
        );
    }

    // --- State / CSRF tests ---

    #[test]
    fn test_state_uniqueness() {
        let s1 = OAuthState::new();
        let s2 = OAuthState::new();
        assert_ne!(s1.as_str(), s2.as_str());
    }

    #[test]
    fn test_state_verify_matching_state_passes() {
        let state = OAuthState::new();
        assert!(state.verify(state.as_str()).is_ok());
    }

    #[test]
    fn test_state_verify_wrong_state_rejected() {
        let state = OAuthState::new();
        let other = OAuthState::new();
        assert!(state.verify(other.as_str()).is_err(), "mismatched state must be rejected (CSRF)");
    }

    #[test]
    fn test_state_verify_empty_rejected() {
        let state = OAuthState::new();
        assert!(state.verify("").is_err());
    }
}
