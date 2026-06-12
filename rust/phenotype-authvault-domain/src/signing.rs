//! Asymmetric and symmetric JWT signing key abstraction.
//!
//! FR-AUTHV-017 (GAP-007): supports HS256 (HMAC), RS256 (RSA PKCS#1 / PKCS#8),
//! and ES256 (EC P-256) keys via the `jsonwebtoken` crate.  The `SigningKey`
//! enum drives both `EncodingKey` selection and `DecodingKey` selection, and it
//! pins the `jsonwebtoken::Algorithm` so that the validator **rejects any token
//! whose `alg` header differs** — closing the alg-confusion and `alg=none`
//! attack surfaces.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

use crate::errors::AuthError;

/// Configurable signing key that supports HS256, RS256, and ES256.
///
/// Construct via one of the factory methods; the chosen variant pins the JWT
/// `alg` for both signing and validation.
#[derive(Clone)]
pub enum SigningKey {
    /// HMAC-SHA256 — symmetric secret (bytes).
    Hmac(String),
    /// RSA PKCS#1 v1.5 SHA-256 — PEM-encoded RSA private key for signing,
    /// PEM-encoded RSA public key (or certificate) for verification.
    Rs256 {
        /// PEM-encoded RSA private key (PKCS#1 or PKCS#8).
        private_pem: String,
        /// PEM-encoded RSA public key.
        public_pem: String,
    },
    /// ECDSA P-256 SHA-256 — PEM-encoded EC private key for signing,
    /// PEM-encoded EC public key for verification.
    Es256 {
        /// PEM-encoded EC private key (SEC1 or PKCS#8).
        private_pem: String,
        /// PEM-encoded EC public key.
        public_pem: String,
    },
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningKey::Hmac(_) => write!(f, "SigningKey::Hmac(<redacted>)"),
            SigningKey::Rs256 { .. } => write!(f, "SigningKey::Rs256(<pem>)"),
            SigningKey::Es256 { .. } => write!(f, "SigningKey::Es256(<pem>)"),
        }
    }
}

impl SigningKey {
    /// Construct an HS256 key from a shared secret string.
    pub fn hmac(secret: impl Into<String>) -> Self {
        SigningKey::Hmac(secret.into())
    }

    /// Construct an RS256 key from PEM-encoded private and public key strings.
    pub fn rs256(private_pem: impl Into<String>, public_pem: impl Into<String>) -> Self {
        SigningKey::Rs256 { private_pem: private_pem.into(), public_pem: public_pem.into() }
    }

    /// Construct an ES256 key from PEM-encoded private and public key strings.
    pub fn es256(private_pem: impl Into<String>, public_pem: impl Into<String>) -> Self {
        SigningKey::Es256 { private_pem: private_pem.into(), public_pem: public_pem.into() }
    }

    /// The `jsonwebtoken::Algorithm` this key uses.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            SigningKey::Hmac(_) => Algorithm::HS256,
            SigningKey::Rs256 { .. } => Algorithm::RS256,
            SigningKey::Es256 { .. } => Algorithm::ES256,
        }
    }

    /// Build a `jsonwebtoken::EncodingKey` from this `SigningKey`.
    pub(crate) fn encoding_key(&self) -> Result<EncodingKey, AuthError> {
        match self {
            SigningKey::Hmac(secret) => Ok(EncodingKey::from_secret(secret.as_bytes())),
            SigningKey::Rs256 { private_pem, .. } => {
                EncodingKey::from_rsa_pem(private_pem.as_bytes())
                    .map_err(|e| AuthError::TokenGeneration(format!("RS256 key error: {e}")))
            }
            SigningKey::Es256 { private_pem, .. } => {
                EncodingKey::from_ec_pem(private_pem.as_bytes())
                    .map_err(|e| AuthError::TokenGeneration(format!("ES256 key error: {e}")))
            }
        }
    }

    /// Build a `jsonwebtoken::DecodingKey` from this `SigningKey`.
    pub(crate) fn decoding_key(&self) -> Result<DecodingKey, AuthError> {
        match self {
            SigningKey::Hmac(secret) => Ok(DecodingKey::from_secret(secret.as_bytes())),
            SigningKey::Rs256 { public_pem, .. } => {
                DecodingKey::from_rsa_pem(public_pem.as_bytes())
                    .map_err(|e| AuthError::TokenVerification(format!("RS256 key error: {e}")))
            }
            SigningKey::Es256 { public_pem, .. } => DecodingKey::from_ec_pem(public_pem.as_bytes())
                .map_err(|e| AuthError::TokenVerification(format!("ES256 key error: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;

    #[test]
    fn signing_key_algorithm_is_bound_to_variant() {
        let hmac = SigningKey::hmac("secret");
        let rs256 = SigningKey::rs256("private", "public");
        let es256 = SigningKey::es256("private", "public");

        assert_eq!(hmac.algorithm(), Algorithm::HS256);
        assert_eq!(rs256.algorithm(), Algorithm::RS256);
        assert_eq!(es256.algorithm(), Algorithm::ES256);
    }

    #[test]
    fn signing_key_debug_redacts_hmac_secret() {
        let key = SigningKey::hmac("s3cr3t");
        assert_eq!(format!("{:?}", key), "SigningKey::Hmac(<redacted>)");
    }

    #[test]
    fn signing_key_invalid_rs256_keys_fail_fast() {
        let key = SigningKey::rs256("not-a-private-key", "not-a-public-key");
        assert!(matches!(key.encoding_key(), Err(AuthError::TokenGeneration(_))));
        assert!(matches!(key.decoding_key(), Err(AuthError::TokenVerification(_))));
    }

    #[test]
    fn signing_key_invalid_es256_keys_fail_fast() {
        let key = SigningKey::es256("not-a-private-key", "not-a-public-key");
        assert!(matches!(key.encoding_key(), Err(AuthError::TokenGeneration(_))));
        assert!(matches!(key.decoding_key(), Err(AuthError::TokenVerification(_))));
    }
}
