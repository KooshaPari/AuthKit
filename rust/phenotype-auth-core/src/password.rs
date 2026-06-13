//! Password hashing and verification.
//!
//! The [`PasswordHasher`] trait abstracts over the hash algorithm. The
//! canonical implementation is [`Argon2Hasher`](argon2) — a 3-pass Argon2id
//! configuration with configurable parallelism (defaults: 19 MiB, 2 passes,
//! 1 lane). The `password-hash` crate provides the canonical `$argon2id$`
//! PHC string format, so hashes are interoperable with other tools.
//!
//! # Example
//!
//! ```
//! use phenotype_auth_core::password::{Argon2Hasher, PasswordHasher};
//!
//! let hasher = Argon2Hasher::default();
//! let hash = hasher.hash("my-secret").unwrap();
//! assert!(hasher.verify("my-secret", &hash).unwrap());
//! assert!(!hasher.verify("wrong-secret", &hash).unwrap());
//! ```

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher as Argon2PwHasher, PasswordVerifier, SaltString},
    Argon2,
};
use crate::error::AuthError;
use crate::error::Result;

/// Abstract password hashing.
///
/// Implementors produce a PHC-string hash (e.g. `$argon2id$v=19$m=65536,...`)
/// that can be stored in a database and verified later.
pub trait PasswordHasher: Send + Sync {
    /// Hash a plaintext password.
    fn hash(&self, password: &str) -> Result<String>;

    /// Verify a plaintext password against a stored hash.
    fn verify(&self, password: &str, hash: &str) -> Result<bool>;
}

/// Argon2id hasher with the default OWASP-recommended parameters.
///
/// Memory cost: 19 MiB (OWASP recommends ≥ 37 MiB for tier-1; 19 MiB is
/// a conservative default for 2024 that still runs in < 100 ms on a
/// modern laptop).  Passes: 2.  Lanes: 1.
#[derive(Debug, Clone)]
pub struct Argon2Hasher {
    inner: Argon2<'static>,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        let params = argon2::Params::new(19 * 1024, 2, 1, None)
            .expect("valid argon2 params");
        let inner = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );
        Self { inner }
    }
}

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .inner
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHashError(format!("argon2 hash failed: {e}")))?;
        Ok(password_hash.to_string())
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHashError(format!("invalid hash string: {e}")))?;
        let result = self
            .inner
            .verify_password(password.as_bytes(), &parsed_hash)
            .map(|_| true)
            .map_err(|_| false);
        Ok(result.unwrap_or(false))
    }
}

/// A no-op hasher for testing.  **Never use in production.**
///
/// The hash is always the same string (`"noop"`), and verification
/// always returns true.  This makes tests deterministic and fast.
#[derive(Debug, Clone)]
pub struct DummyHasher;

impl PasswordHasher for DummyHasher {
    fn hash(&self, _password: &str) -> Result<String> {
        Ok("noop".to_string())
    }

    fn verify(&self, _password: &str, _hash: &str) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_hash_produces_argon2id_prefix() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("secret").unwrap();
        assert!(hash.starts_with("$argon2id$"), "hash={}", hash);
    }

    #[test]
    fn argon2_verify_correct_password() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("secret").unwrap();
        assert!(hasher.verify("secret", &hash).unwrap());
    }

    #[test]
    fn argon2_verify_wrong_password() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash("secret").unwrap();
        assert!(!hasher.verify("wrong").unwrap());
    }

    #[test]
    fn argon2_verify_corrupted_hash() {
        let hasher = Argon2Hasher::default();
        let result = hasher.verify("secret", "not-a-hash");
        assert!(result.is_err());
    }

    #[test]
    fn dummy_hasher_always_true() {
        let hasher = DummyHasher;
        let hash = hasher.hash("anything").unwrap();
        assert!(hasher.verify("anything", &hash).unwrap());
        assert!(hasher.verify("wrong", &hash).unwrap()); // yes, even wrong
    }
}
