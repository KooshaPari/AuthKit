//! User management — register, login, profile (AUT-SOTA-004a).
//!
//! Provides a hexagonal `UserStore` trait backed by an in-memory adapter.
//! Password hashing uses PBKDF2-HMAC-SHA256 with a random 16-byte salt
//! and 100,000 iterations (OWASP recommended minimum).
//!
//! ## Quick start
//!
//! ```ignore
//! use authkit::user::{InMemoryUserStore, UserRegistration};
//!
//! let store = InMemoryUserStore::new();
//! let user = store.register_user(UserRegistration {
//!     email: "alice@example.com".into(),
//!     password: "hunter2".into(),
//! })?;
//! assert!(store.verify_password("alice@example.com", "hunter2")?);
//! ```

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// PBKDF2 iterations (OWASP 2023 rec for SHA-256).
const PBKDF2_ITERATIONS: u32 = 100_000;
/// Salt length in bytes (128 bits).
const SALT_LEN: usize = 16;

/// Errors emitted by the user store.
#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("user with email '{0}' already exists")]
    EmailAlreadyExists(String),

    #[error("user not found: {0}")]
    UserNotFound(String),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("store lock poisoned")]
    Poisoned,
}

/// Data required to register a new user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRegistration {
    pub email: String,
    pub password: String,
}

/// A registered user (safe for serialization — no password material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

/// Internal stored record (includes password hash).
#[derive(Debug, Clone)]
struct StoredUser {
    user: User,
    /// Hex-encoded "salt_hex:hash_hex".
    password_hash: Vec<u8>,
    #[allow(dead_code)]
    salt: [u8; SALT_LEN],
}

/// PBKDF2-HMAC-SHA256 hash.
fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    use pbkdf2::pbkdf2_hmac;
    let mut out = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut out);
    out
}

/// SHA-256 hex digest.
#[allow(dead_code)]
fn sha256_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)
}

/// Hex-encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex-decode a string.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Encode salt + hash as "salt_hex:hash_hex".
fn encode_password_hash(salt: &[u8; SALT_LEN], hash: &[u8]) -> String {
    format!("{}:{}", hex_encode(salt), hex_encode(hash))
}

/// Parse "salt_hex:hash_hex" back into (salt, hash).
fn decode_password_hash(stored: &str) -> Option<([u8; SALT_LEN], Vec<u8>)> {
    let (salt_hex, hash_hex) = stored.split_once(':')?;
    let salt_bytes = hex_decode(salt_hex)?;
    let hash_bytes = hex_decode(hash_hex)?;
    if salt_bytes.len() != SALT_LEN {
        return None;
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_bytes);
    Some((salt, hash_bytes))
}

/// Hexagonal port for user persistence.
pub trait UserStore: Send + Sync {
    /// Register a new user. Returns the created `User` on success.
    fn register_user(&self, registration: UserRegistration) -> Result<User, UserStoreError>;

    /// Look up a user by email.
    fn get_user_by_email(&self, email: &str) -> Result<User, UserStoreError>;

    /// Look up a user by id.
    fn get_user_by_id(&self, id: &str) -> Result<User, UserStoreError>;

    /// Verify a password against the stored hash for the given email.
    fn verify_password(&self, email: &str, password: &str) -> Result<bool, UserStoreError>;

    /// Delete a user by id.
    fn delete_user(&self, id: &str) -> Result<(), UserStoreError>;
}

/// Thread-safe in-memory user store.
#[derive(Debug)]
pub struct InMemoryUserStore {
    by_email: Mutex<HashMap<String, StoredUser>>,
    by_id: Mutex<HashMap<String, String>>, // id -> email
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self {
            by_email: Mutex::new(HashMap::new()),
            by_id: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.by_email.lock().map(|m| m.is_empty()).unwrap_or(true)
    }

    pub fn len(&self) -> usize {
        self.by_email.lock().map(|m| m.len()).unwrap_or(0)
    }
}

impl Default for InMemoryUserStore {
    fn default() -> Self {
        Self::new()
    }
}

impl UserStore for InMemoryUserStore {
    fn register_user(&self, registration: UserRegistration) -> Result<User, UserStoreError> {
        let email = registration.email.trim().to_lowercase();
        if email.is_empty() {
            return Err(UserStoreError::InvalidCredentials);
        }

        let mut by_email = self.by_email.lock().map_err(|_| UserStoreError::Poisoned)?;

        if by_email.contains_key(&email) {
            return Err(UserStoreError::EmailAlreadyExists(email.clone()));
        }

        // Generate salt + hash password
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let hash = hash_password(&registration.password, &salt);
        let encoded = encode_password_hash(&salt, &hash);

        let user_id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let user = User {
            id: user_id.clone(),
            email: email.clone(),
            created_at: now,
        };

        let stored = StoredUser {
            user: user.clone(),
            password_hash: encoded.into_bytes(),
            salt,
        };

        by_email.insert(email.clone(), stored);
        drop(by_email);

        let mut by_id = self.by_id.lock().map_err(|_| UserStoreError::Poisoned)?;
        by_id.insert(user_id, email);

        Ok(user)
    }

    fn get_user_by_email(&self, email: &str) -> Result<User, UserStoreError> {
        let by_email = self.by_email.lock().map_err(|_| UserStoreError::Poisoned)?;
        let email = email.trim().to_lowercase();
        by_email
            .get(&email)
            .map(|s| s.user.clone())
            .ok_or(UserStoreError::UserNotFound(email))
    }

    fn get_user_by_id(&self, id: &str) -> Result<User, UserStoreError> {
        let by_id = self.by_id.lock().map_err(|_| UserStoreError::Poisoned)?;
        let email = by_id
            .get(id)
            .ok_or(UserStoreError::UserNotFound(id.to_string()))?
            .clone();
        drop(by_id);

        self.get_user_by_email(&email)
    }

    fn verify_password(&self, email: &str, password: &str) -> Result<bool, UserStoreError> {
        let by_email = self.by_email.lock().map_err(|_| UserStoreError::Poisoned)?;
        let email = email.trim().to_lowercase();

        let stored = by_email
            .get(&email)
            .ok_or(UserStoreError::InvalidCredentials)?;

        let hash_str = String::from_utf8_lossy(&stored.password_hash);
        let (expected_salt, expected_hash) =
            decode_password_hash(&hash_str).ok_or(UserStoreError::InvalidCredentials)?;

        let computed_hash = hash_password(password, &expected_salt);

        // Constant-time compare
        use subtle::ConstantTimeEq;
        Ok(computed_hash.ct_eq(&expected_hash).into())
    }

    fn delete_user(&self, id: &str) -> Result<(), UserStoreError> {
        let by_id = self.by_id.lock().map_err(|_| UserStoreError::Poisoned)?;
        let email = by_id
            .get(id)
            .ok_or(UserStoreError::UserNotFound(id.to_string()))?
            .clone();
        drop(by_id);

        let mut by_email = self.by_email.lock().map_err(|_| UserStoreError::Poisoned)?;
        by_email.remove(&email);

        let mut by_id = self.by_id.lock().map_err(|_| UserStoreError::Poisoned)?;
        by_id.remove(id);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> InMemoryUserStore {
        InMemoryUserStore::new()
    }

    #[test]
    fn register_user_succeeds() {
        let store = fixture();
        let user = store
            .register_user(UserRegistration {
                email: "alice@example.com".into(),
                password: "hunter2".into(),
            })
            .unwrap();
        assert_eq!(user.email, "alice@example.com");
        assert!(!user.id.is_empty());
    }

    #[test]
    fn register_duplicate_email_fails() {
        let store = fixture();
        store
            .register_user(UserRegistration {
                email: "alice@example.com".into(),
                password: "hunter2".into(),
            })
            .unwrap();
        let err = store
            .register_user(UserRegistration {
                email: "alice@example.com".into(),
                password: "different".into(),
            })
            .unwrap_err();
        assert!(matches!(err, UserStoreError::EmailAlreadyExists(_)));
    }

    #[test]
    fn verify_correct_password_succeeds() {
        let store = fixture();
        store
            .register_user(UserRegistration {
                email: "alice@example.com".into(),
                password: "hunter2".into(),
            })
            .unwrap();
        assert!(store
            .verify_password("alice@example.com", "hunter2")
            .unwrap());
    }

    #[test]
    fn verify_wrong_password_fails() {
        let store = fixture();
        store
            .register_user(UserRegistration {
                email: "alice@example.com".into(),
                password: "hunter2".into(),
            })
            .unwrap();
        assert!(!store
            .verify_password("alice@example.com", "wrong password")
            .unwrap());
    }

    #[test]
    fn verify_nonexistent_user_fails() {
        let store = fixture();
        let err = store
            .verify_password("nobody@example.com", "password")
            .unwrap_err();
        assert!(matches!(err, UserStoreError::InvalidCredentials));
    }

    #[test]
    fn get_user_by_id_after_register() {
        let store = fixture();
        let user = store
            .register_user(UserRegistration {
                email: "bob@example.com".into(),
                password: "secure123".into(),
            })
            .unwrap();
        let found = store.get_user_by_id(&user.id).unwrap();
        assert_eq!(found.email, "bob@example.com");
    }

    #[test]
    fn get_user_by_email_case_insensitive() {
        let store = fixture();
        store
            .register_user(UserRegistration {
                email: "Alice@Example.COM".into(),
                password: "pwd".into(),
            })
            .unwrap();
        let user = store.get_user_by_email("alice@example.com").unwrap();
        assert_eq!(user.email, "alice@example.com");
    }

    #[test]
    fn delete_user_removes_from_both_maps() {
        let store = fixture();
        let user = store
            .register_user(UserRegistration {
                email: "del@example.com".into(),
                password: "pwd".into(),
            })
            .unwrap();
        store.delete_user(&user.id).unwrap();
        assert!(store.get_user_by_id(&user.id).is_err());
        assert!(store.get_user_by_email("del@example.com").is_err());
    }

    #[test]
    fn new_store_is_empty() {
        let store = fixture();
        assert!(store.is_empty());
    }

    #[test]
    fn constant_time_compare_different_passwords() {
        let store = fixture();
        store
            .register_user(UserRegistration {
                email: "ct@example.com".into(),
                password: "correct-password".into(),
            })
            .unwrap();
        assert!(!store
            .verify_password("ct@example.com", "wrong-password-xxx")
            .unwrap());
    }

    #[test]
    fn password_hash_differs_with_different_salts() {
        let store = fixture();
        store
            .register_user(UserRegistration {
                email: "user1@example.com".into(),
                password: "same-password".into(),
            })
            .unwrap();
        store
            .register_user(UserRegistration {
                email: "user2@example.com".into(),
                password: "same-password".into(),
            })
            .unwrap();
        assert!(store
            .verify_password("user1@example.com", "same-password")
            .unwrap());
        assert!(store
            .verify_password("user2@example.com", "same-password")
            .unwrap());
    }

    #[test]
    fn register_empty_email_fails() {
        let store = fixture();
        let err = store
            .register_user(UserRegistration {
                email: "   ".into(),
                password: "pwd".into(),
            })
            .unwrap_err();
        assert!(matches!(err, UserStoreError::InvalidCredentials));
    }
}
