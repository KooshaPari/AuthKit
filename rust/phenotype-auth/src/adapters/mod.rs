//! Adapters layer.

pub mod hashers;
pub mod storage;

// Re-exports
pub use hashers::{Argon2Hasher, BcryptHasher};
pub use storage::InMemoryUserStorage;
