//! Authvault domain layer (V20 AUTH cluster step 2/5).
//!
//! The pure auth-domain logic migrated from the standalone
//! `Authvault` repo into the `AuthKit` workspace. The repository
//! `Authvault/` is a hexagonal architecture split into `domain`,
//! `application`, `adapters`, and `app`. This sub-crate owns the
//! `domain/` slice only — pure functions and traits, no
//! `tokio`/`axum`/`redis`/`tokio-postgres` dependencies.
//!
//! # Sub-modules
//!
//! - [`auth`] — the top-level `Authenticator` trait + `AuthMethod` /
//!   `Claims` types. Combines the lower-level modules to issue /
//!   validate / revoke tokens.
//! - [`errors`] — `AuthError`, `VaultError`, and other domain-level
//!   error enums (the `thiserror`-derived ones; the I/O errors stay
//!   in adapters).
//! - [`identity`] — `User`, `UserId`, `Role`, `Permission` and the
//!   constructors.
//! - [`pkce`] — RFC 7636 Proof Key for Code Exchange (PKCE) primitives.
//! - [`policy`] — authorization-policy evaluation (e.g. role
//!   permission checks).
//! - [`ports`] — `AuditSink`, `KeyManagementService`,
//!   `PasswordHasher`, `RefreshTokenStore`, `RevocationStore`,
//!   `SessionStorage`, `UserStorage` traits. Implementations live
//!   in adapters (downstream).
//! - [`session`] — `Session`, `SessionId`, lifecycle.
//! - [`session_store`] — in-memory `SessionStore` for tests
//!   (production uses an adapter).
//! - [`signing`] — `SigningKey` wrapper + helpers.
//! - [`vault`] — `VaultEntry`, secret encryption / decryption
//!   (chacha20poly1305 + zeroize).
//!
//! # Migration provenance
//!
//! All 11 files lifted from `Authvault/src/domain/` and pasted
//! verbatim (the V20 migration rewrites only the 5
//! `crate::domain::` import paths and the 2 doc-comment
//! `crate::adapters::` references to be sub-crate-friendly).
//!
//! # Examples
//!
//! ```no_run
//! use phenotype_authvault_domain::errors::AuthError;
//! use phenotype_authvault_domain::identity::{User, UserId, Role};
//!
//! let user = User::new(UserId::random(), "alice".to_string(), Role::Admin);
//! assert!(matches!(user.role(), Role::Admin));
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod auth;
pub mod errors;
pub mod identity;
pub mod pkce;
pub mod policy;
pub mod ports;
pub mod session;
pub mod session_store;
pub mod signing;
pub mod vault;

// Re-exports (mirroring Authvault's `src/domain/mod.rs`).
pub use auth::{AuthMethod, Authenticator, Claims};
pub use errors::AuthError;
pub use identity::{Permission, Role, User, UserId};
pub use pkce::{CodeChallenge, CodeVerifier, OAuthState};
pub use policy::{Condition, Policy, PolicyEffect, PolicyEngine};
pub use ports::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, PasswordHasher, RefreshTokenStore,
    RevocationStore, SessionStorage, UserStorage,
};
pub use session::{Session, SessionId};
pub use session_store::{InMemorySessionStore, SessionStore, SessionStoreError};
pub use signing::SigningKey;
pub use vault::{EncryptedBlob, SecretVault, VaultEntry, VaultError, VaultKey};
