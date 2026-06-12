//! # phenotype-authvault-adapters
//!
//! Concrete implementations of the outbound port traits defined in
//! [`phenotype_authvault_domain`]. Step 4/5 of the V20 AUTH-cluster
//! canonical-merge pass (see `FLEET_DAG_v3.md` §107 +
//! `V20_CROSSREPO_CANONICAL_AUDIT.md`).
//!
//! ## Modules
//!
//! - [`audit`] — In-memory [`AuditSink`] for emitting domain events.
//! - [`hashers`] — [`PasswordHasher`] implementations (Argon2 default).
//! - [`kms`] — [`KeyManagementService`] trait + a local-process stub.
//! - [`refresh_token`] — In-memory refresh token store.
//! - [`revocation`] — JWT/session revocation list.
//! - [`storage`] — In-memory [`UserStorage`] + session-storage sweep.
//! - [`vault_store`] — File-backed [`SecretVault`] adapter.
//!
//! All adapters depend only on the domain ports and the domain
//! types. They are `Send + Sync` (the auth domain's adapters are
//! usually held in Arc behind an HTTP server), and free of `unsafe`.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod audit;
pub mod hashers;
pub mod kms;
pub mod refresh_token;
pub mod revocation;
pub mod storage;
pub mod vault_store;
