//! # phenotype-authvault-application
//!
//! V20 AUTH cluster step 3/5: Authvault's application layer migrated to the
//! AuthKit workspace as a sub-crate. The application layer is the thin
//! orchestration that wires the [`phenotype_authvault_domain`] ports into
//! a single `AuthService` consumed by the HTTP / gRPC adapters (step 4/5
//! in the AUTH cluster plan).
//!
//! ## What this crate provides
//!
//! - [`AuthService`] — the canonical authentication application service.
//!   Owns the [`Authenticator`], [`PolicyEngine`], and the
//!   [`UserStorage`] + [`SessionStorage`] + [`PasswordHasher`] ports.
//! - Async methods: `register`, `login`, `logout`, `logout_all`,
//!   `get_user`.
//! - Sync methods: `verify_token`, `validate_bearer_token`,
//!   `refresh_token`, `authorize`.
//!
//! ## What this crate does NOT provide
//!
//! - The HTTP / gRPC server (the `app/` layer in the upstream Authvault
//!   repo). That lives in a future step-4/5 migration.
//! - The Postgres / Redis / in-memory adapters. Same — future step.
//!
//! ## Source provenance
//!
//! Lifted from `Authvault/src/application/services.rs` (159 LOC), with
//! one path rewrite: `use crate::domain::...` → `use
//! phenotype_authvault_domain::...`. No logic changes; no API changes.
//!
//! [`AuthService`]: services::AuthService
//! [`Authenticator`]: phenotype_authvault_domain::Authenticator
//! [`PolicyEngine`]: phenotype_authvault_domain::PolicyEngine
//! [`UserStorage`]: phenotype_authvault_domain::UserStorage
//! [`SessionStorage`]: phenotype_authvault_domain::SessionStorage
//! [`PasswordHasher`]: phenotype_authvault_domain::PasswordHasher

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod services;

pub use services::AuthService;
