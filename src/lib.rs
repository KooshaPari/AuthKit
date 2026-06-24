//! AuthKit: canonical Rust auth boundary.
//!
//! This crate is the successor to the archived `Authvault` repository.
//! It absorbs the GAP features that were developed in `Authvault` worktrees
//! but never merged:
//!
//! - FR-AUTHV-018 — PKCE state→session binding (originally GAP-008)
//!
//! The crate is currently a single hexagonal port (`SessionStore`) and a
//! tower middleware (`enforce_pkce_state_session`) that uses it. Future
//! AuthKit units (AUT-SOTA-001..) will add: RS256/ES256 signing key
//! rotation, OIDC discovery, WebAuthn, TOTP, KMS-backed secrets, DPoP.

pub mod domain;
pub mod middleware;

pub use domain::session_store::{InMemorySessionStore, SessionStore, SessionStoreError};
pub use middleware::pkce_state_session::enforce_pkce_state_session;
