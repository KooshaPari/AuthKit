//! AuthKit: canonical Rust auth boundary.
//!
//! This crate is the successor to the archived `Authvault` repository.
//! It absorbs the GAP features that were developed in `Authvault` worktrees
//! but never merged:
//!
//! - FR-AUTHV-018 — PKCE state→session binding (originally GAP-008)
//!
//! ## FR Status
//!
//! | FR | Area | Status |
//! |----|------|--------|
//! | FR-AUTHV-018 | PKCE state→session binding | SHIPPED |
//! | AUT-SOTA-001 | OIDC Discovery + JWKS | SHIPPED |
//! | AUT-SOTA-002 | TOTP / HOTP (RFC 6238 / 4226) | SHIPPED |
//! | AUT-SOTA-003 | WebAuthn challenge/assertion | SHIPPED |
//! | AUT-004a / FR-001 | User registration | SHIPPED |
//! | AUT-004a / FR-002 | Login (email/password) | SHIPPED |

pub mod domain;
pub mod middleware;
pub mod totp;
pub mod user;

pub use domain::session_store::{InMemorySessionStore, SessionStore, SessionStoreError};
pub use middleware::pkce_state_session::enforce_pkce_state_session;
pub use totp::{TotpAlgorithm, TotpError, TotpSecret};
pub use user::{User, UserStore, UserStoreError};