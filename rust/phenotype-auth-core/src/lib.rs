//! # phenotype-auth-core
//!
//! Canonical auth domain model for the Phenotype ecosystem (AuthKit).
//!
//! This crate defines the **single source of truth** for the five primitives
//! every Pheno* binary needs:
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`User`] | Authenticated identity (id, email, `display_name`, role) |
//! | [`UserId`] | UUIDv4-backed identifier (`Display` + `FromStr`) |
//! | [`Role`] | RBAC role: Admin, Operator, Viewer, Custom |
//! | [`Permission`] | Scoped permission: Resource × Action |
//! | [`Session`] | Time-bounded active session with renew/extend |
//! | [`Token`] | Opaque token with redaction + sign/verify round-trip |
//!
//! The crate is dependency-light (std + sha2 + hex + chrono + serde + uuid +
//! tracing) so it can be embedded in `no_std`-adjacent contexts and exposed
//! via FFI bindings (Python via PyO3, TS via napi-rs, Go via cgo, etc.).
//!
//! ## Build info
//!
//! The crate version, git SHA, build profile, and target triple are sourced
//! from `BuildInfo` (inlined here; the upstream `phenotype-build-info` crate
//! is not a dep of this sub-crate).
//!
//! ## Example
//!
//! ```
//! use phenotype_auth_core::{Role, Permission, User, UserId};
//!
//! let admin = User::new(
//!     UserId::new_v4(),
//!     "koosha@phenotype.dev".into(),
//!     "Koosha Pari".into(),
//!     Role::Admin,
//! );
//! // Admin has access to everything, including billing refunds.
//! assert!(admin.role().can_access(&Permission::billing_refund()));
//!
//! // A Viewer can access read-only resources but not billing refunds.
//! let viewer = User::new(
//!     UserId::new_v4(),
//!     "reader@phenotype.dev".into(),
//!     "Read-only user".into(),
//!     Role::Viewer,
//! );
//! assert!(!viewer.role().can_access(&Permission::billing_refund()));
//! ```

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod health;
pub mod role;
pub mod session;
pub mod token;
pub mod user;

pub use error::AuthError;
pub use health::{auth_health, version_only_health, HealthSnapshot};
pub use role::{Permission, Role};
pub use session::{Session, SessionId};
pub use token::Token;
pub use user::{User, UserId};

/// A minimal build-info snapshot, inlined from the upstream
/// `phenotype-build-info` crate so this sub-crate has no external build-info
/// dependency. The fields match the upstream shape one-for-one so callers
/// can convert between the two with a trivial copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BuildInfo {
    /// Package version (from `env!("CARGO_PKG_VERSION")`).
    pub version: &'static str,
    /// Short git SHA, or `"unknown"` if `PHENOTYPE_GIT_SHA` is unset.
    pub git_sha: &'static str,
    /// Build profile name (`"debug"` or `"release"`).
    pub build_profile: &'static str,
    /// Rust target triple (from `env!("PHENOTYPE_TARGET")`).
    pub target_triple: &'static str,
}

impl core::fmt::Display for BuildInfo {
    /// Formats as `"<version> (<profile> <target>, git <sha>)"`, e.g.
    /// `"0.1.0 (debug x86_64-unknown-linux-gnu, git deadbeefcaf0)"`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} ({} {}, git {})",
            self.version, self.build_profile, self.target_triple, self.git_sha
        )
    }
}

/// Build a [`BuildInfo`] snapshot. Const fn, no allocation.
pub const fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: match option_env!("PHENOTYPE_GIT_SHA") {
            Some(sha) => sha,
            None => "unknown",
        },
        build_profile: if cfg!(debug_assertions) { "debug" } else { "release" },
        target_triple: env!("PHENOTYPE_TARGET"),
    }
}

/// Canonical version string. Sourced from the crate's `[package].version`
/// at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
