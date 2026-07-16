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
//! | AUT-004b / FR-003 | Session management | SHIPPED |
//! | AUT-004c / FR-005 | RBAC roles/permissions | SHIPPED |
//! | AUT-004d / FR-004 | Password reset / email verification | SHIPPED |
//! | AUT-004e / FR-006 | Magic-link (passwordless) authentication | SHIPPED |
//! | AUT-004f / FR-007 | API-key authentication for SDK / CLI clients | SHIPPED |

pub mod api_key;
pub mod domain;
pub mod magic_link;
pub mod middleware;
pub mod password_reset;
pub mod rbac;
pub mod session;
pub mod rate_limiter;
pub mod totp;
pub mod user;

pub use api_key::{
    ApiKeyError, ApiKeyResolution, ApiKeyService, ApiKeyStore, ApiKeySummary, InMemoryApiKeyStore,
    IssuedApiKey, API_KEY_PREFIX, KEY_BODY_HEX_CHARS, KEY_ID_HEX_CHARS,
};

pub use domain::session_store::{InMemorySessionStore, SessionStore, SessionStoreError};
pub use magic_link::{
    InMemoryMagicLinkStore, MagicLink, MagicLinkError, MagicLinkService, MagicLinkStore,
    DEFAULT_MAGIC_LINK_TTL_SECS,
};
pub use middleware::pkce_state_session::enforce_pkce_state_session;
pub use rate_limiter::{LimitTier, RateLimitError, RateLimiter};
pub use password_reset::{
    InMemoryTokenStore, PasswordResetError, ResetToken, TokenKind, TokenStore,
};
pub use rbac::{Permission, Role, RoleStore, RoleStoreError};
pub use session::{Session, SessionManager, SessionManagerError};
pub use totp::{TotpAlgorithm, TotpError, TotpSecret};
pub use user::{User, UserStore, UserStoreError};
