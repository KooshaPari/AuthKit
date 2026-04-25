//! Authentication and authorization framework.
//!
//! # Architecture
//!
//! authkit follows hexagonal architecture:
//!
//! - **Domain**: Pure business logic (identity, auth, policy)
//! - **Application**: Use cases and auth services
//! - **Adapters**: JWT, OAuth2, storage, hashers
//! - **Infrastructure**: Cross-cutting concerns (error handling, logging)
//!
//! # Quick Start
//!
//! ```
//! use authkit::{Authenticator, UserId, Role};
//!
//! let auth = Authenticator::new("secret_key");
//! let token = auth.generate_token(&UserId::new(), &[Role::new("admin")]);
//! ```

pub mod adapters;
pub mod application;
pub mod domain;
pub mod infrastructure;

// Re-exports
pub use application::services::AuthService;
pub use domain::auth::Authenticator;
pub use domain::errors::AuthError;
pub use domain::policy::{Condition, Policy, PolicyEffect, PolicyEngine};
pub use domain::{Claims, Permission, Role, Session, SessionId, User, UserId};
pub use infrastructure::error::AuthKitError;

/// Framework version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
