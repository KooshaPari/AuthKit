//! Domain layer - pure authentication and authorization logic.

pub mod auth;
pub mod errors;
pub mod identity;
pub mod policy;
pub mod ports;
pub mod session;

// Re-exports
pub use auth::{AuthMethod, Authenticator, Claims};
pub use errors::AuthError;
pub use identity::{Permission, Role, User, UserId};
pub use policy::{Condition, Policy, PolicyEffect, PolicyEngine};
pub use ports::{PasswordHasher, SessionStorage, UserStorage};
pub use session::{Session, SessionId};
