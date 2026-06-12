//! User identity: [`User`] and [`UserId`].
//!
//! A `User` is the canonical authenticated identity in the Phenotype
//! ecosystem. It carries:
//! - a `UUIDv4` identifier ([`UserId`])
//! - an email (unique within a tenant)
//! - a human-readable display name
//! - an RBAC [`Role`](crate::Role)
//!
//! The struct is `Clone + PartialEq + Eq + Hash + Serialize + Deserialize`
//! so it can be embedded in JWT claims, JSON Web Tokens, or any other
//! serialization format downstream consumers want to use.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AuthError, Result};
use crate::role::Role;

/// UUIDv4-backed user identifier.
///
/// Cheap to clone (16 bytes), hash, and compare. Implements `Display`
/// (so it can be embedded in error messages) and `FromStr` (so it can
/// be parsed from a header or env var).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(Uuid);

impl UserId {
    /// Generates a new random UUIDv4-backed user ID.
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wraps an existing `Uuid` as a `UserId`.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Parses a `UserId` from its canonical string form.
    pub fn parse(s: &str) -> Result<Self> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|_| AuthError::InvalidUserId(s.to_string()))
    }

    /// Returns the inner `Uuid`.
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for UserId {
    type Err = AuthError;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Authenticated identity: id + email + display name + role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    id: UserId,
    email: String,
    display_name: String,
    role: Role,
}

impl User {
    /// Constructs a new `User`. No validation is performed at this layer
    /// (caller is responsible for ensuring the email is well-formed
    /// and the role is appropriate).
    pub const fn new(id: UserId, email: String, display_name: String, role: Role) -> Self {
        Self {
            id,
            email,
            display_name,
            role,
        }
    }

    /// Returns the user's `UUIDv4` ID.
    pub const fn id(&self) -> UserId {
        self.id
    }

    /// Returns the user's email.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns the user's display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the user's RBAC role.
    pub const fn role(&self) -> &Role {
        &self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_round_trips_through_display_and_from_str() {
        let id = UserId::new_v4();
        let s = id.to_string();
        let parsed = UserId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn user_id_parse_rejects_garbage() {
        let err = UserId::parse("not-a-uuid").unwrap_err();
        assert!(matches!(err, AuthError::InvalidUserId(_)));
    }

    #[test]
    fn user_id_is_16_bytes() {
        // UUIDv4 is 16 bytes — invariant for FFI size computations.
        assert_eq!(std::mem::size_of::<UserId>(), 16);
    }

    #[test]
    fn user_exposes_all_fields() {
        let id = UserId::new_v4();
        let u = User::new(
            id,
            "koosha@phenotype.dev".into(),
            "Koosha Pari".into(),
            Role::Admin,
        );
        assert_eq!(u.id(), id);
        assert_eq!(u.email(), "koosha@phenotype.dev");
        assert_eq!(u.display_name(), "Koosha Pari");
        assert_eq!(*u.role(), Role::Admin);
    }

    #[test]
    fn user_serializes_to_json() {
        let u = User::new(
            UserId::new_v4(),
            "a@b.c".into(),
            "A B".into(),
            Role::Viewer,
        );
        let json = serde_json::to_string(&u).unwrap();
        // Round-trip back to the same struct.
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }
}
