//! RBAC primitives: [`Role`] and [`Permission`].
//!
//! A `Role` is a named bundle of [`Permission`]s. The `Admin` role has
//! all permissions; `Viewer` has only read-only permissions; `Operator`
//! sits in between. A `Custom` role can carry an arbitrary set of
//! permissions for cases the standard roles don't cover.
//!
//! Permission checks are O(n) over the role's permission set where
//! n is small (typically < 20). If your workload needs O(1) checks,
//! use `Role::has_permission` which short-circuits on first match.

use serde::{Deserialize, Serialize};

use crate::error::{AuthError, Result};

/// RBAC role: a named bundle of [`Permission`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Role {
    /// Full access to every permission.
    Admin,
    /// Read + write access to most resources, no billing.
    Operator,
    /// Read-only access to most resources.
    Viewer,
    /// Custom role with an explicit permission set. The Vec is
    /// sorted + deduped at construction time.
    Custom {
        /// The role's display name (e.g. `"billing_admin"`).
        name: String,
        /// The role's permission set, sorted + deduped.
        permissions: Vec<Permission>,
    },
}

impl Role {
    /// Constructs a `Custom` role with the given name and permissions.
    /// Permissions are sorted + deduped for deterministic equality.
    pub fn custom(name: impl Into<String>, mut permissions: Vec<Permission>) -> Self {
        permissions.sort_by_key(|p| p.sort_key());
        permissions.dedup();
        Self::Custom {
            name: name.into(),
            permissions,
        }
    }

    /// Returns the human-readable role name.
    pub fn name(&self) -> &str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Viewer => "viewer",
            Role::Custom { name, .. } => name,
        }
    }

    /// Returns true if the role grants the given permission.
    pub fn can_access(&self, permission: &Permission) -> bool {
        match self {
            Role::Admin => true,
            Role::Operator => !matches!(permission, Permission::BillingRefund),
            Role::Viewer => permission.is_read_only(),
            Role::Custom { permissions, .. } => permissions.binary_search_by_key(&permission.sort_key(), Permission::sort_key).is_ok(),
        }
    }

    /// Returns true if the role grants the given permission, or
    /// returns a `NotAuthorized` error otherwise. Useful for
    /// request-handler paths that want a single-line guard.
    pub fn check(&self, permission: &Permission) -> Result<()> {
        if self.can_access(permission) {
            Ok(())
        } else {
            Err(AuthError::NotAuthorized {
                role: self.name().to_string(),
                permission: permission.to_string(),
            })
        }
    }
}

/// Scoped permission: a (resource, action) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    // Users
    /// Read user records.
    UsersRead,
    /// Write user records.
    UsersWrite,
    /// Delete user records.
    UsersDelete,
    // Skills
    /// Read skill records.
    SkillsRead,
    /// Write skill records.
    SkillsWrite,
    // Billing
    /// Issue a billing refund.
    BillingRefund,
    /// Read billing records.
    BillingRead,
    // Admin
    /// Manage the fleet / cluster.
    FleetManage,
}

impl Permission {
    /// Convenience constructor for `UsersWrite`.
    #[must_use]
    pub const fn users_write() -> Self {
        Permission::UsersWrite
    }

    /// Convenience constructor for `BillingRefund`.
    #[must_use]
    pub const fn billing_refund() -> Self {
        Permission::BillingRefund
    }

    /// Returns true if the permission is read-only.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        matches!(self, Permission::UsersRead | Permission::SkillsRead | Permission::BillingRead)
    }

    /// Sort key for `binary_search`. Stable across runs.
    #[allow(clippy::missing_const_for_fn)]
    fn sort_key(&self) -> u8 {
        match self {
            Permission::UsersRead => 0,
            Permission::UsersWrite => 1,
            Permission::UsersDelete => 2,
            Permission::SkillsRead => 3,
            Permission::SkillsWrite => 4,
            Permission::BillingRead => 5,
            Permission::BillingRefund => 6,
            Permission::FleetManage => 7,
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Permission::UsersRead => "users:read",
            Permission::UsersWrite => "users:write",
            Permission::UsersDelete => "users:delete",
            Permission::SkillsRead => "skills:read",
            Permission::SkillsWrite => "skills:write",
            Permission::BillingRead => "billing:read",
            Permission::BillingRefund => "billing:refund",
            Permission::FleetManage => "fleet:manage",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_can_access_everything() {
        let r = Role::Admin;
        assert!(r.can_access(&Permission::UsersWrite));
        assert!(r.can_access(&Permission::BillingRefund));
        assert!(r.can_access(&Permission::FleetManage));
    }

    #[test]
    fn viewer_can_only_read() {
        let r = Role::Viewer;
        assert!(r.can_access(&Permission::UsersRead));
        assert!(r.can_access(&Permission::SkillsRead));
        assert!(!r.can_access(&Permission::UsersWrite));
        assert!(!r.can_access(&Permission::BillingRefund));
    }

    #[test]
    fn operator_cannot_refund() {
        let r = Role::Operator;
        assert!(r.can_access(&Permission::UsersWrite));
        assert!(r.can_access(&Permission::BillingRead));
        assert!(!r.can_access(&Permission::BillingRefund));
    }

    #[test]
    fn custom_role_with_explicit_permissions() {
        let r = Role::custom(
            "billing_admin",
            vec![Permission::BillingRead, Permission::BillingRefund],
        );
        assert!(r.can_access(&Permission::BillingRead));
        assert!(r.can_access(&Permission::BillingRefund));
        assert!(!r.can_access(&Permission::UsersWrite));
        assert_eq!(r.name(), "billing_admin");
    }

    #[test]
    fn custom_role_permissions_are_sorted_and_deduped() {
        let r = Role::custom(
            "messy",
            vec![Permission::BillingRefund, Permission::BillingRead, Permission::BillingRead],
        );
        if let Role::Custom { permissions, .. } = r {
            // Sorted ascending by sort_key; dup removed.
            assert_eq!(permissions, vec![Permission::BillingRead, Permission::BillingRefund]);
        } else {
            // Reaching this branch means `Role::custom` failed to
            // construct a `Custom` variant, which would be a crate
            // invariant violation rather than a normal test failure.
            unreachable!("Role::custom should always produce a Custom variant");
        }
    }

    #[test]
    fn check_returns_err_for_denied_permission() {
        let r = Role::Viewer;
        let err = r.check(&Permission::UsersWrite).unwrap_err();
        assert!(matches!(err, AuthError::NotAuthorized { .. }));
    }

    #[test]
    fn check_returns_ok_for_granted_permission() {
        let r = Role::Admin;
        assert!(r.check(&Permission::FleetManage).is_ok());
    }

    #[test]
    fn permission_display_format_is_stable() {
        // The string form is part of the public API (embedded in error
        // messages and JWT claims). Tests guard against accidental
        // reformatting.
        assert_eq!(Permission::UsersWrite.to_string(), "users:write");
        assert_eq!(Permission::BillingRefund.to_string(), "billing:refund");
        assert_eq!(Permission::FleetManage.to_string(), "fleet:manage");
    }
}
