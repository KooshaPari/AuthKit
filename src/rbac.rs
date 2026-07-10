//! RBAC — Role-based access control (AUT-SOTA-004c).
//!
//! Provides a `RoleStore` trait that maps users to roles and roles to
//! permissions, with an in-memory adapter for testing and development.
//!
//! ## Quick start
//!
//! ```ignore
//! use authkit::rbac::{InMemoryRoleStore, Role, Permission};
//!
//! let store = InMemoryRoleStore::new();
//! store.assign_role("user-1", Role::Admin)?;
//! assert!(store.user_has_permission("user-1", Permission::DeleteUser)?);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use thiserror::Error;

/// Errors emitted by the role store.
#[derive(Debug, Error)]
pub enum RoleStoreError {
    #[error("store lock poisoned")]
    Poisoned,

    #[error("role '{0}' not found")]
    RoleNotFound(String),
}

/// Pre-defined roles in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Super-admin: all permissions.
    Admin,
    /// Standard authenticated user.
    User,
    /// Read-only viewer.
    Viewer,
    /// Custom named role.
    Custom(String),
}

impl Role {
    /// The string representation of this role.
    pub fn as_str(&self) -> &str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
            Role::Viewer => "viewer",
            Role::Custom(name) => name.as_str(),
        }
    }

    /// Parse a string into a Role, defaulting to `Custom`.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" => Role::Admin,
            "user" => Role::User,
            "viewer" => Role::Viewer,
            custom => Role::Custom(custom.to_string()),
        }
    }
}

/// Pre-defined permissions in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // User management
    CreateUser,
    ReadUser,
    UpdateUser,
    DeleteUser,
    // Session management
    ManageSessions,
    // Role management
    ManageRoles,
    AssignRoles,
    // Content
    ReadContent,
    CreateContent,
    UpdateContent,
    DeleteContent,
    // Custom
    Custom(String),
}

impl Permission {
    /// The string representation of this permission.
    pub fn as_str(&self) -> &str {
        match self {
            Permission::CreateUser => "create_user",
            Permission::ReadUser => "read_user",
            Permission::UpdateUser => "update_user",
            Permission::DeleteUser => "delete_user",
            Permission::ManageSessions => "manage_sessions",
            Permission::ManageRoles => "manage_roles",
            Permission::AssignRoles => "assign_roles",
            Permission::ReadContent => "read_content",
            Permission::CreateContent => "create_content",
            Permission::UpdateContent => "update_content",
            Permission::DeleteContent => "delete_content",
            Permission::Custom(name) => name.as_str(),
        }
    }
}

/// Default permission set for each built-in role.
fn default_permissions_for_role(role: &Role) -> HashSet<Permission> {
    match role {
        Role::Admin => {
            let mut p = HashSet::new();
            p.insert(Permission::CreateUser);
            p.insert(Permission::ReadUser);
            p.insert(Permission::UpdateUser);
            p.insert(Permission::DeleteUser);
            p.insert(Permission::ManageSessions);
            p.insert(Permission::ManageRoles);
            p.insert(Permission::AssignRoles);
            p.insert(Permission::ReadContent);
            p.insert(Permission::CreateContent);
            p.insert(Permission::UpdateContent);
            p.insert(Permission::DeleteContent);
            p
        }
        Role::User => {
            let mut p = HashSet::new();
            p.insert(Permission::ReadUser);
            p.insert(Permission::UpdateUser);
            p.insert(Permission::ReadContent);
            p.insert(Permission::CreateContent);
            p.insert(Permission::UpdateContent);
            p
        }
        Role::Viewer => {
            let mut p = HashSet::new();
            p.insert(Permission::ReadUser);
            p.insert(Permission::ReadContent);
            p
        }
        Role::Custom(_) => HashSet::new(),
    }
}

/// A permission check result: either allowed or denied with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessResult {
    Granted,
    Denied(String),
}

/// Hexagonal port for role-based access control.
pub trait RoleStore: Send + Sync {
    /// Assign a role to a user. Replaces any existing role.
    fn assign_role(&self, user_id: &str, role: Role) -> Result<(), RoleStoreError>;

    /// Get the role assigned to a user.
    fn get_role(&self, user_id: &str) -> Result<Option<Role>, RoleStoreError>;

    /// Remove a user's role assignment.
    fn remove_role(&self, user_id: &str) -> Result<(), RoleStoreError>;

    /// Grant an additional permission to a user (overlays their role).
    fn grant_permission(&self, user_id: &str, permission: Permission)
        -> Result<(), RoleStoreError>;

    /// Revoke an additional permission from a user.
    fn revoke_permission(
        &self,
        user_id: &str,
        permission: &Permission,
    ) -> Result<(), RoleStoreError>;

    /// Check whether a user has a specific permission.
    fn user_has_permission(
        &self,
        user_id: &str,
        permission: &Permission,
    ) -> Result<bool, RoleStoreError>;

    /// Check access and return a structured result.
    fn check_access(
        &self,
        user_id: &str,
        permission: Permission,
    ) -> Result<AccessResult, RoleStoreError>;

    /// List all users with a given role.
    fn list_users_with_role(&self, role: &Role) -> Result<Vec<String>, RoleStoreError>;
}

/// Thread-safe in-memory role store.
#[derive(Debug)]
pub struct InMemoryRoleStore {
    user_roles: Mutex<HashMap<String, Role>>,
    user_permissions: Mutex<HashMap<String, HashSet<Permission>>>,
}

impl InMemoryRoleStore {
    pub fn new() -> Self {
        Self {
            user_roles: Mutex::new(HashMap::new()),
            user_permissions: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.user_roles.lock().map(|m| m.is_empty()).unwrap_or(true)
    }

    pub fn user_count(&self) -> usize {
        self.user_roles.lock().map(|m| m.len()).unwrap_or(0)
    }
}

impl Default for InMemoryRoleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleStore for InMemoryRoleStore {
    fn assign_role(&self, user_id: &str, role: Role) -> Result<(), RoleStoreError> {
        let mut roles = self
            .user_roles
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        roles.insert(user_id.to_string(), role);
        Ok(())
    }

    fn get_role(&self, user_id: &str) -> Result<Option<Role>, RoleStoreError> {
        let roles = self
            .user_roles
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        Ok(roles.get(user_id).cloned())
    }

    fn remove_role(&self, user_id: &str) -> Result<(), RoleStoreError> {
        let mut roles = self
            .user_roles
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        roles.remove(user_id);
        let mut perms = self
            .user_permissions
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        perms.remove(user_id);
        Ok(())
    }

    fn grant_permission(
        &self,
        user_id: &str,
        permission: Permission,
    ) -> Result<(), RoleStoreError> {
        let mut perms = self
            .user_permissions
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        perms
            .entry(user_id.to_string())
            .or_default()
            .insert(permission);
        Ok(())
    }

    fn revoke_permission(
        &self,
        user_id: &str,
        permission: &Permission,
    ) -> Result<(), RoleStoreError> {
        let mut perms = self
            .user_permissions
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        if let Some(set) = perms.get_mut(user_id) {
            set.remove(permission);
        }
        Ok(())
    }

    fn user_has_permission(
        &self,
        user_id: &str,
        permission: &Permission,
    ) -> Result<bool, RoleStoreError> {
        let roles = self
            .user_roles
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        let perms = self
            .user_permissions
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;

        // Check role-based default permissions
        if let Some(role) = roles.get(user_id) {
            let defaults = default_permissions_for_role(role);
            if defaults.contains(permission) {
                return Ok(true);
            }
        }

        // Check user-specific grants
        if let Some(extra) = perms.get(user_id) {
            if extra.contains(permission) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn check_access(
        &self,
        user_id: &str,
        permission: Permission,
    ) -> Result<AccessResult, RoleStoreError> {
        if self.user_has_permission(user_id, &permission)? {
            Ok(AccessResult::Granted)
        } else {
            Ok(AccessResult::Denied(format!(
                "user {user_id} lacks permission {}",
                permission.as_str()
            )))
        }
    }

    fn list_users_with_role(&self, role: &Role) -> Result<Vec<String>, RoleStoreError> {
        let roles = self
            .user_roles
            .lock()
            .map_err(|_| RoleStoreError::Poisoned)?;
        Ok(roles
            .iter()
            .filter(|(_, r)| *r == role)
            .map(|(uid, _)| uid.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> InMemoryRoleStore {
        InMemoryRoleStore::new()
    }

    #[test]
    fn admin_has_all_permissions() {
        let store = fixture();
        store.assign_role("admin-1", Role::Admin).unwrap();
        assert!(store
            .user_has_permission("admin-1", &Permission::DeleteUser)
            .unwrap());
        assert!(store
            .user_has_permission("admin-1", &Permission::ManageRoles)
            .unwrap());
        assert!(store
            .user_has_permission("admin-1", &Permission::ReadContent)
            .unwrap());
    }

    #[test]
    fn viewer_cannot_create_content() {
        let store = fixture();
        store.assign_role("viewer-1", Role::Viewer).unwrap();
        assert!(!store
            .user_has_permission("viewer-1", &Permission::CreateContent)
            .unwrap());
        assert!(store
            .user_has_permission("viewer-1", &Permission::ReadContent)
            .unwrap());
    }

    #[test]
    fn user_without_role_has_no_permissions() {
        let store = fixture();
        assert!(!store
            .user_has_permission("unknown", &Permission::ReadUser)
            .unwrap());
    }

    #[test]
    fn grant_extra_permission_overrides_role() {
        let store = fixture();
        store.assign_role("user-1", Role::Viewer).unwrap();
        // Viewer can't create content by default
        assert!(!store
            .user_has_permission("user-1", &Permission::CreateContent)
            .unwrap());
        // Grant it explicitly
        store
            .grant_permission("user-1", Permission::CreateContent)
            .unwrap();
        assert!(store
            .user_has_permission("user-1", &Permission::CreateContent)
            .unwrap());
    }

    #[test]
    fn revoke_permission_removes_extra_grant() {
        let store = fixture();
        store.assign_role("user-1", Role::Viewer).unwrap();
        store
            .grant_permission("user-1", Permission::CreateContent)
            .unwrap();
        store
            .revoke_permission("user-1", &Permission::CreateContent)
            .unwrap();
        assert!(!store
            .user_has_permission("user-1", &Permission::CreateContent)
            .unwrap());
    }

    #[test]
    fn check_access_returns_granted_or_denied() {
        let store = fixture();
        store.assign_role("user-1", Role::Admin).unwrap();

        assert_eq!(
            store
                .check_access("user-1", Permission::DeleteUser)
                .unwrap(),
            AccessResult::Granted
        );

        assert!(matches!(
            store
                .check_access("user-2", Permission::DeleteUser)
                .unwrap(),
            AccessResult::Denied(_)
        ));
    }

    #[test]
    fn remove_role_clears_assignments() {
        let store = fixture();
        store.assign_role("user-1", Role::Admin).unwrap();
        store.remove_role("user-1").unwrap();
        assert!(store.get_role("user-1").unwrap().is_none());
        assert!(!store
            .user_has_permission("user-1", &Permission::ReadUser)
            .unwrap());
    }

    #[test]
    fn list_users_with_role_returns_matching() {
        let store = fixture();
        store.assign_role("u1", Role::Admin).unwrap();
        store.assign_role("u2", Role::User).unwrap();
        store.assign_role("u3", Role::Admin).unwrap();

        let admins = store.list_users_with_role(&Role::Admin).unwrap();
        assert_eq!(admins.len(), 2);
        assert!(admins.contains(&"u1".to_string()));
        assert!(admins.contains(&"u3".to_string()));

        let users = store.list_users_with_role(&Role::User).unwrap();
        assert_eq!(users.len(), 1);
        assert!(users.contains(&"u2".to_string()));
    }

    #[test]
    fn role_from_str_roundtrip() {
        assert_eq!(Role::from_str("admin"), Role::Admin);
        assert_eq!(Role::from_str("user"), Role::User);
        assert_eq!(Role::from_str("viewer"), Role::Viewer);
        assert_eq!(
            Role::from_str("custom_role"),
            Role::Custom("custom_role".to_string())
        );
    }

    #[test]
    fn permission_as_str_roundtrip() {
        assert_eq!(Permission::CreateUser.as_str(), "create_user");
        assert_eq!(Permission::DeleteUser.as_str(), "delete_user");
        assert_eq!(
            Permission::Custom("special_op".to_string()).as_str(),
            "special_op"
        );
    }

    #[test]
    fn new_store_is_empty() {
        let store = fixture();
        assert!(store.is_empty());
        assert_eq!(store.user_count(), 0);
    }

    #[test]
    fn user_role_assignment_idempotent() {
        let store = fixture();
        store.assign_role("user-1", Role::User).unwrap();
        store.assign_role("user-1", Role::Admin).unwrap(); // upgrade
        assert_eq!(store.get_role("user-1").unwrap(), Some(Role::Admin));
    }
}
