//! Identity entities - users, roles, permissions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Unique user identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

impl UserId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// User entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier.
    pub id: UserId,
    /// Email address (unique).
    pub email: String,
    /// Hashed password.
    pub password_hash: Option<String>,
    /// User roles.
    pub roles: Vec<Role>,
    /// User attributes for ABAC.
    pub attributes: std::collections::HashMap<String, serde_json::Value>,
    /// Whether the user is active.
    pub active: bool,
    /// Email verified.
    pub email_verified: bool,
    /// Created timestamp.
    pub created_at: DateTime<Utc>,
    /// Updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// Last login.
    pub last_login: Option<DateTime<Utc>>,
}

impl User {
    /// Create a new user.
    pub fn new(email: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: UserId::new(),
            email: email.into(),
            password_hash: None,
            roles: Vec::new(),
            attributes: std::collections::HashMap::new(),
            active: true,
            email_verified: false,
            created_at: now,
            updated_at: now,
            last_login: None,
        }
    }

    /// Set the password hash.
    pub fn with_password_hash(mut self, hash: impl Into<String>) -> Self {
        self.password_hash = Some(hash.into());
        self
    }

    /// Add a role.
    pub fn with_role(mut self, role: Role) -> Self {
        self.roles.push(role);
        self
    }

    /// Add an attribute.
    pub fn with_attribute(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.attributes.insert(key.into(), value);
        self
    }

    /// Verify the user.
    pub fn verify(&mut self) {
        self.email_verified = true;
        self.updated_at = Utc::now();
    }

    /// Deactivate the user.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.updated_at = Utc::now();
    }

    /// Record login.
    pub fn record_login(&mut self) {
        self.last_login = Some(Utc::now());
    }

    /// Check if user has a role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r.name == role || r.implies(role))
    }

    /// Check if user has a permission.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.roles.iter().any(|r| r.has_permission(permission))
    }
}

/// Role with permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name.
    pub name: String,
    /// Parent roles (for hierarchy).
    pub parents: Vec<String>,
    /// Role permissions.
    pub permissions: Vec<Permission>,
    /// Role description.
    pub description: Option<String>,
}

impl Role {
    /// Create a new role.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), parents: Vec::new(), permissions: Vec::new(), description: None }
    }

    /// Add a parent role.
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parents.push(parent.into());
        self
    }

    /// Add a permission.
    pub fn with_permission(mut self, permission: Permission) -> Self {
        self.permissions.push(permission);
        self
    }

    /// Check if this role implies another role.
    pub fn implies(&self, role: &str) -> bool {
        self.parents.iter().any(|p| p == role)
    }

    /// Check if this role has a permission.
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p.matches(permission))
    }
}

/// Permission with resource and action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Resource pattern (e.g., "users:*", "posts:read").
    pub resource: String,
    /// Actions (e.g., ["read", "write"]).
    pub actions: Vec<String>,
}

impl Permission {
    /// Create a new permission.
    pub fn new(resource: impl Into<String>, actions: Vec<String>) -> Self {
        Self { resource: resource.into(), actions }
    }

    /// Check if this permission matches a resource and action.
    pub fn matches(&self, resource_action: &str) -> bool {
        // Parse "resource:action" format
        if let Some((resource, action)) = resource_action.split_once(':') {
            self.matches_resource_action(resource, action)
        } else {
            // Check if it's just the resource
            self.matches_resource(resource_action)
        }
    }

    /// Check if this permission matches a resource and action.
    pub fn matches_resource_action(&self, resource: &str, action: &str) -> bool {
        // Check resource pattern
        if !self.matches_resource(resource) {
            return false;
        }
        // Check action
        self.actions.iter().any(|a| a == "*" || a == action)
    }

    /// Check if this permission matches a resource pattern.
    pub fn matches_resource(&self, resource: &str) -> bool {
        if self.resource == "*" {
            return true;
        }
        if self.resource.ends_with(":*") {
            let prefix = &self.resource[..self.resource.len() - 2];
            return resource.starts_with(prefix);
        }
        self.resource == resource
    }
}

/// Built-in roles.
pub mod roles {
    use super::*;

    pub fn admin() -> Role {
        Role::new("admin").with_permission(Permission::new("*", vec!["*".to_string()]))
    }

    pub fn user() -> Role {
        Role::new("user").with_permission(Permission::new("self:*", vec!["*".to_string()]))
    }

    pub fn guest() -> Role {
        Role::new("guest").with_permission(Permission::new("public:*", vec!["read".to_string()]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new("test@example.com");
        assert_eq!(user.email, "test@example.com");
        assert!(user.active);
        assert!(!user.email_verified);
    }

    #[test]
    fn test_role_hierarchy() {
        let admin = Role::new("admin").with_parent("moderator");
        let moderator = Role::new("moderator").with_parent("user");

        assert!(admin.implies("moderator"));
        assert!(!admin.implies("user"));
    }

    #[test]
    fn test_permission_matching() {
        let perm = Permission::new("users:*", vec!["read".to_string(), "write".to_string()]);

        assert!(perm.matches_resource_action("users:123", "read"));
        assert!(perm.matches_resource_action("users:123", "write"));
        assert!(!perm.matches_resource_action("users:123", "delete"));
        assert!(!perm.matches_resource_action("posts:123", "read"));
    }
}
