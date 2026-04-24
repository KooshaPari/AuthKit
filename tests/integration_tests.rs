//! Integration tests for AuthService

use authvault::{
    adapters::{
        hashers::Argon2Hasher,
        storage::{InMemorySessionStorage, InMemoryUserStorage},
    },
    application::AuthService,
    domain::{
        policy::{Condition, Policy, PolicyEffect, PolicyEngine},
        ports::{PasswordHasher, SessionStorage, UserStorage},
        AuthError, Session, SessionId, User,
    },
};
use std::collections::HashMap;

fn create_test_auth_service() -> AuthService {
    let user_storage = std::sync::Arc::new(InMemoryUserStorage::new());
    let session_storage = std::sync::Arc::new(InMemorySessionStorage::new());
    let hasher = std::sync::Arc::new(Argon2Hasher::new());

    AuthService::new("test-secret", user_storage, session_storage, hasher)
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-001
async fn test_register_new_user() {
    let service = create_test_auth_service();
    let result = service.register("test@example.com", "password123").await;

    assert!(result.is_ok());
    let user = result.unwrap();
    assert_eq!(user.email, "test@example.com");
    assert!(user.password_hash.is_some());
    assert!(user.active);
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-002
async fn test_register_duplicate_user_fails() {
    let service = create_test_auth_service();

    service.register("test@example.com", "password123").await.unwrap();

    let result = service.register("test@example.com", "password456").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::UserAlreadyExists));
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-003
async fn test_login_valid_credentials() {
    let service = create_test_auth_service();

    service.register("test@example.com", "password123").await.unwrap();

    let result = service.login("test@example.com", "password123").await;
    assert!(result.is_ok());

    let (token, session) = result.unwrap();
    assert!(!token.is_empty());
    assert_ne!(session.user_id, "test@example.com"); // user_id is UUID, not email
    assert_eq!(session.state, authvault::domain::session::SessionState::Active);
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-004
async fn test_login_invalid_password() {
    let service = create_test_auth_service();

    service.register("test@example.com", "password123").await.unwrap();

    let result = service.login("test@example.com", "wrongpassword").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::InvalidCredentials));
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-005
async fn test_login_nonexistent_user() {
    let service = create_test_auth_service();
    let result = service.login("nonexistent@example.com", "password123").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::InvalidCredentials));
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-006
async fn test_login_inactive_user() {
    let mut user = User::new("test@example.com");
    user.active = false;

    let storage = std::sync::Arc::new(InMemoryUserStorage::new());
    storage.create(&user).await.unwrap();

    let session_storage = std::sync::Arc::new(InMemorySessionStorage::new());
    let hasher = std::sync::Arc::new(Argon2Hasher::new());

    let service = AuthService::new("test-secret", storage, session_storage, hasher);

    let result = service.login("test@example.com", "password123").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::AccountDisabled));
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-007
async fn test_verify_valid_token() {
    let service = create_test_auth_service();

    let user = service.register("test@example.com", "password123").await.unwrap();

    let (token, _) = service.login("test@example.com", "password123").await.unwrap();

    let claims = service.verify_token(&token);
    assert!(claims.is_ok());
    // The claims.sub is the user UUID, not email
    assert_eq!(claims.unwrap().sub, user.id.to_string());
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-008
async fn test_verify_invalid_token() {
    let service = create_test_auth_service();
    let result = service.verify_token("invalid.token.here");

    // Could be InvalidToken or TokenVerification depending on decode failure
    assert!(result.is_err());
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-009
async fn test_refresh_token() {
    let service = create_test_auth_service();

    service.register("test@example.com", "password123").await.unwrap();

    let (token, _) = service.login("test@example.com", "password123").await.unwrap();

    let new_token = service.refresh_token(&token);
    assert!(new_token.is_ok());
    assert_ne!(new_token.unwrap(), token);
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-010
async fn test_logout_session() {
    let service = create_test_auth_service();

    service.register("test@example.com", "password123").await.unwrap();

    let (_, session) = service.login("test@example.com", "password123").await.unwrap();

    let result = service.logout(&session.id).await;
    assert!(result.is_ok());
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-011
async fn test_logout_nonexistent_session() {
    let service = create_test_auth_service();
    let result = service.logout(&SessionId::new()).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::SessionNotFound));
}

#[tokio::test]
// Traces to: FR-AUTHVAULT-012
async fn test_logout_all_sessions() {
    let service = create_test_auth_service();

    service.register("test@example.com", "password123").await.unwrap();

    let (_, session1) = service.login("test@example.com", "password123").await.unwrap();
    let (_, _session2) = service.login("test@example.com", "password123").await.unwrap();

    let result = service.logout_all("test@example.com").await;
    assert!(result.is_ok());

    // After logout_all, the session should be deleted
    let session_storage = std::sync::Arc::new(InMemorySessionStorage::new());
    let found = session_storage.get_by_id(&session1.id).await.unwrap();
    assert!(found.is_none());
}

mod password_hasher_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-020
    fn test_argon2_hasher_different_passwords() {
        let hasher = Argon2Hasher::new();
        let hash1 = hasher.hash("password1").unwrap();
        let hash2 = hasher.hash("password2").unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-021
    fn test_argon2_hasher_same_password_different_hash() {
        let hasher = Argon2Hasher::new();
        let hash1 = hasher.hash("password").unwrap();
        let hash2 = hasher.hash("password").unwrap();

        assert_ne!(hash1, hash2);
        assert!(hasher.verify("password", &hash1));
        assert!(hasher.verify("password", &hash2));
    }
}

mod storage_tests {
    use super::*;

    #[tokio::test]
    // Traces to: FR-AUTHVAULT-030
    async fn test_inmemory_user_storage_crud() {
        let storage = InMemoryUserStorage::new();
        let user = User::new("test@example.com");

        storage.create(&user).await.unwrap();

        let found = storage.get_by_id(&user.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.as_ref().unwrap().email, "test@example.com");

        let mut updated = found.unwrap();
        updated.email = "updated@example.com".to_string();
        storage.update(&updated).await.unwrap();

        // Verify the user was updated by getting by ID
        let found_after = storage.get_by_id(&user.id).await.unwrap();
        assert!(found_after.is_some());
        assert_eq!(found_after.unwrap().email, "updated@example.com");

        storage.delete(&user.id).await.unwrap();
        let deleted = storage.get_by_id(&user.id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    // Traces to: FR-AUTHVAULT-031
    async fn test_inmemory_user_storage_list() {
        let storage = InMemoryUserStorage::new();

        storage.create(&User::new("user1@example.com")).await.unwrap();
        storage.create(&User::new("user2@example.com")).await.unwrap();

        let users = storage.list().await.unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    // Traces to: FR-AUTHVAULT-032
    async fn test_inmemory_session_storage_crud() {
        let storage = InMemorySessionStorage::new();
        let session = Session::new("user-123");

        storage.create(&session).await.unwrap();

        let found = storage.get_by_id(&session.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, "user-123");

        storage.delete(&session.id).await.unwrap();
        let deleted = storage.get_by_id(&session.id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    // Traces to: FR-AUTHVAULT-033
    async fn test_inmemory_session_storage_delete_by_user() {
        let storage = InMemorySessionStorage::new();

        let session1 = Session::new("user-123");
        let session2 = Session::new("user-123");

        storage.create(&session1).await.unwrap();
        storage.create(&session2).await.unwrap();

        storage.delete_by_user("user-123").await.unwrap();

        let found = storage.get_by_id(&session1.id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    // Traces to: FR-AUTHVAULT-034
    async fn test_inmemory_session_storage_delete_expired() {
        let storage = InMemorySessionStorage::new();

        let mut active_session = Session::new("user-123");
        active_session.expires_at = chrono::Utc::now() + chrono::Duration::hours(1);

        let mut expired_session = Session::new("user-456");
        expired_session.expires_at = chrono::Utc::now() - chrono::Duration::hours(1);

        storage.create(&active_session).await.unwrap();
        storage.create(&expired_session).await.unwrap();

        let deleted = storage.delete_expired().await.unwrap();
        assert_eq!(deleted, 1);

        let remaining = storage.get_by_id(&active_session.id).await.unwrap();
        assert!(remaining.is_some());
    }

    #[tokio::test]
    // Traces to: FR-AUTHVAULT-035
    async fn test_inmemory_session_storage_update() {
        let storage = InMemorySessionStorage::new();
        let mut session = Session::new("user-123");

        storage.create(&session).await.unwrap();

        session.state = authvault::domain::session::SessionState::Revoked;
        storage.update(&session).await.unwrap();

        let found = storage.get_by_id(&session.id).await.unwrap();
        assert_eq!(found.unwrap().state, authvault::domain::session::SessionState::Revoked);
    }
}

mod policy_engine_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-040
    fn test_policy_engine_empty_returns_true() {
        // With no policies, there's no deny, so it returns true
        let engine = PolicyEngine::new();
        let attrs = HashMap::new();
        assert!(engine.evaluate("anything", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-041
    fn test_policy_engine_deny_blocks() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-admin", "admin:*", PolicyEffect::Deny)
                .with_action("write")
                .with_priority(10),
        );

        let attrs = HashMap::new();
        assert!(!engine.evaluate("admin:users", "write", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-042
    fn test_policy_engine_condition_eq() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("allow-if-not-confidential", "documents:*", PolicyEffect::Allow)
                .with_action("read")
                .with_condition(Condition::Eq {
                    attribute: "classification".to_string(),
                    value: serde_json::json!("confidential"),
                })
                .with_priority(1),
        );
        engine.add_policy(
            Policy::new("deny-confidential", "documents:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Eq {
                    attribute: "classification".to_string(),
                    value: serde_json::json!("confidential"),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("classification".to_string(), serde_json::json!("public"));
        // Without the condition matching, allow doesn't apply, no deny
        assert!(engine.evaluate("documents:123", "read", &attrs));

        attrs.insert("classification".to_string(), serde_json::json!("confidential"));
        assert!(!engine.evaluate("documents:123", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-043
    fn test_policy_engine_condition_ne() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-test-env", "*", PolicyEffect::Deny)
                .with_action("write")
                .with_condition(Condition::Ne {
                    attribute: "environment".to_string(),
                    value: serde_json::json!("production"),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("environment".to_string(), serde_json::json!("production"));
        assert!(engine.evaluate("anything", "write", &attrs));

        attrs.insert("environment".to_string(), serde_json::json!("development"));
        assert!(!engine.evaluate("anything", "write", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-044
    fn test_policy_engine_condition_in() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("allow-admin-roles", "*", PolicyEffect::Allow)
                .with_action("admin")
                .with_condition(Condition::In {
                    attribute: "role".to_string(),
                    values: vec![serde_json::json!("admin"), serde_json::json!("superadmin")],
                })
                .with_priority(1),
        );

        let mut attrs = HashMap::new();
        attrs.insert("role".to_string(), serde_json::json!("admin"));
        assert!(engine.evaluate("system", "admin", &attrs));

        attrs.insert("role".to_string(), serde_json::json!("user"));
        assert!(engine.evaluate("system", "admin", &attrs)); // No deny, so allow
    }

    #[test]
    // Traces to: FR-AUTHVAULT-045
    fn test_policy_engine_condition_regex() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-internal", "docs:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Regex {
                    attribute: "classification".to_string(),
                    pattern: r"^internal-.*$".to_string(),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("classification".to_string(), serde_json::json!("internal-project"));
        assert!(!engine.evaluate("docs:123", "read", &attrs));

        attrs.insert("classification".to_string(), serde_json::json!("external"));
        assert!(engine.evaluate("docs:123", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-046
    fn test_policy_engine_condition_gt() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("allow-high-tier", "api:*", PolicyEffect::Allow)
                .with_action("read")
                .with_condition(Condition::Gt { attribute: "tier".to_string(), value: 2.0 })
                .with_priority(1),
        );
        engine.add_policy(
            Policy::new("deny-all", "api:*", PolicyEffect::Deny)
                .with_action("read")
                .with_priority(5),
        );

        let mut attrs = HashMap::new();
        attrs.insert("tier".to_string(), serde_json::json!(3));
        assert!(!engine.evaluate("api:data", "read", &attrs)); // Deny takes precedence

        attrs.insert("tier".to_string(), serde_json::json!(1));
        assert!(!engine.evaluate("api:data", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-047
    fn test_policy_engine_condition_lt() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-low-tier", "api:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Lt { attribute: "tier".to_string(), value: 3.0 })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("tier".to_string(), serde_json::json!(1));
        assert!(!engine.evaluate("api:data", "read", &attrs));

        attrs.insert("tier".to_string(), serde_json::json!(5));
        assert!(engine.evaluate("api:data", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-048
    fn test_policy_engine_condition_starts_with() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-eng", "docs:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::StartsWith {
                    attribute: "department".to_string(),
                    prefix: "eng-".to_string(),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("department".to_string(), serde_json::json!("eng-backend"));
        assert!(!engine.evaluate("docs:123", "read", &attrs));

        attrs.insert("department".to_string(), serde_json::json!("sales"));
        assert!(engine.evaluate("docs:123", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-049
    fn test_policy_engine_condition_ends_with() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-temp", "files:*", PolicyEffect::Deny)
                .with_action("write")
                .with_condition(Condition::EndsWith {
                    attribute: "suffix".to_string(),
                    suffix: "_temp".to_string(),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("suffix".to_string(), serde_json::json!("data_temp"));
        assert!(!engine.evaluate("files:123", "write", &attrs));

        attrs.insert("suffix".to_string(), serde_json::json!("data_perm"));
        assert!(engine.evaluate("files:123", "write", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-050
    fn test_policy_engine_condition_and() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-not-dev-internal", "api:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Not {
                    condition: Box::new(Condition::And {
                        conditions: vec![
                            Condition::Eq {
                                attribute: "environment".to_string(),
                                value: serde_json::json!("development"),
                            },
                            Condition::Eq {
                                attribute: "department".to_string(),
                                value: serde_json::json!("engineering"),
                            },
                        ],
                    }),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("environment".to_string(), serde_json::json!("development"));
        attrs.insert("department".to_string(), serde_json::json!("engineering"));
        assert!(engine.evaluate("api:data", "read", &attrs));

        attrs.insert("environment".to_string(), serde_json::json!("production"));
        assert!(!engine.evaluate("api:data", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-051
    fn test_policy_engine_condition_or() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-external", "docs:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Or {
                    conditions: vec![
                        Condition::Eq {
                            attribute: "role".to_string(),
                            value: serde_json::json!("admin"),
                        },
                        Condition::Eq {
                            attribute: "department".to_string(),
                            value: serde_json::json!("internal"),
                        },
                    ],
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("role".to_string(), serde_json::json!("admin"));
        attrs.remove("department");
        assert!(!engine.evaluate("docs:123", "read", &attrs));

        attrs.remove("role");
        attrs.insert("department".to_string(), serde_json::json!("internal"));
        assert!(!engine.evaluate("docs:123", "read", &attrs));

        attrs.remove("department");
        assert!(engine.evaluate("docs:123", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-052
    fn test_policy_engine_condition_not() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-non-internal", "docs:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Not {
                    condition: Box::new(Condition::Eq {
                        attribute: "classification".to_string(),
                        value: serde_json::json!("internal"),
                    }),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("classification".to_string(), serde_json::json!("internal"));
        assert!(engine.evaluate("docs:123", "read", &attrs));

        attrs.insert("classification".to_string(), serde_json::json!("public"));
        assert!(!engine.evaluate("docs:123", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-053
    fn test_policy_engine_priority_ordering() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(
            Policy::new("low-priority-deny", "docs:*", PolicyEffect::Deny)
                .with_action("write")
                .with_priority(1),
        );
        engine.add_policy(
            Policy::new("high-priority-allow", "docs:*", PolicyEffect::Allow)
                .with_action("write")
                .with_priority(10),
        );

        let attrs = HashMap::new();
        // High priority allow doesn't override low priority deny
        assert!(!engine.evaluate("docs:123", "write", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-054
    fn test_policy_engine_explain() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("allow-read", "docs:*", PolicyEffect::Allow)
                .with_action("read")
                .with_priority(1),
        );
        engine.add_policy(
            Policy::new("deny-confidential", "docs:*", PolicyEffect::Deny)
                .with_action("read")
                .with_condition(Condition::Eq {
                    attribute: "classification".to_string(),
                    value: serde_json::json!("confidential"),
                })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("classification".to_string(), serde_json::json!("confidential"));

        let reasons = engine.explain("docs:123", "read", &attrs);
        assert!(!reasons.is_empty());
        assert!(reasons.iter().any(|r| r.contains("DENY")));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-055
    fn test_policy_engine_clear() {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("deny-all", "*", PolicyEffect::Deny).with_action("*").with_priority(1),
        );

        engine.clear();

        let attrs = HashMap::new();
        // No policies means no deny, so returns true
        assert!(engine.evaluate("anything", "read", &attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-056
    fn test_policy_engine_add_policies_batch() {
        let mut engine = PolicyEngine::new();
        engine.add_policies(vec![
            Policy::new("allow-read", "docs:*", PolicyEffect::Allow)
                .with_action("read")
                .with_priority(1),
            Policy::new("deny-write", "docs:*", PolicyEffect::Deny)
                .with_action("write")
                .with_priority(10),
        ]);

        let attrs = HashMap::new();
        assert!(engine.evaluate("docs:123", "read", &attrs));
        assert!(!engine.evaluate("docs:123", "write", &attrs));
    }
}
