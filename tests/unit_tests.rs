//! Extended unit tests for domain layer

use authvault::domain::{
    auth::{AuthMethod, Authenticator, Claims},
    errors::AuthError,
    identity::{Permission, Role, User, UserId},
    policy::{Condition, Policy, PolicyEffect},
    session::{Session, SessionId, SessionState},
};
use chrono::{Duration, Utc};
use std::collections::HashMap;

mod claims_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-060
    fn test_claims_new() {
        let user_id = UserId::from_string("test-user");
        let roles = vec![Role::new("admin")];
        let claims = Claims::new(&user_id, &roles);

        assert_eq!(claims.sub, "test-user");
        assert!(claims.roles.contains(&"admin".to_string()));
        assert!(!claims.is_expired());
    }

    #[test]
    // Traces to: FR-AUTHVAULT-061
    fn test_claims_with_expiration() {
        let user_id = UserId::new();
        let roles = vec![];
        let claims = Claims::new(&user_id, &roles).with_expiration(Duration::hours(1));

        let now = Utc::now().timestamp();
        assert!(claims.exp > now);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-062
    fn test_claims_with_claim() {
        let user_id = UserId::new();
        let claims = Claims::new(&user_id, &[]).with_claim("custom", serde_json::json!("value"));

        assert_eq!(claims.extra.get("custom"), Some(&serde_json::json!("value")));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-063
    fn test_claims_user_id() {
        let user_id = UserId::from_string("specific-user");
        let claims = Claims::new(&user_id, &[]);

        assert_eq!(claims.user_id().to_string(), "specific-user");
    }
}

mod authenticator_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-070
    fn test_authenticator_new() {
        let auth = Authenticator::new("secret");
        assert!(auth.generate_token(&UserId::new(), &[]).is_ok());
    }

    #[test]
    // Traces to: FR-AUTHVAULT-071
    fn test_authenticator_with_issuer() {
        let auth = Authenticator::new("secret").with_issuer("custom-issuer", "custom-audience");
        let token = auth.generate_token(&UserId::new(), &[]).unwrap();
        let claims = auth.verify_token(&token).unwrap();

        assert_eq!(claims.iss, "custom-issuer");
        assert_eq!(claims.aud, "custom-audience");
    }

    #[test]
    // Traces to: FR-AUTHVAULT-072
    fn test_authenticator_different_secrets() {
        let auth1 = Authenticator::new("secret1");
        let auth2 = Authenticator::new("secret2");
        let user_id = UserId::new();

        let token = auth1.generate_token(&user_id, &[]).unwrap();
        let result = auth2.verify_token(&token);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidSignature));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-073
    fn test_authenticator_generate_with_expiry() {
        let auth = Authenticator::new("secret");
        let token =
            auth.generate_token_with_expiry(&UserId::new(), &[], Duration::minutes(30)).unwrap();

        assert!(auth.verify_token(&token).is_ok());
    }

    #[test]
    // Traces to: FR-AUTHVAULT-074
    fn test_authenticator_refresh_token() {
        let auth = Authenticator::new("secret");
        let token = auth.generate_token(&UserId::new(), &[Role::new("admin")]).unwrap();

        let new_token = auth.refresh_token(&token).unwrap();
        let claims = auth.verify_token(&new_token).unwrap();

        assert!(claims.roles.contains(&"admin".to_string()));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-075
    fn test_authenticator_refresh_invalid_token() {
        let auth = Authenticator::new("secret");
        let result = auth.refresh_token("invalid-token");

        assert!(result.is_err());
    }
}

mod identity_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-080
    fn test_user_id_new_is_unique() {
        let id1 = UserId::new();
        let id2 = UserId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-081
    fn test_user_id_from_string() {
        let id = UserId::from_string("specific");
        assert_eq!(id.to_string(), "specific");
    }

    #[test]
    // Traces to: FR-AUTHVAULT-082
    fn test_user_display() {
        let id = UserId::from_string("display-test");
        assert_eq!(format!("{}", id), "display-test");
    }

    #[test]
    // Traces to: FR-AUTHVAULT-083
    fn test_user_with_password_hash() {
        let user = User::new("test@example.com").with_password_hash("hash123");
        assert_eq!(user.password_hash, Some("hash123".to_string()));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-084
    fn test_user_with_role() {
        let user = User::new("test@example.com").with_role(Role::new("admin"));
        assert!(user.has_role("admin"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-085
    fn test_user_with_attribute() {
        let user = User::new("test@example.com")
            .with_attribute("department", serde_json::json!("engineering"));

        assert_eq!(user.attributes.get("department"), Some(&serde_json::json!("engineering")));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-086
    fn test_user_verify() {
        let mut user = User::new("test@example.com");
        assert!(!user.email_verified);

        user.verify();
        assert!(user.email_verified);
        assert!(user.updated_at > user.created_at);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-087
    fn test_user_deactivate() {
        let mut user = User::new("test@example.com");
        assert!(user.active);

        user.deactivate();
        assert!(!user.active);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-088
    fn test_user_record_login() {
        let mut user = User::new("test@example.com");
        assert!(user.last_login.is_none());

        user.record_login();
        assert!(user.last_login.is_some());
    }

    #[test]
    // Traces to: FR-AUTHVAULT-089
    fn test_user_has_permission() {
        let user = User::new("test@example.com").with_role(Role::new("editor").with_permission(
            Permission::new("documents", vec!["read".to_string(), "write".to_string()]),
        ));

        assert!(user.has_permission("documents:read"));
        assert!(user.has_permission("documents:write"));
        assert!(!user.has_permission("documents:delete"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-090
    fn test_role_implies() {
        let role = Role::new("admin").with_parent("moderator").with_parent("user");
        assert!(role.implies("moderator"));
        assert!(role.implies("user"));
        assert!(!role.implies("guest"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-091
    fn test_role_has_permission() {
        let role =
            Role::new("editor").with_permission(Permission::new("docs", vec!["*".to_string()]));

        assert!(role.has_permission("docs:read"));
        assert!(role.has_permission("docs:write"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-092
    fn test_permission_matches_resource_action() {
        let perm = Permission::new("posts", vec!["read".to_string(), "write".to_string()]);

        assert!(perm.matches_resource_action("posts", "read"));
        assert!(perm.matches_resource_action("posts", "write"));
        assert!(!perm.matches_resource_action("posts", "delete"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-093
    fn test_permission_matches_wildcard_action() {
        let perm = Permission::new("posts", vec!["*".to_string()]);

        assert!(perm.matches_resource_action("posts", "any-action"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-094
    fn test_permission_matches_resource_wildcard() {
        let perm = Permission::new("*", vec!["*".to_string()]);

        assert!(perm.matches_resource_action("anything", "any-action"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-095
    fn test_permission_matches_just_resource() {
        let perm = Permission::new("users:123", vec!["read".to_string()]);

        // matches() with no colon just checks resource match
        assert!(perm.matches_resource("users:123"));
        assert!(!perm.matches_resource("users:456"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-096
    fn test_builtin_roles() {
        use authvault::domain::identity::roles;

        let admin = roles::admin();
        assert!(admin.has_permission("*:*"));

        let user = roles::user();
        assert!(user.has_permission("self:profile:read"));

        let guest = roles::guest();
        assert!(guest.has_permission("public:read"));
        assert!(!guest.has_permission("public:write"));
    }
}

mod session_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-100
    fn test_session_id_new_is_unique() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-101
    fn test_session_display() {
        let id = SessionId::new();
        assert_eq!(format!("{}", id), id.to_string());
    }

    #[test]
    // Traces to: FR-AUTHVAULT-102
    fn test_session_with_refresh_token() {
        let session = Session::new("user-123").with_refresh_token("refresh-abc");
        assert_eq!(session.refresh_token_id, Some("refresh-abc".to_string()));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-103
    fn test_session_with_ip() {
        let session = Session::new("user-123").with_ip("192.168.1.1");
        assert_eq!(session.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-104
    fn test_session_with_user_agent() {
        let session = Session::new("user-123").with_user_agent("Mozilla/5.0");
        assert_eq!(session.user_agent, Some("Mozilla/5.0".to_string()));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-105
    fn test_session_with_expiry() {
        let session = Session::new("user-123").with_expiry(Duration::hours(48));
        let expected = session.created_at + Duration::hours(48);
        assert_eq!(session.expires_at, expected);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-106
    fn test_session_is_valid() {
        let session = Session::new("user-123");
        assert!(session.is_valid());
    }

    #[test]
    // Traces to: FR-AUTHVAULT-107
    fn test_session_touch() {
        let mut session = Session::new("user-123");
        let original_activity = session.last_activity;
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch();
        assert!(session.last_activity > original_activity);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-108
    fn test_session_revoke() {
        let mut session = Session::new("user-123");
        session.revoke();
        assert_eq!(session.state, SessionState::Revoked);
        assert!(!session.is_valid());
    }

    #[test]
    // Traces to: FR-AUTHVAULT-109
    fn test_session_state_default() {
        let state: SessionState = Default::default();
        assert_eq!(state, SessionState::Active);
    }
}

mod auth_method_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-110
    fn test_auth_method_default() {
        let method: AuthMethod = Default::default();
        assert_eq!(method, AuthMethod::Password);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-111
    fn test_auth_method_serialization() {
        let method = AuthMethod::OAuth2;
        let json = serde_json::to_string(&method).unwrap();
        // snake_case converts OAuth2 to o_auth2
        assert_eq!(json, "\"o_auth2\"");

        let parsed: AuthMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, AuthMethod::OAuth2);
    }
}

mod policy_effect_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-115
    fn test_policy_effect_serialization() {
        let effect = PolicyEffect::Allow;
        let json = serde_json::to_string(&effect).unwrap();
        assert_eq!(json, "\"allow\"");

        let effect_deny = PolicyEffect::Deny;
        let json_deny = serde_json::to_string(&effect_deny).unwrap();
        assert_eq!(json_deny, "\"deny\"");
    }
}

mod policy_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-120
    fn test_policy_new() {
        let policy = Policy::new("test-policy", "docs", PolicyEffect::Allow);
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.resource, "docs");
        assert_eq!(policy.effect, PolicyEffect::Allow);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-121
    fn test_policy_with_action() {
        let policy =
            Policy::new("test", "*", PolicyEffect::Allow).with_action("read").with_action("write");

        assert_eq!(policy.actions, vec!["read", "write"]);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-122
    fn test_policy_with_condition() {
        let policy = Policy::new("test", "*", PolicyEffect::Allow).with_condition(Condition::Eq {
            attribute: "role".to_string(),
            value: serde_json::json!("admin"),
        });

        assert_eq!(policy.conditions.len(), 1);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-123
    fn test_policy_with_priority() {
        let policy = Policy::new("test", "*", PolicyEffect::Allow).with_priority(100);
        assert_eq!(policy.priority, 100);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-124
    fn test_policy_applies_to_exact_match() {
        let policy = Policy::new("test", "docs", PolicyEffect::Allow).with_action("read");

        assert!(policy.applies_to("docs", "read"));
        assert!(!policy.applies_to("docs", "write"));
        assert!(!policy.applies_to("other", "read"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-125
    fn test_policy_applies_to_wildcard_prefix() {
        let policy = Policy::new("test", "docs:*", PolicyEffect::Allow).with_action("read");

        assert!(policy.applies_to("docs:123", "read"));
        assert!(!policy.applies_to("posts:123", "read"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-126
    fn test_policy_applies_to_wildcard_action() {
        let policy = Policy::new("test", "*", PolicyEffect::Allow).with_action("*");

        assert!(policy.applies_to("docs:123", "any-action"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-127
    fn test_policy_evaluate_no_conditions() {
        let policy = Policy::new("test", "*", PolicyEffect::Allow);
        let attrs = HashMap::new();

        assert_eq!(policy.evaluate(&attrs), Some(PolicyEffect::Allow));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-128
    fn test_policy_evaluate_with_conditions() {
        let policy = Policy::new("test", "*", PolicyEffect::Allow).with_condition(Condition::Eq {
            attribute: "env".to_string(),
            value: serde_json::json!("prod"),
        });

        let mut attrs = HashMap::new();
        attrs.insert("env".to_string(), serde_json::json!("prod"));
        assert_eq!(policy.evaluate(&attrs), Some(PolicyEffect::Allow));

        attrs.insert("env".to_string(), serde_json::json!("dev"));
        assert_eq!(policy.evaluate(&attrs), None);
    }

    #[test]
    // Traces to: FR-AUTHVAULT-129
    fn test_condition_eq_missing_attribute() {
        let cond =
            Condition::Eq { attribute: "missing".to_string(), value: serde_json::json!("value") };
        let attrs = HashMap::new();

        assert!(!cond.evaluate(&attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-130
    fn test_condition_ne_missing_attribute() {
        let cond =
            Condition::Ne { attribute: "missing".to_string(), value: serde_json::json!("value") };
        let attrs = HashMap::new();

        assert!(cond.evaluate(&attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-131
    fn test_condition_in_missing_attribute() {
        let cond = Condition::In {
            attribute: "missing".to_string(),
            values: vec![serde_json::json!("value")],
        };
        let attrs = HashMap::new();

        assert!(!cond.evaluate(&attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-132
    fn test_condition_regex_invalid_pattern() {
        let cond =
            Condition::Regex { attribute: "field".to_string(), pattern: "[invalid".to_string() };
        let mut attrs = HashMap::new();
        attrs.insert("field".to_string(), serde_json::json!("value"));

        assert!(!cond.evaluate(&attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-133
    fn test_condition_gt_non_number() {
        let cond = Condition::Gt { attribute: "field".to_string(), value: 5.0 };
        let mut attrs = HashMap::new();
        attrs.insert("field".to_string(), serde_json::json!("not-a-number"));

        assert!(!cond.evaluate(&attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-134
    fn test_condition_lt_non_number() {
        let cond = Condition::Lt { attribute: "field".to_string(), value: 5.0 };
        let mut attrs = HashMap::new();
        attrs.insert("field".to_string(), serde_json::json!("not-a-number"));

        assert!(!cond.evaluate(&attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-135
    fn test_condition_starts_with_non_string() {
        let cond =
            Condition::StartsWith { attribute: "field".to_string(), prefix: "pre".to_string() };
        let mut attrs = HashMap::new();
        attrs.insert("field".to_string(), serde_json::json!(123));

        assert!(!cond.evaluate(&attrs));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-136
    fn test_condition_ends_with_non_string() {
        let cond =
            Condition::EndsWith { attribute: "field".to_string(), suffix: "fix".to_string() };
        let mut attrs = HashMap::new();
        attrs.insert("field".to_string(), serde_json::json!(123));

        assert!(!cond.evaluate(&attrs));
    }
}

mod error_serialization_tests {
    use super::*;

    #[test]
    // Traces to: FR-AUTHVAULT-140
    fn test_auth_error_serialization() {
        let error = AuthError::InvalidCredentials;
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("Invalid credentials"));

        let error = AuthError::UserNotFound;
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("User not found"));

        let error = AuthError::TokenExpired;
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("Token expired"));
    }

    #[test]
    // Traces to: FR-AUTHVAULT-141
    fn test_auth_error_with_message() {
        let error = AuthError::TokenGeneration("crypto failure".to_string());
        assert!(error.to_string().contains("crypto failure"));

        let error = AuthError::TokenVerification("signature mismatch".to_string());
        assert!(error.to_string().contains("signature mismatch"));

        let error = AuthError::PasswordTooWeak("needs symbols".to_string());
        assert!(error.to_string().contains("needs symbols"));

        let error = AuthError::StorageError("db connection failed".to_string());
        assert!(error.to_string().contains("db connection failed"));

        let error = AuthError::ValidationError("invalid format".to_string());
        assert!(error.to_string().contains("invalid format"));
    }
}
