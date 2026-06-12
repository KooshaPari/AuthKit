//! End-to-end integration tests for `phenotype-auth-core`.
//!
//! These tests exercise the full public surface: User construction,
//! permission checks, session lifecycle, token sign/verify, and the
//! build-info / version-source contract. The test surface is
//! written against the **current** lib API (post-Wave D); the
//! previous draft-API version of this file was rewritten when the
//! real session/permission/token signatures landed.

use chrono::Utc;
use phenotype_auth_core::{
    auth_health, build_info, health, AuthError, Permission, Role, Session, SessionId, Token, User,
    UserId, VERSION,
};

#[test]
fn health_snapshot_is_consistent_with_build_info() {
    let h = auth_health();
    let info = build_info();
    assert_eq!(h.version, info.version);
    assert_eq!(h.git_sha, info.git_sha);
    assert_eq!(h.target_triple, info.target_triple);
    assert_eq!(h.build_profile, info.build_profile);
}

#[test]
fn health_round_trips_through_json() {
    let h = auth_health();
    let json = serde_json::to_string(&h).unwrap();
    let back: health::HealthSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn version_constant_is_non_empty_and_matches_pkg_version() {
    assert!(!VERSION.is_empty());
    // The build_info() version should match VERSION (they're both
    // sourced from phenotype-build-info::pkg_version()).
    assert_eq!(VERSION, build_info().version);
}

#[test]
fn full_lifecycle_user_session_token() {
    use chrono::Duration;

    // 1. Construct a user
    let user = User::new(
        UserId::new_v4(),
        "koosha@phenotype.dev".into(),
        "Koosha Pari".into(),
        Role::Admin,
    );
    assert!(user.role().can_access(&Permission::users_write()));
    // Admin can access everything, including billing.
    assert!(user.role().can_access(&Permission::billing_refund()));

    // 2. Open a session
    let mut session = Session::new(user.id(), Utc::now(), Duration::seconds(3600));
    assert!(!session.is_expired());

    // 3. Issue a token
    let token = Token::generate();
    let signed = token.sign(b"my-secret");

    // 4. Verify the token
    let verified = Token::verify(&signed, b"my-secret").unwrap();
    assert_eq!(verified.as_bytes(), token.as_bytes());

    // 5. Extend the session
    session
        .extend(Duration::seconds(1800), Utc::now())
        .unwrap();
    assert!(!session.is_expired());

    // 6. Re-redact to confirm the redact() method is total
    let display = token.redact();
    assert!(!display.is_empty());
}

#[test]
fn permission_matrix_for_each_role() {
    // Admin: all
    assert!(Role::Admin.can_access(&Permission::users_write()));
    assert!(Role::Admin.can_access(&Permission::billing_refund()));
    assert!(Role::Admin.can_access(&Permission::FleetManage));

    // Operator: writes + everything-except-billing. So FleetManage IS allowed.
    assert!(Role::Operator.can_access(&Permission::users_write()));
    assert!(!Role::Operator.can_access(&Permission::billing_refund()));
    assert!(Role::Operator.can_access(&Permission::FleetManage));

    // The actual matrix delta: Operator is denied ONLY BillingRefund
    // (out of the 8 permissions in the enum).
    let operator_denies: Vec<&str> = [
        (Permission::UsersRead, "UsersRead"),
        (Permission::users_write(), "UsersWrite"),
        (Permission::UsersDelete, "UsersDelete"),
        (Permission::SkillsRead, "SkillsRead"),
        (Permission::SkillsWrite, "SkillsWrite"),
        (Permission::billing_refund(), "BillingRefund"),
        (Permission::BillingRead, "BillingRead"),
        (Permission::FleetManage, "FleetManage"),
    ]
    .iter()
    .filter(|(p, _)| !Role::Operator.can_access(p))
    .map(|(_, name)| *name)
    .collect();
    assert_eq!(operator_denies, vec!["BillingRefund"]);

    // Viewer: reads only
    assert!(Role::Viewer.can_access(&Permission::UsersRead));
    assert!(!Role::Viewer.can_access(&Permission::users_write()));
    assert!(!Role::Viewer.can_access(&Permission::billing_refund()));

    // Custom: deny by default
    let custom = Role::custom("ghost-role", vec![]);
    assert!(!custom.can_access(&Permission::UsersRead));
    assert!(!custom.can_access(&Permission::users_write()));

    // Custom WITH the right permission: grant
    let custom_granted = Role::custom("billing-bot", vec![Permission::billing_refund()]);
    assert!(custom_granted.can_access(&Permission::billing_refund()));
    assert!(!custom_granted.can_access(&Permission::users_write()));
}

#[test]
fn user_id_round_trips_through_string() {
    let id = UserId::new_v4();
    let s = id.to_string();
    let back = UserId::parse(&s).unwrap();
    assert_eq!(id, back);
}

#[test]
fn user_id_parse_rejects_invalid() {
    assert!(UserId::parse("not-a-uuid").is_err());
    assert!(UserId::parse("").is_err());
    assert!(UserId::parse("00000000-0000-0000-0000-XXXXXXXXXXXX").is_err());
}

#[test]
fn session_id_round_trips() {
    let id = SessionId::new_v4();
    let s = id.to_string();
    let back = SessionId::parse(&s).unwrap();
    assert_eq!(id, back);
}

#[test]
fn session_id_parse_rejects_garbage() {
    assert!(SessionId::parse("not-a-uuid").is_err());
    assert!(SessionId::parse("").is_err());
}

#[test]
fn token_redaction_is_total() {
    let token = Token::generate();
    let display = token.redact();
    // The Display/redact output should be a non-empty glyph string.
    assert!(!display.is_empty());
    // The raw token bytes (hex-encoded) must not appear in the redacted form.
    let raw_hex = token
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .fold(String::new(), |mut acc, chunk| {
            acc.push_str(&chunk);
            acc
        });
    assert!(!display.contains(&raw_hex), "redact must hide raw bytes");
}

#[test]
fn token_with_wrong_secret_does_not_verify() {
    let token = Token::generate();
    let signed = token.sign(b"correct");
    let res = Token::verify(&signed, b"wrong");
    assert!(res.is_err(), "wrong secret must not verify");
    // The error must be one of the verification failures.
    let err = res.unwrap_err();
    assert!(
        matches!(err, AuthError::TokenInvalid | AuthError::TokenExpired(_)),
        "expected TokenInvalid or TokenExpired, got {err:?}"
    );
}

#[test]
fn session_extension_increases_expiry() {
    use chrono::Duration;
    let mut s1 = Session::new(UserId::new_v4(), Utc::now(), Duration::seconds(60));
    let original_expiry = s1.expires_at();
    s1.extend(Duration::seconds(120), Utc::now()).unwrap();
    assert!(s1.expires_at() > original_expiry);
}

#[test]
fn session_extend_after_expiry_returns_error() {
    use chrono::Duration;
    let now = Utc::now();
    // Zero-TTL session: already expired.
    let mut s = Session::new(UserId::new_v4(), now, Duration::seconds(0));
    let err = s.extend(Duration::seconds(60), now).unwrap_err();
    assert!(matches!(err, AuthError::SessionExpired(_)));
}
