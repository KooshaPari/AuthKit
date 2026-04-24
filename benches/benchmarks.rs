//! Benchmarks for Authvault

use authvault::{
    adapters::hashers::{Argon2Hasher, BcryptHasher},
    domain::{
        auth::Authenticator,
        identity::{Permission, Role, User, UserId},
        policy::{Condition, Policy, PolicyEffect, PolicyEngine},
        session::Session,
    },
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("authenticator");

    group.bench_function("generate_token", |b| {
        let auth = Authenticator::new("benchmark-secret");
        let user_id = UserId::new();
        let roles = vec![Role::new("admin")];

        b.iter(|| auth.generate_token(black_box(&user_id), black_box(&roles)).unwrap());
    });

    group.bench_function("verify_token", |b| {
        let auth = Authenticator::new("benchmark-secret");
        let user_id = UserId::new();
        let roles = vec![Role::new("admin")];
        let token = auth.generate_token(&user_id, &roles).unwrap();

        b.iter(|| auth.verify_token(black_box(&token)).unwrap());
    });

    group.finish();

    let mut hash_group = c.benchmark_group("password_hashing");

    hash_group.bench_function("argon2_hash", |b| {
        let hasher = Argon2Hasher::new();
        b.iter(|| hasher.hash(black_box("password123")).unwrap());
    });

    hash_group.bench_function("bcrypt_hash", |b| {
        let hasher = BcryptHasher::new(12);
        b.iter(|| hasher.hash(black_box("password123")).unwrap());
    });

    hash_group.bench_function("argon2_verify", |b| {
        let hasher = Argon2Hasher::new();
        let hash = hasher.hash("password123").unwrap();
        b.iter(|| hasher.verify(black_box("password123"), black_box(&hash)));
    });

    hash_group.bench_function("bcrypt_verify", |b| {
        let hasher = BcryptHasher::new(12);
        let hash = hasher.hash("password123").unwrap();
        b.iter(|| hasher.verify(black_box("password123"), black_box(&hash)));
    });

    hash_group.finish();

    let mut policy_group = c.benchmark_group("policy_engine");

    policy_group.bench_function("evaluate_simple", |b| {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("allow-all", "*", PolicyEffect::Allow).with_action("*").with_priority(1),
        );
        let attrs = HashMap::new();

        b.iter(|| engine.evaluate(black_box("resource"), black_box("action"), black_box(&attrs)));
    });

    policy_group.bench_function("evaluate_with_conditions", |b| {
        let mut engine = PolicyEngine::new();
        engine.add_policy(
            Policy::new("complex", "docs:*", PolicyEffect::Allow)
                .with_action("read")
                .with_condition(Condition::Eq {
                    attribute: "env".to_string(),
                    value: serde_json::json!("prod"),
                })
                .with_condition(Condition::Gt { attribute: "tier".to_string(), value: 2.0 })
                .with_priority(10),
        );

        let mut attrs = HashMap::new();
        attrs.insert("env".to_string(), serde_json::json!("prod"));
        attrs.insert("tier".to_string(), serde_json::json!(3));

        b.iter(|| engine.evaluate(black_box("docs:123"), black_box("read"), black_box(&attrs)));
    });

    policy_group.finish();

    let mut identity_group = c.benchmark_group("identity");

    identity_group.bench_function("user_creation", |b| {
        b.iter(|| User::new(black_box("test@example.com")));
    });

    identity_group.bench_function("role_permission_check", |b| {
        let role =
            Role::new("admin").with_permission(Permission::new("docs:*", vec!["*".to_string()]));

        b.iter(|| role.has_permission(black_box("docs:123:read")));
    });

    identity_group.bench_function("user_permission_check", |b| {
        let user = User::new("test@example.com").with_role(Role::new("editor").with_permission(
            Permission::new("documents:*", vec!["read".to_string(), "write".to_string()]),
        ));

        b.iter(|| user.has_permission(black_box("documents:456:write")));
    });

    identity_group.finish();

    let mut session_group = c.benchmark_group("session");

    session_group.bench_function("session_creation", |b| {
        b.iter(|| Session::new(black_box("user-123")));
    });

    session_group.bench_function("session_validation", |b| {
        let session = Session::new("user-123");
        b.iter(|| session.is_valid());
    });

    session_group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
