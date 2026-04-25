use authvault::{
    domain::policy::{Condition, Policy, PolicyEffect, PolicyEngine},
    domain::{Role, UserId},
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;

fn bench_claims_creation(c: &mut Criterion) {
    let user_id = UserId::new();
    let roles = vec![Role::new("admin"), Role::new("user")];

    c.bench_function("claims_new", |b| {
        b.iter(|| authvault::domain::auth::Claims::new(black_box(&user_id), black_box(&roles)));
    });
}

fn bench_token_generation(c: &mut Criterion) {
    let auth = authvault::Authenticator::new("benchmark_secret_key_12345");
    let user_id = UserId::new();
    let roles = vec![Role::new("admin")];

    c.bench_function("token_generation", |b| {
        b.iter(|| auth.generate_token(black_box(&user_id), black_box(&roles)));
    });
}

fn bench_token_verification(c: &mut Criterion) {
    let auth = authvault::Authenticator::new("benchmark_secret_key_12345");
    let user_id = UserId::new();
    let roles = vec![Role::new("admin")];
    let token = auth.generate_token(&user_id, &roles).unwrap();

    c.bench_function("token_verification", |b| {
        b.iter(|| auth.verify_token(black_box(&token)));
    });
}

fn bench_condition_eq_evaluate(c: &mut Criterion) {
    let condition =
        Condition::Eq { attribute: "role".to_string(), value: serde_json::json!("admin") };
    let mut attrs = HashMap::new();
    attrs.insert("role".to_string(), serde_json::json!("admin"));

    c.bench_function("condition_eq_evaluate", |b| {
        b.iter(|| condition.evaluate(black_box(&attrs)));
    });
}

fn bench_condition_regex_evaluate(c: &mut Criterion) {
    let condition = Condition::Regex {
        attribute: "email".to_string(),
        pattern: r"^[\w.-]+@[\w.-]+\.\w+$".to_string(),
    };
    let mut attrs = HashMap::new();
    attrs.insert("email".to_string(), serde_json::json!("test@example.com"));

    c.bench_function("condition_regex_evaluate", |b| {
        b.iter(|| condition.evaluate(black_box(&attrs)));
    });
}

fn bench_condition_and_evaluate(c: &mut Criterion) {
    let condition = Condition::And {
        conditions: vec![
            Condition::Eq { attribute: "role".to_string(), value: serde_json::json!("admin") },
            Condition::Eq {
                attribute: "department".to_string(),
                value: serde_json::json!("engineering"),
            },
        ],
    };
    let mut attrs = HashMap::new();
    attrs.insert("role".to_string(), serde_json::json!("admin"));
    attrs.insert("department".to_string(), serde_json::json!("engineering"));

    c.bench_function("condition_and_evaluate", |b| {
        b.iter(|| condition.evaluate(black_box(&attrs)));
    });
}

fn bench_policy_creation(c: &mut Criterion) {
    c.bench_function("policy_creation", |b| {
        b.iter(|| {
            Policy::new(
                black_box("test_policy"),
                black_box("documents:*"),
                black_box(PolicyEffect::Allow),
            )
            .with_action(black_box("read"))
            .with_action(black_box("write"))
            .with_priority(black_box(10))
        });
    });
}

fn bench_policy_evaluate(c: &mut Criterion) {
    let policy = Policy::new("test", "documents:*", PolicyEffect::Allow)
        .with_action("read")
        .with_condition(Condition::Eq {
            attribute: "classification".to_string(),
            value: serde_json::json!("public"),
        });

    let mut attrs = HashMap::new();
    attrs.insert("classification".to_string(), serde_json::json!("public"));

    c.bench_function("policy_evaluate", |b| {
        b.iter(|| policy.evaluate(black_box(&attrs)));
    });
}

fn bench_policy_engine_evaluate(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();

    engine.add_policy(
        Policy::new("read-all", "documents:*", PolicyEffect::Allow)
            .with_action("read")
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

    c.bench_function("policy_engine_evaluate", |b| {
        b.iter(|| {
            engine.evaluate(black_box("documents:123"), black_box("read"), black_box(&attrs))
        });
    });
}

fn bench_policy_engine_with_many_policies(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();

    for i in 0..100 {
        engine.add_policy(
            Policy::new(format!("policy_{}", i), "documents:*", PolicyEffect::Allow)
                .with_action("read")
                .with_priority(i),
        );
    }

    let attrs = HashMap::new();

    c.bench_function("policy_engine_evaluate_100_policies", |b| {
        b.iter(|| {
            engine.evaluate(black_box("documents:123"), black_box("read"), black_box(&attrs))
        });
    });
}

fn bench_user_id_creation(c: &mut Criterion) {
    c.bench_function("user_id_creation", |b| {
        b.iter(UserId::new);
    });
}

fn bench_role_creation(c: &mut Criterion) {
    c.bench_function("role_creation", |b| {
        b.iter(|| Role::new(black_box("admin")));
    });
}

criterion_group!(
    benches,
    bench_claims_creation,
    bench_token_generation,
    bench_token_verification,
    bench_condition_eq_evaluate,
    bench_condition_regex_evaluate,
    bench_condition_and_evaluate,
    bench_policy_creation,
    bench_policy_evaluate,
    bench_policy_engine_evaluate,
    bench_policy_engine_with_many_policies,
    bench_user_id_creation,
    bench_role_creation
);
criterion_main!(benches);
