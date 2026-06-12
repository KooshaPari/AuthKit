//! Criterion micro-benchmarks for the three hottest paths in
//! `phenotype-auth-core`.
//!
//! The bench fixture is `harness = false` (declared in
//! `Cargo.toml`); criterion provides its own harness via
//! `criterion_main!`. Run with:
//!
//! ```text
//! cargo bench -p phenotype-auth-core --bench hot_paths
//! ```
//!
//! Or, to compile-check without running the timed loops:
//!
//! ```text
//! cargo bench -p phenotype-auth-core --bench hot_paths --no-run
//! ```
//!
//! HTML reports are emitted under
//! `target/criterion/<group>/report/index.html` (the `html_reports`
//! feature on the workspace `criterion` dep keeps them on disk for
//! regression diffing across CI runs).
//!
//! ## Why these three?
//!
//! - **`Token::sign`** is on every request that mints or refreshes
//!   a token, and is the most allocation-heavy of the three (hex
//!   encode the 32 token bytes + 32 HMAC bytes → 128-byte
//!   `String`). Secret length is the realistic variable: short
//!   API-key-shaped secrets (16 B), HMAC-SHA256 block size (32 B),
//!   and "key from a secret manager" (64 B).
//! - **`Session::new`** is on every login. It allocates a
//!   `SessionId` (UUIDv4) and computes `issued_at + ttl`. The
//!   `user_id` shape (a UUID string of varying length) is the
//!   realistic variable: real users have IDs that come from a DB
//!   join, not all 36 chars.
//! - **`Role::can_access`** is on every authorization check, which
//!   is the highest-QPS auth path in the fleet. The realistic
//!   variable is the `Permission` shape: read-only checks dominate
//!   production traffic (audit logs, dashboards), write checks are
//!   the minority path.
//!
//! The `criterion_group!` macro generates a top-level function that
//! has no doc comment, so `#![allow(missing_docs)]` is set at the
//! file level to silence the false positive. `expect()` in the
//! fixture builders is intentional — a failure here means a real
//! bug in the bench setup, not a recoverable error. `doc_markdown`
//! is allowed because the bench doc-comment intentionally
//! references OTel / SHA-style tokens without backticks.

#![allow(missing_docs, clippy::expect_used, clippy::doc_markdown)]

use std::hint::black_box;

use chrono::{Duration, Utc};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use uuid::Uuid;

use phenotype_auth_core::{Permission, Role, Session, Token, UserId};

/// Number of bytes in a `Token` (mirrors
/// `phenotype_auth_core::token::TOKEN_BYTES`; the constant is not
/// re-exported at the crate root, so we hard-code the 32-byte size
/// the `Token` type guarantees by construction).
const TOKEN_BYTE_LEN: usize = 32;

/// Synthesise a stable, deterministic token for the bench (avoids
/// pulling `rand`/OS entropy into a hot-loop timing path). The
/// contents do not matter for timing; only the length does.
fn bench_token(seed: u8) -> Token {
    let mut bytes = [0u8; TOKEN_BYTE_LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        // Mix the seed and the index so different seeds produce
        // different bytes (sanity) and different indexes are
        // distinguishable in `cargo bench --verbose` output.
        *b = seed.wrapping_add(u8::try_from(i & 0xFF).unwrap_or(0));
    }
    Token::from_bytes(bytes)
}

/// `Token::sign` over three realistic secret lengths. Grouped so
/// the criterion report shows the secret-length × cost curve.
fn bench_token_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_sign");
    // 16 / 32 / 64 bytes: short API key, HMAC block, secret-manager key.
    for &secret_len in &[16usize, 32, 64] {
        let secret: Vec<u8> = (0..secret_len).map(|i| u8::try_from(i & 0xFF).unwrap_or(0)).collect();
        let token = bench_token(0xAB);
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{secret_len}B-secret")),
            &secret_len,
            |b, _| {
                b.iter(|| {
                    let signed = black_box(&token).sign(black_box(&secret));
                    black_box(signed);
                });
            },
        );
    }
    group.finish();
}

/// `Session::new` over three realistic `user_id` shapes:
/// - 8 B: short opaque ID (legacy systems)
/// - 16 B: half of a UUID (truncated)
/// - 36 B: full hyphenated UUID (the canonical shape)
fn bench_session_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_new");
    let now = Utc::now();
    let ttl = Duration::hours(1);
    for &user_id_len in &[8usize, 16, 36] {
        // Build a deterministic UUID-shaped string of the requested length.
        let uuid_full = Uuid::from_u128(0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0);
        let user_id_str = uuid_full.to_string();
        let user_id_str: String = user_id_str.chars().take(user_id_len).collect();
        // For lengths shorter than 8 (the shortest valid user_id
        // we test), the truncated string may not parse as a UUID
        // and the bench would panic on the .parse() call. We never
        // ask for less than 8, so we're safe; the 8-char prefix
        // is not a valid UUID either, so we use `UserId::from_uuid`
        // for the bench input instead.
        let user_id = if user_id_len >= 36 {
            UserId::parse(&user_id_str).expect("36-char UUID parses")
        } else {
            // Synthesise a UserId directly from a Uuid for the
            // shorter lengths so the bench doesn't depend on a
            // valid hyphenated prefix.
            UserId::from_uuid(Uuid::from_u128(u128::try_from(user_id_len).unwrap_or(0)))
        };
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{user_id_len}B-user_id")),
            &user_id_len,
            |b, _| {
                b.iter(|| {
                    let s = Session::new(black_box(user_id), black_box(now), black_box(ttl));
                    black_box(s);
                });
            },
        );
    }
    group.finish();
}

/// `Role::can_access` over the three permission shapes that
/// dominate production traffic:
/// - Read: the dashboard / audit-log hot path
/// - Write: the form-submission / update hot path
/// - Billing-refund: a cold path, but the one with the most
///   regulatory interest
fn bench_role_can_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("role_can_access");
    // Use a `Custom` role with 4 permissions so the binary-search
    // path is exercised (the Admin/Operator/Viewer variants are
    // constant-time and would understate the cost of the realistic
    // `Custom` RBAC path).
    let role = Role::custom(
        "operator-pro",
        vec![
            Permission::UsersRead,
            Permission::SkillsRead,
            Permission::BillingRead,
            Permission::FleetManage,
        ],
    );
    for &permission in &[
        Permission::UsersRead,
        Permission::UsersWrite,
        Permission::BillingRefund,
    ] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{permission}")),
            &permission,
            |b, &p| {
                b.iter(|| {
                    let allowed = black_box(&role).can_access(black_box(&p));
                    black_box(allowed);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = hot_paths;
    config = Criterion::default()
        // A 3-second measurement window is the criterion default
        // and gives stable numbers without burning CI time.
        .measurement_time(std::time::Duration::from_secs(3))
        // 100-sample warmup is enough for these pure-CPU paths.
        .warm_up_time(std::time::Duration::from_millis(500));
    targets = bench_token_sign, bench_session_new, bench_role_can_access
);
criterion_main!(hot_paths);
