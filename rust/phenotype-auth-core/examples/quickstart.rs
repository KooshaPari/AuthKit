//! Quickstart for `phenotype-auth-core`.
//!
//! Walks through the canonical auth lifecycle:
//!
//! 1. Construct a [`User`] with a [`Role`].
//! 2. Open a [`Session`] (24-hour TTL by default).
//! 3. Sign a [`Token`] and verify the signature round-trips.
//! 4. Print a `version_only_health()` snapshot for `/health` endpoints.
//!
//! Run with: `cargo run -p phenotype-auth-core --example quickstart`.
//! `expect()` in example code is intentional — failure means a real
//! bug in `phenotype-auth-core`, not a recoverable error.
#![allow(clippy::expect_used)]

use phenotype_auth_core::health::version_only_health;
use phenotype_auth_core::{Permission, Role, Session, Token, User, UserId};

fn main() {
    // 1. Build a User. `UserId::new_v4()` mints a random UUIDv4;
    // production code would parse the ID from a session cookie or
    // a JWT claim rather than minting a fresh one.
    let user = User::new(
        UserId::new_v4(),
        "koosha@phenotype.dev".into(),
        "Koosha Pari".into(),
        Role::Admin,
    );
    println!("user.id      = {}", user.id());
    println!("user.role    = {}", user.role().name());

    // Admin can do everything, including issuing billing refunds.
    assert!(user.role().can_access(&Permission::billing_refund()));
    println!("admin can refund billing: ok");

    // 2. Open a Session (24-hour default TTL). The session tracks
    // its own issued_at and expires_at; callers extend / revoke
    // it via the Session methods.
    let session = Session::new_default(user.id());
    println!(
        "session.id        = {}\nsession.expires_at = {}",
        session.id(),
        session.expires_at()
    );

    // 3. Sign + verify a Token. The signing secret should be loaded
    // from a secret manager in production; the literal here is a
    // bench-grade placeholder.
    let token = Token::generate();
    let secret = b"do-not-commit-this-secret";
    let signed = token.sign(secret);
    let recovered = Token::verify(&signed, secret).expect("verify with the same secret succeeds");
    assert_eq!(recovered, token);
    println!("token.redact()    = {}", token.redact());

    // 4. Health snapshot. `version_only_health()` is the cheap
    // (no git SHA, no target triple) variant suitable for high-QPS
    // `/health` endpoints; the full `auth_health()` is for
    // `/version` / debug pages.
    let health = version_only_health();
    println!("health.version    = {}", health.version);
    println!("health.build      = {}", health.build_profile);
    println!("OK");
}
