//! Integration smoke test for `auth-core`.
//!
//! Verifies the crate compiles as a downstream dependency and the
//! `Cargo.toml` metadata contract is intact (workspace inheritance).
//!
//! (The existing `tests/integration.rs` covers the runtime surface.)

#[test]
fn test_crate_metadata_contract() {
    assert_eq!(env!("CARGO_PKG_NAME"), "phenotype-auth-core");
    let _major: u32 = env!("CARGO_PKG_VERSION_MAJOR")
        .parse()
        .expect("CARGO_PKG_VERSION_MAJOR must be a valid u32");
}

#[test]
fn test_password_hashing_roundtrip() {
    use phenotype_auth_core::{Argon2Hasher, PasswordHasher, PasswordHashError};
    let hasher = Argon2Hasher::default();
    let password = "correct-horse-battery-staple";
    let hash = hasher.hash(password);
    assert!(hash.is_ok(), "Argon2 hashing should succeed");
    let hash = hash.unwrap();
    assert!(hash.starts_with("$argon2"), "Output should be an argon2 hash");
    let verify = hasher.verify(password, &hash);
    assert!(verify.is_ok(), "Verification should succeed");
    assert!(verify.unwrap(), "Password should match hash");
    let wrong_verify = hasher.verify("wrong-password", &hash);
    assert!(wrong_verify.is_ok(), "Wrong-password verification should return Ok(false)");
    assert!(!wrong_verify.unwrap(), "Wrong password should not match hash");
}
