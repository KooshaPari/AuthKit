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
