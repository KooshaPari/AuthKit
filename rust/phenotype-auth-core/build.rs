//! Populates the `PHENOTYPE_TARGET` and `PHENOTYPE_GIT_SHA` env vars for
//! the downstream lib so `build_info()` can be a `const fn`.
//!
//! `TARGET` is a Cargo-provided env var that's only visible to build
//! scripts, not to library code. The same applies to the `git rev-parse`
//! output. We re-emit them as plain env vars the lib can `env!`.
//!
//! If `git` is not available (e.g. shallow clones, CI without a tag), we
//! fall back to `"unknown"` rather than failing the build.

use std::process::Command;

fn main() {
    // PHENOTYPE_TARGET
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
    println!("cargo:rustc-env=PHENOTYPE_TARGET={target}");

    // PHENOTYPE_GIT_SHA (best-effort; non-fatal)
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=PHENOTYPE_GIT_SHA={sha}");

    // Rebuild triggers.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PHENOTYPE_TARGET");
    println!("cargo:rerun-if-env-changed=PHENOTYPE_GIT_SHA");
}
