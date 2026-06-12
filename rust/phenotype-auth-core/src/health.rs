//! Health-check helpers for phenotype-auth-core.
//!
//! Exposes [`auth_health`] which returns a [`HealthSnapshot`] containing
//! the crate version, the build profile, and the git SHA. The shape
//! mirrors `phenotype-build-info::BuildInfo` but is scoped to the auth
//! crate (so a consumer can log "auth health" without pulling in
//! build-info directly).
//!
//! `BuildInfo` is inlined here as a private helper struct to avoid the
//! upstream `phenotype-build-info` dep on this sub-crate; the public
//! `crate::BuildInfo` re-export is the canonical version.

use serde::{Deserialize, Serialize};

use crate::BuildInfo;

/// Snapshot of the auth crate's runtime identity, suitable for
/// embedding in `/health`, `/version`, or OpenTelemetry `resource`
/// attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    /// The auth crate's version (sourced from `env!("CARGO_PKG_VERSION")`).
    pub version: String,
    /// Whether this is a release build.
    pub release_build: bool,
    /// The git SHA the binary was built from, if available.
    pub git_sha: String,
    /// The build profile (`debug` / `release` / `test`).
    pub build_profile: String,
    /// The Rust target triple.
    pub target_triple: String,
}

impl HealthSnapshot {
    /// Constructs a `HealthSnapshot` from a `BuildInfo`.
    pub fn from_build_info(info: &BuildInfo) -> Self {
        Self {
            version: info.version.to_string(),
            release_build: !cfg!(debug_assertions),
            git_sha: info.git_sha.to_string(),
            build_profile: info.build_profile.to_string(),
            target_triple: info.target_triple.to_string(),
        }
    }
}

impl std::fmt::Display for HealthSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "phenotype-auth-core v{} ({} build, sha {}, target {})",
            self.version, self.build_profile, self.git_sha, self.target_triple
        )
    }
}

/// Returns the current auth crate's [`HealthSnapshot`]. Cheap to call;
/// all fields are `const` or computed once at startup.
pub fn auth_health() -> HealthSnapshot {
    HealthSnapshot::from_build_info(&crate::build_info())
}

/// A trivial snapshot for compile-time-ish use. Lacks the git SHA
/// and target triple (those are runtime fields) but is enough for
/// `format!` calls in callers that only need the version + profile.
pub fn version_only_health() -> HealthSnapshot {
    HealthSnapshot {
        version: crate::VERSION.to_string(),
        release_build: !cfg!(debug_assertions),
        git_sha: String::new(),
        build_profile: if cfg!(debug_assertions) { "debug" } else { "release" }.to_string(),
        target_triple: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VERSION;

    #[test]
    fn auth_health_returns_populated_snapshot() {
        let h = auth_health();
        assert!(!h.version.is_empty());
        assert!(!h.to_string().is_empty());
    }

    #[test]
    fn version_only_health_matches_version_constant() {
        let h = version_only_health();
        assert_eq!(h.version, VERSION);
    }

    #[test]
    fn health_snapshot_serializes_to_json() {
        let h = auth_health();
        let json = serde_json::to_string(&h).unwrap();
        let back: HealthSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }
}
