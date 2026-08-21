# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `InMemorySessionStore::with_capacity(ttl, max_entries)` plus a
  `SessionStoreError::AtCapacity(usize)` variant and `len()` / `is_empty()`
  accessors so callers can bound the store's memory footprint and surface a
  503 once the ceiling is hit (audit finding L25).
- `tracing` instrumentation in `enforce_pkce_state_session`: every allow /
  reject outcome is emitted under the `authkit::audit` target with a
  redacted reason field, so operators get structured audit events without
  leaking session ids or state tokens (audit finding L5/L23/L27).
- `tracing` dependency in `Cargo.toml`.
- `CHANGELOG.md` (this file) to record release-time changes (audit finding L40).
- `.github/CODEOWNERS`, `.github/ISSUE_TEMPLATE/bug.yml`,
  `.github/ISSUE_TEMPLATE/feature.yml`, and
  `.github/pull_request_template.md` to round out the governance surface
  (audit finding L30/L33/L38).
- `Justfile` with a `ci` recipe that runs `fmt`, `clippy`, `test`, `doc`,
  and `deny` in one command so contributors and agents share a single
  verification entry point (audit finding L30/L38).
- `deny.toml` so `cargo-deny` in CI uses the same configuration the
  contributors do locally (audit finding L19/L28).

### Changed

- `.github/workflows/ci.yml`: pin every action by SHA, widen
  `permissions:`/`concurrency:` at the workflow level, and switch
  `runs-on` from `ubuntu-latest` to `ubuntu-24.04` (audit finding L9/L10).

[Unreleased]: https://github.com/KooshaPari/AuthKit/compare/main...HEAD