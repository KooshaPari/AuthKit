# `auth-core`

[![docs.rs](https://img.shields.io/docsrs/phenotype-auth-core)](https://docs.rs/phenotype-auth-core)
[![MSRV](https://img.shields.io/badge/MSRV-1.81-blue)](https://github.com/rust-lang/rust/releases/tag/1.81.0)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../LICENSE)

Canonical Rust auth domain model: `User`, `UserId`, `Role`, `Permission`,
`Session`, `SessionId`, `Token`, `AuthError`, `health::HealthSnapshot`,
`auth_health()`, `version_only_health()`.

## Status

| Field | Value |
|-------|-------|
| Layer | Foundation / Domain |
| Category | Auth |
| Test coverage | High (12 integration tests) |
| Public surface | `User`, `UserId`, `Role`, `Permission`, `Session`, `SessionId`, `Token`, `AuthError`, `health::*`, `VERSION` |
| FFI targets | PyO3, napi-rs, cgo, uniffi, cbindgen (planned) |

## Why this crate exists

Brings the 26,500-LOC Python auth code in `AuthKit/` under a single
Rust crate's authority. See
`PHENOTYPE_5REPO_MODERNIZATION_PLAN.md §8.4` and
`plans/2026-06-09-auth-fleet-world-map-v1.md` for the consolidation
strategy.

## Features

- **`User` + `UserId`** — UUIDv4-backed identifier, `Display` +
  `FromStr`, JSON-safe.
- **`Role` + `Permission`** — RBAC: `Admin`, `Operator`, `Viewer`,
  `Custom`, with a `can_access()` permission matrix.
- **`Session` + `SessionId`** — open, close, extend, `is_active`,
  `is_expired`, `expires_at`.
- **`Token`** — sign, verify, redacted `Display`, raw accessor that
  skips the `Display` impl.
- **`AuthError`** — 10 variants covering signature, expiry, parse,
  permission, etc.
- **`health::HealthSnapshot`** + `auth_health()` +
  `version_only_health()` — sourced from `phenotype-build-info`,
  matching the Eidolon §7.1 propagation pattern.
- **`VERSION`** — sourced from `phenotype-build-info::pkg_version()`.
- **`build_info()`** — re-export of the canonical `BuildInfo`.
- **`password::PasswordHasher`** + **`Argon2Hasher`** — Argon2id password
  hashing with `hash_password()` + `verify_password()`.

## Quick start

```rust,ignore
use phenotype_auth_core::{Role, Permission, User, UserId};

let user = User::new(
    UserId::new_v4(),
    "koosha@phenotype.dev".into(),
    "Koosha Pari".into(),
    Role::Admin,
);
assert!(user.role().can_access(&Permission::users_write()));
assert!(!user.role().can_access(&Permission::billing_refund()));
```

## License

MIT — see [LICENSE](../../LICENSE).
