# phenotype-authvault-application

Authvault's application layer (`AuthService`) migrated to the AuthKit
workspace as a sub-crate. V20 AUTH cluster step 3/5.

## Purpose

Thin orchestration over the [`phenotype-authvault-domain`] ports. The
HTTP / gRPC adapters (planned in step 4/5) consume this service.

## Crate position

```
phenotype-authvault-domain  (ports, entities, pure logic)
            ↓
phenotype-authvault-application  ← you are here (AuthService)
            ↓
phenotype-authvault-adapters  (HTTP / Postgres / Redis)  [step 4/5]
phenotype-authvault-app      (binary entry point)       [step 5/5]
```

## Public surface

- `AuthService` — the single exported type. Constructed via
  `AuthService::new(secret, user_storage, session_storage, hasher)`.
- Async methods: `register`, `login`, `logout`, `logout_all`,
  `get_user`.
- Sync methods: `verify_token`, `validate_bearer_token`,
  `refresh_token`, `authorize`.

## Build

```bash
cargo check -p phenotype-authvault-application
cargo test  -p phenotype-authvault-application
```

## Status

- [x] Source lifted from `Authvault/src/application/services.rs`
- [x] Path rewrite (`crate::domain::` → `phenotype_authvault_domain::`)
- [x] Cargo.toml + lib.rs in place
- [x] `cargo check` clean
- [ ] Tests (deferred — upstream tests live in the cross-layer
      `tests/unit_tests.rs` and reference the `app/` layer that
      hasn't been migrated yet)
