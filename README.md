# AuthKit

AuthKit is the canonical Rust auth boundary in the KooshaPari phenotype
ecosystem. It is the successor to the now-archived
[`Authvault`](https://github.com/KooshaPari/Authvault) repository and
absorbs the FRs that landed in `Authvault` worktrees but were never merged
into `Authvault` main before the archive marker (commit `c7994b9`).

## Status

- **FR-AUTHV-018** — PKCE state→session binding at middleware: **SHIPPED** (this crate, PR #1).
- **AUT-SOTA-001..007** — Asymmetric key rotation, OIDC discovery, WebAuthn, TOTP, KMS-backed secrets, DPoP, rate-limiting: **PLANNED**.

See `specs/requirements/authkit-frnfr.md` for the full traceability table.

## Crate layout

```
src/
  lib.rs                   — pub mod re-exports
  domain/
    mod.rs
    session_store.rs       — SessionStore trait + InMemorySessionStore
  middleware/
    mod.rs
    pkce_state_session.rs  — axum/tower middleware enforcing FR-AUTHV-018
```

## Quick start

```rust
use std::sync::Arc;
use authkit::{enforce_pkce_state_session, InMemorySessionStore, SessionStore};
use axum::{routing::get, Router};

let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
store.bind_state("state-token-abc", "session-cookie-xyz").unwrap();

let app = Router::new()
    .route("/oauth/callback", get(|| async { "ok" }))
    .route_layer(axum::middleware::from_fn_with_state(
        store.clone(),
        enforce_pkce_state_session,
    ));
```

## Migration from Authvault

`Authvault` users should add this dependency:

```toml
[dependencies]
authkit = { git = "https://github.com/KooshaPari/AuthKit" }
```

and replace:

```rust
use authvault::middleware::enforce_pkce_state_session;
```

with:

```rust
use authkit::enforce_pkce_state_session;
```

`Authvault`'s 18 FRs (FR-AUTHV-001..017) are unchanged and remain on
`Authvault` main (pinned at commit `c7994b9`).

## Why a new repo

`Authvault` was archived because the boundary owner responsibility for
new auth work moved from the old crate to this one. The boundary SSOT
entry for Authvault in [`phenotype-registry`](https://github.com/KooshaPari/phenotype-registry)
reflects this: `status: archived-superseded`, `superseded_by: AuthKit`.

## Test plan

- `cargo +nightly test` — 11 unit tests across 2 modules.
- Wire into a consumer's axum router and verify the 401-on-mismatch path against a real OAuth provider.

## License

TBD.
