# Migrating from Authvault to AuthKit

> Authvault was archived on 2026-07-05. AuthKit is the canonical Rust auth
> boundary in the KooshaPari phenotype ecosystem. This doc helps consumers
> migrate.

## Why

Authvault is archived. The successor is [AuthKit](https://github.com/KooshaPari/AuthKit).
AuthKit absorbs the Authvault FRs and adds new SOTA features.

## FR mapping

| Authvault FR | AuthKit equivalent | Status |
|---|---|---|
| FR-AUTHV-018 (PKCE state->session binding) | FR-AUTHV-018 (PKCE) | SHIPPED in AuthKit (#1) |
| GAP-008 (PKCE middleware) | (port pending) | TRACKED in D1-blocker |
| gap-010 (middleware adapter docs) | (port pending) | TRACKED in D1-blocker |
| AUT-SOTA-001 (OIDC Discovery 1.0 + JWKS) | AUT-SOTA-001 | SHIPPED in AuthKit (#2) |
| AUT-SOTA-003 (WebAuthn L3) | AUT-SOTA-003 | SHIPPED in AuthKit (#3) |
| AUT-SOTA-004 (TOTP RFC 6238) | AUT-SOTA-004 | SHIPPED in AuthKit (#4) |
| AUT-SOTA-002 (asymmetric key rotation) | AUT-SOTA-002 | PLANNED |
| AUT-SOTA-005 (KMS-backed secrets) | AUT-SOTA-005 | PLANNED |
| AUT-SOTA-006 (DPoP) | AUT-SOTA-006 | PLANNED |
| AUT-SOTA-007 (rate-limiting) | AUT-SOTA-007 | PLANNED |

## Code migration

### Imports

Replace:
```rust
use authvault::auth::{SessionStore, InMemorySessionStore};
use authvault::middleware::pkce_state_session;
```
With:
```rust
use authkit::domain::session_store::{SessionStore, InMemorySessionStore};
use authkit::middleware::pkce_state_session;
```

### Trait surface

AuthKit exposes the `SessionStore` trait in `src/domain/session_store.rs`.
Authvault's `auth.SessionStore` is the conceptual predecessor but had
slightly different method signatures. Mapping:

| Authvault method | AuthKit method | Notes |
|---|---|---|
| `get_session(id) -> Session` | `get(&self, id: &SessionId) -> Option<Session>` | renamed + returns Option |
| `put_session(session)` | `insert(&self, session: Session)` | renamed |
| `delete_session(id)` | `remove(&self, id: &SessionId) -> bool` | renamed + returns bool |
| `purge_expired()` | `purge_expired(&self) -> usize` | returns count |

### Middleware

Authvault's `pkce_state_session` middleware (FR-AUTHV-018 / GAP-008)
maps to AuthKit's `pkce_state_session` middleware, but the AuthKit
version **enforces** the state->session binding at middleware layer
(it was optional in Authvault). If your code relied on optional
binding, add an explicit bypass (not recommended).

### In-tree vs custom SessionStore

AuthKit ships `InMemorySessionStore` only. For Redis, Postgres, or
other backends, implement the trait in your app:

```rust
use authkit::domain::session_store::{SessionStore, Session, SessionId};

pub struct MyRedisStore { /* ... */ }

#[async_trait]
impl SessionStore for MyRedisStore {
    async fn get(&self, id: &SessionId) -> Option<Session> { /* ... */ }
    async fn insert(&self, session: Session) { /* ... */ }
    async fn remove(&self, id: &SessionId) -> bool { /* ... */ }
    async fn purge_expired(&self) -> usize { /* ... */ }
}
```

## Step-by-step

1. Bump `Cargo.toml` to depend on `authkit = "0.1"`.
2. Replace import paths (see above).
3. `cargo build` -- expect a few method-name errors per the table.
4. Migrate any custom `SessionStore` impl per the trait signature table.
5. `cargo test` -- AuthKit's conformance suite is in `src/domain/session_store.rs`.
6. Open issues against AuthKit for any gaps you find.

## Gap status (D1 RESOLVED 2026-07-05)

GAP-008 (PKCE state->session binding at middleware) and gap-010
(middleware adapter docs) that the original Authvault PRs claimed to
add were actually **no-op commits** in the Authvault repo (identical
tree SHAs across the supposed feature commits and their parents).
The actual PKCE work shipped in AuthKit's initial landing commit
`064b310 feat: AuthKit initial landing -- FR-AUTHV-018 PKCE state binding`
(`src/middleware/pkce_state_session.rs`, ~292 lines, + the
`src/domain/session_store.rs` hexagonal port, ~252 lines).

**D1 path A is complete with 0 port PRs needed.** Authvault was set
to GitHub Archived: True on 2026-07-05T04:54:25Z. The blocker doc at
`docs/sessions/2026-07-05-polyrepo-portfolio-strategy/05-decisions/02-D1-blocker-authvault-authkit-state.md`
and the resolution at
`docs/sessions/2026-07-05-polyrepo-portfolio-strategy/05-decisions/03-D1-RESOLVED-no-port-needed.md`
document the full audit.

If you were looking for GAP-008/010 work to land in AuthKit: it already
did (in 064b310). No further action needed for the migration path.

## Help

Open issues at https://github.com/KooshaPari/AuthKit/issues.
