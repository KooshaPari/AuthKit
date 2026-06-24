# AuthKit — Agent Instructions

## Project identity
- **Boundary:** auth runtime (canonical Rust auth boundary).
- **Supersedes:** Authvault (archived at `c7994b9`).
- **Stack:** Rust (nightly), axum 0.7, tower 0.5, chrono, serde, thiserror.
- **Registry anchor:** `phenotype-registry/projects/AuthKit.json`.

## Boundaries (do not cross)
- This crate owns: session binding, token verification, PKCE state, RBAC/ABAC primitives, OAuth2/OIDC provider adapters.
- This crate does NOT own: persistence (use phenokits-commons store traits), event emission (use Eventra + OutboxStore from `phenotype-event-bus`), config (use Configra).

## Work-unit protocol
- Every non-trivial unit tracked in `agileplus-specs/{NNN-slug}/` with `meta.json` + `spec.md` + `plan.md` + `data-model.md` + `tasks/WP{NN}-{slug}.md`.
- Spec first, plan second, data model third, tasks fourth. Tests before code (TDD).

## Pre-commit gates
- `cargo +nightly fmt -- --check`
- `cargo +nightly clippy --all-targets -- -D warnings`
- `cargo +nightly test --all-features`
- `cargo +nightly doc --no-deps --all-features`

## Migration from Authvault
- `Authvault::X` -> `AuthKit::X` for all public types (deprecated aliases welcome in v0.x).
- 18 FRs from Authvault (FR-AUTHV-001..017) are inherited; FR-AUTHV-018 (PKCE state) shipped at commit `064b310`.

## Linked DAG units
- AUT-FR-018: PKCE state binding (shipped)
- AUT-SOTA-001..007: planned (OIDC discovery, WebAuthn, TOTP, KMS, DPoP, ABAC, Zanzibar-style authz)
- AUT-CRD-101: Authvault supersession cross-verification (resolved)
