# phenotype-authvault-adapters

Outbound port adapters for the [`phenotype-authvault-domain`](../phenotype-authvault-domain) auth
domain. Step 4/5 of the V20 AUTH-cluster canonical-merge pass (see
[`V20_CROSSREPO_CANONICAL_AUDIT.md`](../../../V20_CROSSREPO_CANONICAL_AUDIT.md)).

## Purpose

Lifts the `src/adapters/` directory of the standalone Authvault/ repo (8 files,
~1,200 LOC) into AuthKit as a sub-crate. These are the concrete implementations
of the outbound port traits declared in `phenotype-authvault-domain`:

| Module | Trait / Type | Backend |
|---|---|---|
| `audit` | `AuditSink` | In-memory broadcast channel |
| `hashers` | `PasswordHasher` | Argon2id default + a `DisabledPasswordHasher` (test) |
| `kms` | `KeyManagementService` | Local-process stub (real KMS in step 5) |
| `refresh_token` | `RefreshTokenStore` | In-memory HashMap |
| `revocation` | `RevocationStore` | In-memory set with TTL sweep |
| `storage` | `UserStorage` + session sweep | In-memory HashMap |
| `vault_store` | `SecretVault` | File-backed encrypted store (chacha20poly1305) |

## Crate position

```
phenotype-authvault-domain     (step 2: ports + domain types)
        ↑
phenotype-authvault-application (step 3: AuthService)
        ↑
phenotype-authvault-adapters    (step 4: this crate)   ← we are here
        ↑
phenotype-authvault-app         (step 5: HTTP binary — TODO)
```

## Public surface

All modules are `pub`; all concrete types are `Send + Sync`. The intended
wiring is:

```rust
use std::sync::Arc;
use phenotype_authvault_adapters::{
    audit::InMemoryAuditSink, hashers::Argon2PasswordHasher, storage::InMemoryUserStorage,
    refresh_token::InMemoryRefreshTokenStore, revocation::InMemoryRevocationStore,
    vault_store::FileVaultStore,
};
use phenotype_authvault_application::AuthService;
use phenotype_authvault_domain::ports::{KeyManagementService, SecretVault};

let audit = Arc::new(InMemoryAuditSink::new(1024));
let users = Arc::new(InMemoryUserStorage::new());
let refresh = Arc::new(InMemoryRefreshTokenStore::new());
let revocation = Arc::new(InMemoryRevocationStore::default());
let vault: Arc<dyn SecretVault> = Arc::new(FileVaultStore::new("/var/secrets", /* kms */ None));
let kms: Arc<dyn KeyManagementService> = Arc::new(/* ... */);

let auth = AuthService::new(
    "secret".to_string(), users, /* SessionStorage */ ..., Argon2PasswordHasher::default(),
);
```

## Build

```sh
cargo check -p phenotype-authvault-adapters
cargo test  -p phenotype-authvault-adapters
```

## Status

Landed in `migration/v20-auth-cluster-2026-06-12` step 4/5. Builds clean.
Tests pass (deferred from step-2 since the upstream Authvault tests
reference `crate::adapters::` paths that this isolated sub-crate doesn't have
— the test port comes with step 5 when the application binary is migrated).
