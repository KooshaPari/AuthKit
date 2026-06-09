# AuthKit Stub Inventory

> Generated 2026-05-05. Scan: TODO/FIXME/stub/placeholder/NOT IMPLEMENTED in `.rs`, `.py`, `.ts`, `.tsx`, `.go` files.
> **Total: 68 entries across 12 files.**

## Category: Intentional Namespace Stubs (56 entries)

These are deliberate `pheno` namespace stub packages that re-export from `pheno_auth.unified_auth`. Not production code.

| File | Line | Content |
|------|------|---------|
| `python/pheno-auth/src/pheno/__init__.py` | 1 | Stub package for pheno namespace — see AuthKit unified_auth for real implementations. |
| `python/pheno-auth/src/pheno/adapters/__init__.py` | 1 | Stub package for pheno.adapters namespace. |
| `python/pheno-auth/src/pheno/adapters/auth/__init__.py` | 1 | Stub package for pheno.adapters.auth namespace. |
| `python/pheno-auth/src/pheno/adapters/auth/providers/registry.py` | 1 | Stub providers registry module — re-exported from __init__. |
| `python/pheno-auth/src/pheno/adapters/auth/providers/registry.py` | 4 | from . import ProviderRegistryStub as ProviderRegistry |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 2 | Stub auth providers — real implementations live in pheno_auth.unified_auth |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 16 | class AuthProviderStub |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 17 | Stub auth provider — not for production use. |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 23-25 | Auth0Provider = AuthProviderStub, AuthKitProvider = AuthProviderStub, OAuth2GenericProvider = AuthProviderStub |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 28 | class ProviderRegistryStub |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 29 | Stub provider registry — not for production use. |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 36-37 | create_adapter returns AuthProviderStub |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 44 | ProviderRegistry = ProviderRegistryStub |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 45 | _stub_provider_registry = ProviderRegistryStub() |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 50-52 | create_provider_factory returns AuthProviderStub |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 56 | Stub registration — no-op. |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 60-61 | get_registry returns _stub_provider_registry |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 65-67 | get_provider_registry returns _stub_provider_registry |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 73 | "AuthProviderStub" in __all__ |
| `python/pheno-auth/src/pheno/adapters/auth/providers/__init__.py` | 76 | "ProviderRegistryStub" in __all__ |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 1-2 | MFA module: Stub MFA adapters |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 30 | class MFAAdapterStub |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 31 | Stub MFA adapter — not for production use. |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 32-33 | create_adapter returns MFAAdapterStub |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 38 | Stub registration — no-op. |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 42 | class MFAAdapterRegistryStub |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 43 | Stub MFA registry — not for production use. |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 48-49 | create returns MFAAdapterStub |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 53 | _stub_mfa_registry = MFAAdapterRegistryStub() |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 58-59 | get_registry returns _stub_mfa_registry |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 63-64 | get_mfa_registry returns _stub_mfa_registry |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 71 | "MFAAdapterRegistryStub" in __all__ |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/__init__.py` | 72 | "MFAAdapterStub" in __all__ |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/registry.py` | 1-3 | Stub MFA registry module |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/registry.py` | 6 | class MFAProviderRegistryStub |
| `python/pheno-auth/src/pheno/adapters/auth/mfa/registry.py` | 7 | Stub MFA provider registry. |

## Category: Functional Placeholders (4 entries)

| File | Line | Content |
|------|------|---------|
| `python/pheno-security/src/pheno_security/scanners/scanner.py` | 250 | Note: This is a placeholder. For full implementation, use trufflehog CLI. |
| `python/pheno-security/src/pheno_security/scanners/scanner.py` | 274 | Note: This is a placeholder. For full implementation, use trufflehog CLI. |
| `python/pheno-credentials/src/pheno_credentials/oauth/automation.py` | 326 | This is a placeholder - in a real implementation, you'd integrate... |
| `python/pheno-credentials/src/pheno_credentials/oauth/automation.py` | 370 | This is a placeholder - in a real implementation, you'd query... |

## Category: Not Implemented (1 entry)

| File | Line | Content |
|------|------|---------|
| `python/pheno-auth/src/pheno_auth/playwright_adapter.py` | 97 | raise NotImplementedError("Playwright browser startup not implemented") |

## Category: Route Stubs (2 entries)

| File | Line | Content |
|------|------|---------|
| `python/pheno-auth/src/pheno_auth/routes/api_keys.py` | 63 | Dummy dependency stubs — replace with your real auth middleware |
| `python/pheno-auth/src/pheno_auth/routes/api_keys.py` | 68 | Stub: return the authenticated user's UUID. |

## Category: Rust Stubs (3 entries)

| File | Line | Content |
|------|------|---------|
| `rust/phenotype-contracts/src/lib.rs` | 145 | // Stub implementation |
| `rust/phenotype-contracts/src/lib.rs` | 149 | // Stub implementation |
| `rust/phenotype-contracts/src/lib.rs` | 153 | // Stub implementation |

## Category: TODO (1 entry)

| File | Line | Content |
|------|------|---------|
| `go/middleware/middleware.go` | 92 | // TODO: Add actual dependency checks (DB, cache, etc.) |
