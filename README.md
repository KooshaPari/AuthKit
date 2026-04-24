# AuthKit

Unified, cross-platform authentication SDK providing secure identity and access management across Rust, TypeScript, Python, and Go. Implements OAuth 2.0, OpenID Connect, SAML 2.0, and WebAuthn with a consistent, ergonomic API surface across all language bindings.

## Overview

**AuthKit** is the de facto standard authentication framework for the Phenotype ecosystem. It abstracts away protocol complexity while maintaining strict standards compliance and security-first design. Build secure authentication flows in any language with unified API patterns, battle-tested implementations, and zero cognitive switching costs.

**Core Mission**: Deliver language-unified authentication that makes building secure, standards-compliant authentication flows as simple as installing a library.

## Technology Stack

- **Languages**: Rust, TypeScript/JavaScript, Python, Go (cross-platform)
- **Protocols**:
  - OAuth 2.0 (Authorization Code, Client Credentials, Device Code, PKCE)
  - OpenID Connect (identity layer on OAuth 2.0)
  - SAML 2.0 (enterprise SSO)
  - WebAuthn/Passkeys (passwordless authentication)
  - JWT (token generation, validation, refresh)
- **Security**: Built-in protections (CSRF, XSS mitigation), secure defaults, automatic best practices
- **Providers**: Auth0, Okta, AWS Cognito, Keycloak, Google, GitHub, and custom OIDC servers

## Key Features

- **Language-Unified API**: Identical concepts, patterns, and method names across Rust, TypeScript, Python, and Go
- **Protocol Abstraction**: Handle OAuth/OIDC/SAML complexity internally; intuitive high-level APIs
- **Security-First**: Secure defaults, automatic best practices, built-in CSRF/XSS protections
- **Provider Agnostic**: Single integration point for multiple identity providers
- **Type Safety**: Leverages native type systems (Rust's type safety, TypeScript generics, Python dataclasses, Go interfaces)
- **Enterprise Ready**: Support for SAML, custom claims, fine-grained access control

## Quick Start

```bash
# Clone and explore
git clone <repo-url>
cd AuthKit

# Review architecture and requirements
cat CLAUDE.md          # Governance & constraints
cat PRD.md             # Full product specification
cat AGENTS.md          # Agent operating contract

# Explore language-specific implementations
ls -la rust/           # Rust crates
ls -la typescript/     # TypeScript/Node.js packages
ls -la python/         # Python packages
ls -la go/             # Go modules

# Example: Build and test Rust implementation
cd rust && cargo build && cargo test --workspace
```

## Project Structure

```
AuthKit/
├── rust/              # Rust crates (authkit-core, authkit-provider-*)
├── typescript/        # TypeScript packages (npm packages)
├── python/            # Python packages (PyPI packages)
├── go/                # Go modules (pkg.go.dev modules)
├── docs/              # Shared documentation & guides
├── examples/          # Multi-language integration examples
└── CLAUDE.md, AGENTS.md, PRD.md
```

## Supported Auth Flows

| Flow | Support | Use Case |
|------|---------|----------|
| OAuth 2.0 Authorization Code + PKCE | ✓ | Web apps, SPAs, mobile clients |
| OAuth 2.0 Client Credentials | ✓ | Service-to-service, machine-to-machine |
| OAuth 2.0 Device Code | ✓ | Input-constrained devices (CLI, IoT) |
| OpenID Connect | ✓ | Identity + authentication |
| SAML 2.0 | ✓ | Enterprise SSO |
| WebAuthn/Passkeys | ✓ | Passwordless authentication |
| JWT Validation | ✓ | Token introspection, API security |

## Status

🚧 Under construction — Phase 2 implementation (enterprise features, SDK hardening)

## Related Phenotype Projects

- **[PhenoPlugins](../PhenoPlugins)** — Plugin system supporting auth-aware extensions
- **[McpKit](../McpKit)** — MCP tooling with AuthKit integration
- **[bifrost-extensions](../bifrost-extensions)** — API gateway with unified authentication