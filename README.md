# AuthKit

**Comprehensive authentication and authorization SDK for Phenotype**

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![Security: Best Practices](https://img.shields.io/badge/Security-Best%20Practices-green.svg)](#security)

## Overview

AuthKit provides a complete authentication and authorization framework with:

- **OAuth2/OIDC** - Industry-standard authentication flows
- **JWT** - Secure token generation and validation
- **RBAC/ABAC** - Role and attribute-based access control
- **Multi-tenant** - Full multi-tenancy support
- **Multiple backends** - Database, Redis, and more

## Crates

| Crate | Description |
|-------|-------------|
| `phenotype-auth` | Complete auth framework with OAuth2, JWT, RBAC/ABAC |
| `phenotype-cipher` | Cryptographic operations |
| `phenotype-content-hash` | Content hashing utilities |
| `phenotype-bid` | Bidirectional encoding |
| `phenotype-contracts` | Shared contract definitions |
| `phenotype-authz-engine` | Policy evaluation engine |
| `phenotype-security-aggregator` | Security aggregation |

## Quick Start

```toml
[dependencies]
phenotype-auth = "0.1"
tokio = { version = "1", features = ["full"] }
```

```rust
use phenotype_auth::{AuthService, JwtConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let auth = AuthService::new(JwtConfig::default())?;
    
    // Generate token
    let token = auth.generate_token("user123", vec!["admin".to_string()])?;
    
    // Validate token
    let claims = auth.validate_token(&token)?;
    
    println!("Authenticated: {}", claims.subject);
    Ok(())
}
```

## Features

### OAuth2/OIDC
- Authorization Code Flow
- Client Credentials Flow
- Refresh Token Flow
- OpenID Connect Support

### JWT
- HS256, RS256, ES256 support
- Custom claims
- Token expiration
- Refresh tokens

### Access Control
- RBAC (Role-Based)
- ABAC (Attribute-Based)
- Permission hierarchies
- Tenant isolation

### Multi-tenancy
- Tenant isolation
- Cross-tenant access control
- Tenant-specific configurations

## Security

- Argon2 password hashing
- Rate limiting
- CSRF protection
- Secure token storage
- Audit logging

## Examples

See `examples/` directory for complete examples:
- `basic_auth` - Simple username/password
- `jwt_auth` - JWT token handling
- `rbac` - Role-based access control
- `oauth2` - OAuth2 flows
- `multi_tenant` - Multi-tenancy

## License

MIT OR Apache-2.0
