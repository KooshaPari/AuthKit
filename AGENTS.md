# Agent Rules - AuthKit

**This project is managed through AgilePlus.**

## Project Overview

### Name
AuthKit (Phenotype Authentication & Authorization Toolkit)

### Description
AuthKit is the authentication and authorization toolkit for the Phenotype ecosystem. It provides a comprehensive, secure, and developer-friendly framework for managing user identities, authentication flows (OAuth 2.0/OIDC, passwordless, MFA), session management, and access control across all Phenotype services. It supports multiple languages including Python, Go, Rust, and TypeScript.

### Location
`/Users/kooshapari/CodeProjects/Phenotype/repos/AuthKit`

### Language Stack
- **Python**: OAuth flows, session management, webauthn
- **Go**: Service implementations, middleware
- **Rust**: Policy engine, security components
- **TypeScript**: Client SDKs (planned)

### Purpose & Goals
- **Mission**: Provide unified authentication across all Phenotype services with enterprise security
- **Primary Goal**: Enable secure, seamless identity management with OAuth 2.0/OIDC compliance
- **Secondary Goals**:
  - Support multi-provider authentication (Google, GitHub, Microsoft, Apple, SAML)
  - Implement passwordless and MFA capabilities
  - Provide session management with Redis backend
  - Enable account linking across providers
  - Deliver audit logging for compliance

### Key Responsibilities
1. **Authentication**: OAuth 2.0/OIDC flows with PKCE, passwordless options
2. **Session Management**: Server-side sessions, JWT tokens, secure cookies
3. **Provider Management**: Multi-provider registry with account linking
4. **Authorization**: Policy engine integration for RBAC/ABAC
5. **Security**: Rate limiting, brute force protection, audit logging

---

## Quick Start Commands

### Prerequisites

```bash
# Python 3.12+
brew install python@3.12

# Redis (for session storage)
brew install redis
brew services start redis

# Go 1.24+ (for Go components)
brew install go@1.24
```

### Installation

```bash
# Navigate to AuthKit
cd /Users/kooshapari/CodeProjects/Phenotype/repos/AuthKit

# Install Python components
pip install -e python/pheno-credentials/

# Install Go dependencies
cd go && go mod download

# Verify installation
python -c "import pheno_credentials; print('AuthKit Python OK')"
```

### Development Environment Setup

```bash
# Copy environment configuration
cp .env.example .env

# Initialize development database
python -m pheno_credentials init

# Start development server
python -m pheno_credentials server --dev
```

### Running Authentication Service

```bash
# Development mode
python -m pheno_credentials server --dev

# Production mode
python -m pheno_credentials server --config production.yaml

# Run Go service
cd go && go run ./cmd/authkit-server
```

### Verification

```bash
# Run all tests
cd python && pytest

# Run Go tests
cd go && go test ./...

# Health check
curl http://localhost:8080/health
```

---

## Architecture

### System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Client Applications                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │   Web    │  │  Mobile  │  │   CLI    │  │ Desktop  │       │
│  │  (React) │  │ (Flutter)│  │ (Python) │  │   App    │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
└───────┼─────────────┼─────────────┼─────────────┼─────────────┘
        │             │             │             │
        └─────────────┴─────────────┴─────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      AuthKit Gateway                            │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              API Layer (REST/WebSocket)                 │  │
│  │  • OAuth 2.0 endpoints                                  │  │
│  │  • OIDC discovery                                       │  │
│  │  • Session management                                   │  │
│  └─────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      Core Services                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   OAuth      │  │   Session    │  │   Provider   │       │
│  │   Service    │  │   Manager    │  │   Registry   │       │
│  │              │  │              │  │              │       │
│  │ • PKCE flow  │  │ • Redis      │  │ • Google     │       │
│  │ • Token gen  │  │ • Cookies    │  │ • GitHub     │       │
│  │ • Validation │  │ • JWT        │  │ • SAML       │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
│         │                 │                 │              │
│  ┌──────▼─────────────────▼─────────────────▼───────────┐  │
│  │              Security Layer                          │  │
│  │  • Rate limiting    • Brute force protection        │  │
│  │  • Audit logging    • Input validation              │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────┐    ┌───────────┐    ┌───────────┐
│  Redis    │    │ PostgreSQL│    │   Hashi   │
│(Sessions) │    │ (Users)   │    │   Vault   │
└───────────┘    └───────────┘    └───────────┘
```

### Authentication Flow

```
┌─────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ Client  │──▶│ AuthKit      │──▶│  Provider  │──▶│  User    │
│         │   │ Gateway      │   │ (Google)   │   │ Login    │
└────┬────┘   └──────┬───────┘   └──────┬──────┘   └────┬─────┘
     │               │                  │               │
     │  1. Request   │  2. Auth URL     │  3. Redirect  │
     │  /auth/login  │  + PKCE params   │  to Google    │
     │               │                  │               │
     │◀──────────────│◀─────────────────│◀──────────────┘
     │  4. Code +    │  5. Exchange     │  6. ID Token
     │     State     │  code for tokens │     verified
     │               │                  │
     │───────────────▶                  │
     │  7. Callback  │                  │
     │  validate     │                  │
     │               │                  │
     │◀──────────────│                  │
     │  8. Session   │                  │
     │  + JWT tokens │                  │
     │               │                  │
     │───────────────▶ (API calls)      │
     │  Bearer Token │                  │
     │               │                  │
```

### Component Breakdown

#### 1. API Gateway
- **OAuth Endpoints**: `/auth/login`, `/auth/callback`, `/auth/refresh`
- **Session Endpoints**: `/auth/logout`, `/auth/sessions`
- **OIDC Endpoints**: `/.well-known/openid-configuration`, `/oauth/token`
- **WebSocket**: Real-time session events

#### 2. OAuth Service
- **PKCE Implementation**: Secure code_challenge generation
- **Token Generation**: JWT access tokens (RS256) with short TTL
- **Token Validation**: Signature verification, claim validation
- **Refresh Flow**: Token rotation with secure storage

#### 3. Session Manager
- **Redis Storage**: Distributed session storage with TTL
- **Cookie Management**: HttpOnly, Secure, SameSite=Lax
- **Session Lifecycle**: Creation, refresh, revocation
- **Multi-Device**: Support for concurrent sessions per user

#### 4. Provider Registry
- **Built-in Providers**: Google, GitHub, Microsoft, Apple
- **Custom OAuth2**: Dynamic provider registration
- **SAML Support**: Enterprise SSO integration
- **Account Linking**: Automatic and manual linking strategies

### Multi-Language Structure

```
AuthKit/
├── python/
│   └── pheno-credentials/
│       ├── oauth/              # OAuth 2.0/OIDC flows
│       │   ├── flows.py        # Authorization code flow
│       │   ├── pkce.py         # PKCE implementation
│       │   ├── providers.py    # Provider registry
│       │   └── token_manager.py # JWT handling
│       ├── session/            # Session management
│       │   ├── manager.py      # Session lifecycle
│       │   ├── store.py        # Redis storage
│       │   └── cookie.py       # Cookie handling
│       ├── security/           # Security features
│       │   ├── rate_limiter.py # Rate limiting
│       │   ├── brute_force.py  # Attack protection
│       │   └── audit.py        # Audit logging
│       └── hierarchy/          # Credential hierarchy
│           ├── manager.py
│           └── resolver.py
├── go/
│   ├── auth/                   # Go auth implementations
│   ├── session/                # Go session management
│   └── middleware/             # HTTP middleware
├── rust/
│   ├── phenotype-policy-engine/ # Authorization policies
│   ├── phenotype-security-aggregator/
│   └── phenotype-contracts/    # Security contracts
└── typescript/                   # (planned)
```

---

## Quality Standards

### Testing Requirements

#### Test Coverage
- **Minimum Coverage**: 85% for authentication logic
- **Critical Paths**: 95% for token validation, session management
- **Security Tests**: 100% for crypto operations

#### Test Categories
```bash
# Unit tests
pytest python/pheno-credentials/tests/unit/

# Integration tests
pytest python/pheno-credentials/tests/integration/

# Security tests
pytest python/pheno-credentials/tests/security/

# Go tests
cd go && go test -v ./...
```

### Code Quality

#### Python Standards
```bash
# Linting
ruff check python/
mypy python/pheno-credentials/

# Formatting
black python/
ruff format python/

# Security scanning
bandit -r python/pheno-credentials/
safety check
```

#### Go Standards
```bash
# Linting
golangci-lint run

# Formatting
gofmt -l -w go/

# Testing with race detection
go test -race ./...
```

#### Security Requirements
- All crypto operations use constant-time comparison
- Passwords hashed with Argon2id
- JWT signed with RS256 (asymmetric)
- HTTPS enforced for all endpoints
- CORS properly configured

### Security Standards

| Control | Implementation | Verification |
|---------|---------------|------------|
| PKCE | S256 challenge | Unit tests |
| Rate Limiting | Token bucket | Integration tests |
| Session Security | 48-byte random ID | Audit logs |
| Token Expiry | 15 min access, 30 day refresh | Automated tests |
| Audit Logging | Structured JSON | Log validation |

---

## Git Workflow

### Branch Strategy

```
main
  │
  ├── feature/oauth-pkce
  │   └── PR #23 → squash merge ──┐
  │                               │
  ├── feature/webauthn-support     │
  │   └── PR #24 → squash merge ──┤
  │                               │
  ├── fix/session-race-condition   │
  │   └── PR #25 → squash merge ──┤
  │                               │
  └── hotfix/token-validation ──────┘
      └── PR #26 → merge commit
```

### Branch Naming

```
feature/<scope>-<description>
fix/<component>-<issue>
security/<vulnerability>
docs/<topic>
refactor/<scope>
perf/<optimization>
chore/<maintenance>
```

### Commit Conventions

```
feat(oauth): add PKCE support for mobile apps

Implements RFC 7636 PKCE extension for OAuth 2.0
authorization code flow. Required for mobile and
single-page applications.

- Generate code_challenge with S256 method
- Validate code_verifier in token exchange
- Store PKCE parameters in session

Closes #42

fix(session): resolve race in concurrent refresh

Two simultaneous token refreshes could generate
different refresh tokens, invalidating one session.
Now uses optimistic locking in Redis.
```

---

## File Structure

```
AuthKit/
├── docs/                       # Documentation
│   ├── SPEC.md                 # This specification
│   ├── ADR/                    # Architecture decisions
│   │   ├── ADR-001-auth-flow.md
│   │   ├── ADR-002-session-management.md
│   │   └── ADR-003-multi-provider.md
│   └── research/               # Research documents
│       └── AUTH_TOOLKITS_SOTA.md
│
├── python/                     # Python implementation
│   └── pheno-credentials/
│       ├── pyproject.toml
│       ├── src/pheno_credentials/
│       │   ├── __init__.py
│       │   ├── broker.py
│       │   ├── oauth/
│       │   │   ├── flows.py
│       │   │   ├── pkce.py
│       │   │   ├── providers.py
│       │   │   └── token_manager.py
│       │   ├── session/
│       │   │   ├── manager.py
│       │   │   ├── store.py
│       │   │   └── cookie.py
│       │   ├── security/
│       │   │   ├── rate_limiter.py
│       │   │   ├── brute_force.py
│       │   │   └── audit.py
│       │   └── hierarchy/
│       │       ├── manager.py
│       │       └── resolver.py
│       └── tests/
│
├── go/                         # Go implementation
│   ├── go.mod
│   ├── go.sum
│   ├── auth/
│   │   ├── flows.go
│   │   └── tokens.go
│   ├── session/
│   │   ├── manager.go
│   │   └── store.go
│   └── middleware/
│       └── auth.go
│
├── rust/                       # Rust implementation
│   ├── phenotype-policy-engine/
│   ├── phenotype-security-aggregator/
│   └── phenotype-contracts/
│
├── typescript/                 # TypeScript SDK (planned)
│
├── pyproject.toml              # Python workspace config
├── registry.yaml               # Package registry
├── README.md
└── AGENTS.md                   # This file
```

---

## CLI Commands

### AuthKit CLI

```bash
# Server Operations
authkit server                   # Start auth server
authkit server --port 8080       # Custom port
authkit server --config ./config.yaml

# Provider Management
authkit provider list            # List configured providers
authkit provider add google      # Add Google OAuth
authkit provider add github --client-id xxx --client-secret yyy

# Session Management
authkit session list <user_id>   # List user sessions
authkit session revoke <id>      # Revoke specific session
authkit session revoke-all <user> # Revoke all user sessions

# Token Operations
authkit token generate <user>    # Generate test token
authkit token verify <token>     # Verify token validity
authkit token decode <token>     # Decode token claims

# User Management
authkit user create <email>      # Create user
authkit user link <user> <provider>  # Link provider account

# Audit & Logging
authkit audit events --user <id> # Query audit events
authkit audit export --since 7d  # Export audit log

# Diagnostics
authkit doctor                   # Health check
authkit config validate          # Validate configuration
```

### Development Commands

```bash
# Run Python tests
pytest python/pheno-credentials/ -v

# Run with coverage
pytest --cov=pheno_credentials --cov-report=html

# Run Go tests
cd go && go test ./... -v

# Start Redis for development
redis-server --port 6379

# Run linting
ruff check python/
golangci-lint run

# Type checking
mypy python/pheno-credentials/
```

---

## Troubleshooting

### Common Issues

#### Issue: OAuth callback fails with "state mismatch"

**Symptoms:**
```
Error: AUTH_STATE_MISMATCH - State parameter does not match
```

**Diagnosis:**
```bash
# Check session cookie is being set
curl -v http://localhost:8080/auth/login
# Look for Set-Cookie header

# Verify cookie attributes
curl http://localhost:8080/auth/callback \
  -H "Cookie: authkit_session=xxx" \
  -d '{"code": "xxx", "state": "yyy"}'
```

**Resolution:**
- Ensure cookies are enabled in browser/client
- Check SameSite cookie settings
- Verify HTTPS in production (Secure attribute)
- Clear browser cookies and retry

---

#### Issue: Token refresh returns "session revoked"

**Symptoms:**
```
Error: AUTH_SESSION_REVOKED - Session has been revoked
```

**Diagnosis:**
```bash
# Check session in Redis
redis-cli GET "session:<session_id>"

# Check if user logged out elsewhere
redis-cli SMEMBERS "user:<user_id>:sessions"

# Review audit log
authkit audit events --user <user_id> --type session_revoked
```

**Resolution:**
```bash
# User needs to re-authenticate
# Check for suspicious activity
authkit audit export --user <user_id> --since 24h
```

---

#### Issue: High Redis memory usage from sessions

**Diagnosis:**
```bash
# Check Redis memory
redis-cli INFO memory

# Count sessions
redis-cli EVAL "return redis.call('dbsize')" 0

# Find expired sessions (if any)
redis-cli --scan --pattern "session:*" | wc -l
```

**Resolution:**
```bash
# Adjust session TTL
authkit config set session.ttl 43200  # 12 hours

# Enable aggressive cleanup
authkit config set session.cleanup_interval 300

# Manual cleanup of orphaned sessions
redis-cli EVAL "
  local keys = redis.call('keys', 'session:*')
  for _, key in ipairs(keys) do
    if redis.call('ttl', key) == -1 then
      redis.call('del', key)
    end
  end
  return #keys
" 0
```

---

#### Issue: Provider login fails with "invalid client"

**Symptoms:**
```
Error: AUTH_INVALID_CREDENTIALS - OAuth client credentials invalid
```

**Diagnosis:**
```bash
# Verify provider configuration
authkit provider list --verbose

# Check client credentials are correct
cat config.yaml | grep -A 5 "google:"

# Test provider endpoint
curl https://accounts.google.com/.well-known/openid-configuration
```

**Resolution:**
- Update provider credentials
- Verify redirect URI matches OAuth app settings
- Check for trailing spaces in credentials
- Ensure provider is enabled: `authkit provider enable google`

---

### Debug Mode

```bash
# Enable debug logging
export AUTHKIT_LOG_LEVEL=debug
export AUTHKIT_LOG_FORMAT=json

# Run with verbose output
authkit server --verbose

# Trace HTTP requests
export AUTHKIT_HTTP_TRACE=1

# Redis command logging
redis-cli MONITOR
```

### Recovery Procedures

```bash
# Emergency session revocation (security incident)
authkit session revoke-all --force

# Rebuild provider cache
authkit provider refresh-cache

# Clear rate limit buckets (after attack)
redis-cli DEL "ratelimit:*"

# Regenerate signing keys
authkit keys rotate --grace-period 24h
```

---

## Agent Self-Correction & Verification Protocols

### Critical Rules

1. **Security First**
   - Never log sensitive data (tokens, passwords)
   - Always use constant-time comparison for secrets
   - Validate all inputs before processing
   - Use prepared statements for database queries

2. **OAuth Compliance**
   - PKCE is mandatory for all public clients
   - State parameter required for CSRF protection
   - HTTPS only in production
   - Proper token expiration handling

3. **Session Integrity**
   - Atomic session operations
   - Proper cleanup on revocation
   - TTL management in Redis
   - Session fixation prevention

4. **Audit Requirements**
   - Log all authentication events
   - Include IP, user agent, timestamp
   - Structured logging format
   - Retention policy compliance

---

*This AGENTS.md is a living document. Update it as AuthKit evolves.*
