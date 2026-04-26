# AuthKit Comprehensive Specification (SPEC.md)

**Document ID:** PHENOTYPE_AUTHKIT_SPEC_001
**Status:** Draft
**Last Updated:** 2026-04-03
**Author:** Phenotype Architecture Team
**Version:** 1.0.0

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Functionality Specification](#3-functionality-specification)
4. [Technical Architecture](#4-technical-architecture)
5. [API Reference](#5-api-reference)
6. [Error Handling](#6-error-handling)
7. [Security](#7-security)
8. [Performance](#8-performance)
9. [Deployment](#9-deployment)
10. [Testing](#10-testing)
11. [Migration Guide](#11-migration-guide)
12. [Glossary](#12-glossary)
13. [References](#13-references)

---

## 1. Project Overview

### 1.1 Purpose

AuthKit is the authentication and authorization toolkit for the Phenotype ecosystem. It provides a comprehensive, secure, and developer-friendly framework for managing user identities, authentication flows, session management, and access control across all Phenotype services.

### 1.2 Vision

To be the single source of truth for authentication in the Phenotype ecosystem, providing:

- **Unified authentication** across all services and platforms
- **Secure by default** with industry best practices built in
- **Developer-friendly** APIs with sensible defaults and progressive disclosure
- **Extensible architecture** supporting custom providers and flows
- **Compliance-ready** with audit logging and security controls

### 1.3 Scope

AuthKit covers the following domains:

| Domain | Description | Priority |
|--------|-------------|----------|
| Authentication | OAuth 2.0/OIDC flows, passwordless, MFA | P0 |
| Session Management | Server-side sessions, JWT tokens, cookie security | P0 |
| Provider Management | Multi-provider support, account linking | P0 |
| Authorization | Policy engine integration, RBAC/ABAC | P1 |
| Security | Rate limiting, brute force protection, audit logging | P1 |
| Developer SDK | Python and Go SDKs with documentation | P1 |
| Monitoring | Health checks, metrics, alerting | P2 |

### 1.4 Non-Goals

- **User directory management** - Handled by separate identity service
- **Email/SMS delivery** - Handled by notification service
- **Payment authentication** - Out of scope
- **Custom UI components** - AuthKit provides APIs, not UI

### 1.5 Design Principles

```
┌─────────────────────────────────────────────────────────────┐
│              AuthKit Design Principles                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Security First                                          │
│     • PKCE mandatory for all OAuth flows                    │
│     • HTTPS enforced for all endpoints                      │
│     • Secure cookie attributes by default                   │
│     • Token rotation and revocation built-in                │
│                                                             │
│  2. Developer Experience                                    │
│     • Sensible defaults, minimal configuration              │
│     • Progressive disclosure for advanced features          │
│     • Clear error messages with recovery suggestions        │
│     • Comprehensive documentation and examples              │
│                                                             │
│  3. Extensibility                                           │
│     • Provider abstraction for easy integration             │
│     • Plugin system for custom flows                        │
│     • Configuration-driven behavior                         │
│     • Open extension points                                 │
│                                                             │
│  4. Observability                                           │
│     • Structured logging for all operations                 │
│     • Metrics for performance monitoring                    │
│     • Distributed tracing support                           │
│     • Health checks for all components                      │
│                                                             │
│  5. Compliance                                              │
│     • Audit logging for all authentication events           │
│     • GDPR-compliant data handling                          │
│     • NIST SP 800-63B alignment                             │
│     • SOC 2 Type II ready                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 1.6 Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| OAuth/OIDC (Python) | authlib | Comprehensive, well-maintained |
| OAuth/OIDC (Go) | go-oidc + golang.org/x/oauth2 | Standard, reliable |
| Session Store | Redis | High performance, distributed |
| JWT Library (Python) | PyJWT | Lightweight, well-tested |
| JWT Library (Go) | golang-jwt/jwt | Standard Go JWT library |
| WebAuthn (Python) | webauthn.io | FIDO2/WebAuthn support |
| WebAuthn (Go) | go-webauthn | Native Go WebAuthn |
| Password Hashing | Argon2id | Memory-hard, resistant to GPU attacks |
| Encryption | cryptography (Python), crypto (Go) | Standard cryptographic libraries |
| HTTP Client | httpx (Python), net/http (Go) | Async support, connection pooling |

### 1.7 Project Structure

```
AuthKit/
├── docs/                    # Documentation
│   ├── research/            # Research documents
│   │   └── AUTH_TOOLKITS_SOTA.md
│   ├── adr/                 # Architecture Decision Records
│   │   ├── ADR-001-auth-flow.md
│   │   ├── ADR-002-session-management.md
│   │   └── ADR-003-multi-provider.md
│   └── SPEC.md              # This specification
├── python/                  # Python packages
│   └── pheno-credentials/   # Credential management
│       └── src/pheno_credentials/
│           ├── __init__.py
│           ├── broker.py
│           ├── oauth/
│           │   ├── flows.py
│           │   ├── providers.py
│           │   └── token_manager.py
│           └── hierarchy/
│               ├── manager.py
│               └── resolver.py
├── go/                      # Go modules
│   └── (planned)
├── rust/                    # Rust crates
│   ├── phenotype-policy-engine/
│   ├── phenotype-security-aggregator/
│   ├── phenotype-contracts/
│   ├── phenotype-content-hash/
│   └── phenotype-bid/
├── typescript/              # TypeScript packages
│   └── (planned)
├── pyproject.toml           # Python workspace configuration
├── registry.yaml            # Package registry
└── README.md                # Project overview
```

---

## 2. Architecture

### 2.1 System Context

```
┌─────────────────────────────────────────────────────────────┐
│                    Phenotype Ecosystem                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Web App   │    │  Mobile App │    │   CLI Tool  │     │
│  │  (React)    │    │  (Flutter)  │    │  (Python)   │     │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘     │
│         │                  │                  │             │
│         └──────────────────┼──────────────────┘             │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │                  AuthKit                            │    │
│  │                                                     │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │           Authentication Service            │    │    │
│  │  │  • OAuth 2.0/OIDC flows                    │    │    │
│  │  │  • PKCE implementation                     │    │    │
│  │  │  • Multi-provider support                  │    │    │
│  │  │  • Account linking                         │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │           Session Manager                   │    │    │
│  │  │  • Server-side sessions (Redis)             │    │    │
│  │  │  • JWT access tokens                        │    │    │
│  │  │  • Cookie management                        │    │    │
│  │  │  • Session revocation                       │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │           Provider Registry                 │    │    │
│  │  │  • Google, GitHub, Microsoft, Apple         │    │    │
│  │  │  • SAML enterprise providers                │    │    │
│  │  │  • Custom OAuth2 providers                  │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │           Security Layer                    │    │    │
│  │  │  • Rate limiting                            │    │    │
│  │  │  • Brute force protection                   │    │    │
│  │  │  • Audit logging                            │    │    │
│  │  │  • Token validation                         │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  └─────────────────────────┬───────────────────────────┘    │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │              Phenotype Services                     │    │
│  │                                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │  Service A  │  │  Service B  │  │ Service C  │  │    │
│  │  │             │  │             │  │            │  │    │
│  │  │ Validate    │  │ Validate    │  │ Validate   │  │    │
│  │  │ JWT locally │  │ JWT locally │  │ JWT locally│  │    │
│  │  └─────────────┘  └─────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Infrastructure                         │    │
│  │                                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │   Redis     │  │  Database   │  │  Vault     │  │    │
│  │  │  (Sessions) │  │  (Users)    │  │ (Secrets)  │  │    │
│  │  └─────────────┘  └─────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              AuthKit Component Architecture                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              API Layer                              │    │
│  │  • REST endpoints                                   │    │
│  │  • GraphQL (optional)                               │    │
│  │  • WebSocket (real-time events)                     │    │
│  └─────────────────────────┬───────────────────────────┘    │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │              Service Layer                          │    │
│  │                                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │   Auth      │  │  Session    │  │  Provider  │  │    │
│  │  │   Service   │  │  Service    │  │  Service   │  │    │
│  │  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘  │    │
│  │         │                │                │         │    │
│  │  ┌──────▼────────────────▼────────────────▼──────┐  │    │
│  │  │              Core Engine                      │  │    │
│  │  │  • Token generation & validation              │  │    │
│  │  │  • Session lifecycle management               │  │    │
│  │  │  • Provider abstraction                       │  │    │
│  │  │  • Account linking                            │  │    │
│  │  └───────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │              Infrastructure Layer                   │    │
│  │                                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │   Redis     │  │  Database   │  │  External  │  │    │
│  │  │   Client    │  │   Client    │  │   APIs     │  │    │
│  │  └─────────────┘  └─────────────┘  └────────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│              Authentication Data Flow                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Client initiates login                                  │
│     └─▶ POST /auth/login {provider: "google"}               │
│                                                             │
│  2. AuthKit generates PKCE pair and authorization URL       │
│     └─▶ Response: {authorization_url, state}                │
│                                                             │
│  3. Client redirects user to provider                       │
│     └─▶ User authenticates with Google                      │
│                                                             │
│  4. Provider redirects back with authorization code         │
│     └─▶ GET /auth/callback?code=xxx&state=yyy               │
│                                                             │
│  5. AuthKit exchanges code for tokens                       │
│     └─▶ POST /oauth/token {code, code_verifier}             │
│     └─▶ Response: {access_token, refresh_token, id_token}   │
│                                                             │
│  6. AuthKit validates ID token and extracts user info       │
│     └─▶ Verify signature, claims, expiration                │
│                                                             │
│  7. AuthKit resolves or creates user identity               │
│     └─▶ Check account linking, create if new                │
│                                                             │
│  8. AuthKit creates session                                 │
│     └─▶ Store in Redis, generate session cookie             │
│                                                             │
│  9. AuthKit generates JWT access token                      │
│     └─▶ Sign with HS256, embed session ID                   │
│                                                             │
│  10. Response to client                                     │
│      └─▶ Set-Cookie: authkit_session=...                    │
│      └─▶ Response: {access_token, user, expires_in}         │
│                                                             │
│  11. Client uses access token for API requests              │
│      └─▶ Authorization: Bearer <jwt>                        │
│      └─▶ Services validate JWT locally                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Functionality Specification

### 3.1 Authentication Flows

#### 3.1.1 OAuth 2.0 Authorization Code Flow with PKCE

**Description:** Primary authentication flow for all client types.

**Inputs:**
- `provider`: Provider identifier (e.g., "google", "github")
- `redirect_uri`: Callback URL (must be pre-registered)
- `state`: CSRF protection token (generated by client)
- `login_hint` (optional): Pre-fill login form

**Process:**
1. Generate PKCE code_verifier and code_challenge (S256)
2. Build authorization URL with required parameters
3. Redirect user to provider authorization endpoint
4. Provider authenticates user and returns authorization code
5. Exchange code for tokens using code_verifier
6. Validate ID token (signature, claims, expiration)
7. Extract user information from ID token or userinfo endpoint
8. Resolve or create user identity
9. Create server-side session
10. Generate JWT access token
11. Return session cookie and access token to client

**Outputs:**
- Session cookie (HttpOnly, Secure, SameSite=Lax)
- JWT access token (15-minute TTL)
- Refresh token (if supported by provider)
- User profile information

**Error Conditions:**
- Invalid provider → `AUTH_PROVIDER_NOT_FOUND`
- State mismatch → `AUTH_STATE_MISMATCH`
- Code exchange failure → `AUTH_CODE_EXCHANGE_FAILED`
- Invalid ID token → `AUTH_INVALID_ID_TOKEN`
- Session creation failure → `AUTH_SESSION_CREATION_FAILED`

#### 3.1.2 Client Credentials Flow

**Description:** Service-to-service authentication for backend services.

**Inputs:**
- `client_id`: Service client identifier
- `client_secret`: Service client secret
- `scope`: Requested permissions

**Process:**
1. Validate client credentials
2. Generate JWT access token with service identity
3. Return token to requesting service

**Outputs:**
- JWT access token with service claims
- Token expiration time

**Error Conditions:**
- Invalid credentials → `AUTH_INVALID_CREDENTIALS`
- Insufficient scope → `AUTH_INSUFFICIENT_SCOPE`

#### 3.1.3 Token Refresh Flow

**Description:** Refresh expired access tokens without user interaction.

**Inputs:**
- `refresh_token`: Valid refresh token
- `session_id`: Current session identifier

**Process:**
1. Validate refresh token (signature, expiration, revocation)
2. Verify session is still active
3. Generate new access token
4. Rotate refresh token (if supported)
5. Return new tokens

**Outputs:**
- New JWT access token
- New refresh token (rotated)
- Updated expiration time

**Error Conditions:**
- Invalid refresh token → `AUTH_INVALID_REFRESH_TOKEN`
- Expired refresh token → `AUTH_REFRESH_TOKEN_EXPIRED`
- Revoked session → `AUTH_SESSION_REVOKED`

### 3.2 Session Management

#### 3.2.1 Session Creation

**Description:** Create a new user session after successful authentication.

**Session Properties:**
| Property | Type | Description |
|----------|------|-------------|
| session_id | string | Cryptographically random identifier (48 bytes) |
| user_id | string | User identifier |
| organization_id | string? | Organization context |
| created_at | timestamp | Session creation time |
| last_accessed | timestamp | Last activity time |
| expires_at | timestamp | Absolute expiration time |
| ip_address | string? | Client IP address |
| user_agent | string? | Browser/app identifier |
| device_fingerprint | string? | Device hash |
| is_revoked | boolean | Revocation flag |
| mfa_verified | boolean | MFA completion status |
| auth_level | enum | NIST AAL level (aal1, aal2, aal3) |
| metadata | object | Custom metadata |

**Session Lifecycle:**
- **Creation**: Generated after successful authentication
- **Activity**: Updated on each request (sliding expiration)
- **Expiration**: Auto-deleted by Redis TTL (24 hours default)
- **Revocation**: Explicit deletion via API or admin action
- **Cleanup**: Expired sessions purged from secondary indexes

#### 3.2.2 Session Validation

**Description:** Validate session on each request.

**Validation Steps:**
1. Extract session ID from cookie or authorization header
2. Verify cookie signature (HMAC-SHA256)
3. Look up session in Redis
4. Check session is not revoked
5. Check session is not expired
6. Update last_accessed time (sliding expiration)
7. Verify IP/device fingerprint matches (optional)
8. Check MFA requirement for sensitive operations

#### 3.2.3 Session Revocation

**Description:** Revoke a session immediately.

**Revocation Triggers:**
- User logout
- Password change
- MFA enabled/disabled
- Suspicious activity detected
- Administrative action
- Account deletion

**Revocation Process:**
1. Delete session from Redis
2. Remove from user session set
3. Remove from activity sorted set
4. Publish revocation event via Redis Pub/Sub
5. All subscribed services invalidate cached session state

### 3.3 Provider Management

#### 3.3.1 Provider Registration

**Description:** Register a new authentication provider.

**Provider Configuration:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| provider_id | string | Yes | Unique provider identifier |
| provider_type | string | Yes | Provider type (google, github, etc.) |
| protocol | enum | Yes | Authentication protocol |
| client_id | string | Yes | OAuth client ID |
| client_secret | string | No | OAuth client secret |
| authorization_endpoint | string | No | Authorization URL |
| token_endpoint | string | No | Token exchange URL |
| userinfo_endpoint | string | No | User info URL |
| jwks_uri | string | No | JWKS URL for token validation |
| redirect_uri | string | Yes | OAuth redirect URI |
| scopes | array | Yes | Requested scopes |
| capabilities | array | No | Supported capabilities |
| metadata | object | No | Provider-specific metadata |
| enabled | boolean | No | Provider enabled flag |

#### 3.3.2 Account Linking

**Description:** Link multiple provider accounts to a single user identity.

**Linking Rules:**
1. Same email address → Auto-link
2. Different email → User confirmation required
3. Already linked → Show existing link, prevent duplicates
4. Primary provider → Cannot be unlinked
5. Minimum one active provider → Cannot unlink last provider

**Link Resolution:**
1. Check if provider_user_id is already linked
2. Check if email matches existing user
3. If match found → Link to existing user
4. If no match → Create new user and link

### 3.4 Authorization

#### 3.4.1 Policy Engine Integration

**Description:** Integrate with Phenotype policy engine for authorization decisions.

**Integration Points:**
- Session context passed to policy engine
- User roles and attributes resolved from identity
- Organization context for multi-tenant policies
- Resource attributes for ABAC evaluation

**Authorization Flow:**
```
┌─────────────────────────────────────────────────────────────┐
│              Authorization Flow                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Request ──▶ AuthKit ──▶ Policy Engine ──▶ Decision         │
│              │              │                                │
│              │  ┌───────────▼───────────┐                   │
│              │  │   Evaluation Context  │                   │
│              │  │  • Subject (user)     │                   │
│              │  │  • Action (CRUD)      │                   │
│              │  │  • Resource           │                   │
│              │  │  • Environment        │                   │
│              │  └───────────────────────┘                   │
│              │              │                                │
│              │  ┌───────────▼───────────┐                   │
│              │  │   Policy Evaluation   │                   │
│              │  │  1. RBAC (fast path)  │                   │
│              │  │  2. ABAC (context)    │                   │
│              │  │  3. Cache result      │                   │
│              │  └───────────────────────┘                   │
│              │              │                                │
│              ◀── Allow/Deny ◀──┘                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.5 Security Controls

#### 3.5.1 Rate Limiting

**Description:** Protect authentication endpoints from abuse.

**Rate Limit Configuration:**
| Endpoint | Limit | Window | Action |
|----------|-------|--------|--------|
| /auth/login | 10 req/min | Per IP | Block + CAPTCHA |
| /auth/callback | 20 req/min | Per IP | Block |
| /auth/refresh | 5 req/min | Per session | Revoke session |
| /auth/logout | 30 req/min | Per session | Allow |
| /auth/password-reset | 3 req/hour | Per email | Block |

#### 3.5.2 Brute Force Protection

**Description:** Prevent credential stuffing and brute force attacks.

**Protection Mechanisms:**
- Progressive delays after failed attempts
- Account lockout after threshold (5 attempts)
- IP-based blocking for repeated failures
- CAPTCHA challenge after 3 failed attempts
- Breached password detection (Have I Been Pwned API)

#### 3.5.3 Audit Logging

**Description:** Log all authentication events for compliance and security monitoring.

**Audit Events:**
| Event | Severity | Data Logged |
|-------|----------|-------------|
| Login success | Info | user_id, provider, IP, UA |
| Login failure | Warning | provider, IP, error_code |
| Session created | Info | session_id, user_id, IP |
| Session revoked | Warning | session_id, user_id, reason |
| Password changed | Warning | user_id, IP |
| MFA enabled/disabled | Warning | user_id, method |
| Account linked | Info | user_id, provider, email |
| Token refreshed | Info | session_id, user_id |
| Rate limit exceeded | Warning | IP, endpoint, count |
| Suspicious activity | Critical | user_id, IP, reason |

---

## 4. Technical Architecture

### 4.1 Python Implementation

#### 4.1.1 Package Structure

```python
"""
AuthKit Python Package Structure
"""

authkit/
├── __init__.py              # Package exports
├── config.py                # Configuration management
├── auth/
│   ├── __init__.py
│   ├── flows.py             # OAuth 2.0/OIDC flows
│   ├── pkce.py              # PKCE implementation
│   ├── tokens.py            # Token generation/validation
│   └── callbacks.py         # OAuth callback handlers
├── session/
│   ├── __init__.py
│   ├── manager.py           # Session lifecycle management
│   ├── store.py             # Redis session storage
│   ├── cookie.py            # Cookie management
│   └── jwt.py               # JWT access tokens
├── providers/
│   ├── __init__.py
│   ├── base.py              # Abstract provider interface
│   ├── registry.py          # Provider registry
│   ├── google.py            # Google OAuth2 provider
│   ├── github.py            # GitHub OAuth2 provider
│   ├── microsoft.py         # Microsoft OIDC provider
│   ├── apple.py             # Apple Sign-In provider
│   └── saml.py              # SAML enterprise provider
├── security/
│   ├── __init__.py
│   ├── rate_limiter.py      # Rate limiting
│   ├── brute_force.py       # Brute force protection
│   ├── audit.py             # Audit logging
│   └── headers.py           # Security headers
├── linking/
│   ├── __init__.py
│   ├── account.py           # Account linking service
│   └── resolver.py          # Identity resolution
└── sdk/
    ├── __init__.py
    ├── client.py            # AuthKit SDK client
    └── middleware.py         # Framework middleware
```

#### 4.1.2 Core SDK Client

```python
"""
AuthKit Python SDK Client
Developer-friendly interface for integrating AuthKit
"""

import time
from typing import Optional
from dataclasses import dataclass

@dataclass
class AuthKitConfig:
    """AuthKit configuration with sensible defaults."""

    base_url: str
    client_id: str
    client_secret: Optional[str] = None
    redirect_uri: str = "http://localhost:3000/callback"
    session_cookie_name: str = "authkit_session"
    session_ttl: int = 86400  # 24 hours
    access_token_ttl: int = 900  # 15 minutes
    refresh_token_ttl: int = 2592000  # 30 days
    enable_mfa: bool = True
    enable_passkeys: bool = False
    allowed_origins: list[str] = None

    def __post_init__(self):
        if self.allowed_origins is None:
            self.allowed_origins = ["http://localhost:3000"]

class AuthKitClient:
    """Main AuthKit client for Python applications."""

    def __init__(self, config: AuthKitConfig):
        self._config = config
        self._http_client = None
        self._session_manager = None
        self._token_validator = None

    async def initialize(self):
        """Initialize AuthKit client components."""
        import httpx
        self._http_client = httpx.AsyncClient(
            base_url=self._config.base_url,
            timeout=10.0,
        )

    async def login(self, provider: str = "google",
                   redirect_uri: Optional[str] = None) -> dict:
        """Generate login URL for specified provider."""
        response = await self._http_client.post(
            "/auth/login",
            json={
                "provider": provider,
                "redirect_uri": redirect_uri or self._config.redirect_uri,
            },
        )
        response.raise_for_status()
        return response.json()

    async def handle_callback(self, code: str, state: str) -> dict:
        """Handle OAuth callback and create session."""
        response = await self._http_client.post(
            "/auth/callback",
            json={
                "code": code,
                "state": state,
            },
        )
        response.raise_for_status()
        return response.json()

    async def verify_token(self, token: str) -> dict:
        """Verify authentication token."""
        response = await self._http_client.post(
            "/auth/verify",
            json={"token": token},
        )
        response.raise_for_status()
        return response.json()

    async def refresh_token(self, refresh_token: str) -> dict:
        """Refresh expired access token."""
        response = await self._http_client.post(
            "/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        response.raise_for_status()
        return response.json()

    async def logout(self, session_id: str) -> bool:
        """Revoke user session."""
        response = await self._http_client.post(
            "/auth/logout",
            json={"session_id": session_id},
        )
        response.raise_for_status()
        return response.json().get("success", False)

    async def get_user_sessions(self, user_id: str) -> list:
        """Get all active sessions for a user."""
        response = await self._http_client.get(
            f"/auth/users/{user_id}/sessions",
        )
        response.raise_for_status()
        return response.json().get("sessions", [])

    async def revoke_session(self, session_id: str) -> bool:
        """Revoke a specific session."""
        response = await self._http_client.delete(
            f"/auth/sessions/{session_id}",
        )
        response.raise_for_status()
        return response.json().get("success", False)

    async def close(self):
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
```

### 4.2 Go Implementation

#### 4.2.1 Package Structure

```go
// AuthKit Go Package Structure

authkit/
├── authkit.go              # Package entry point
├── config.go               # Configuration management
├── auth/
│   ├── flows.go            # OAuth 2.0/OIDC flows
│   ├── pkce.go             # PKCE implementation
│   ├── tokens.go           # Token generation/validation
│   └── callbacks.go        # OAuth callback handlers
├── session/
│   ├── manager.go          # Session lifecycle management
│   ├── store.go            # Redis session storage
│   ├── cookie.go           # Cookie management
│   └── jwt.go              # JWT access tokens
├── providers/
│   ├── provider.go         # Abstract provider interface
│   ├── registry.go         # Provider registry
│   ├── google.go           # Google OAuth2 provider
│   ├── github.go           # GitHub OAuth2 provider
│   └── microsoft.go        # Microsoft OIDC provider
├── security/
│   ├── rate_limiter.go     # Rate limiting
│   ├── brute_force.go      # Brute force protection
│   └── audit.go            # Audit logging
├── linking/
│   ├── account.go          # Account linking service
│   └── resolver.go         # Identity resolution
└── sdk/
    ├── client.go           # AuthKit SDK client
    └── middleware.go       # HTTP middleware
```

#### 4.2.2 Go SDK Client

```go
// AuthKit Go SDK Client
// Developer-friendly interface for integrating AuthKit

package authkit

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Client is the main AuthKit client for Go applications
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Config     *ClientConfig
}

// ClientConfig holds client configuration
type ClientConfig struct {
	BaseURL           string
	ClientID          string
	ClientSecret      string
	RedirectURI       string
	SessionCookieName string
	SessionTTL        time.Duration
	AccessTokenTTL    time.Duration
}

// NewClient creates a new AuthKit client
func NewClient(config *ClientConfig) *Client {
	return &Client{
		BaseURL: config.BaseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Config: config,
	}
}

// Login initiates the authentication flow
func (c *Client) Login(ctx context.Context, provider string,
	redirectURI string) (*LoginResponse, error) {

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/auth/login", c.BaseURL), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Implementation would send request and parse response
	return nil, fmt.Errorf("not implemented")
}

// HandleCallback processes the OAuth callback
func (c *Client) HandleCallback(ctx context.Context, code, state string) (*AuthResult, error) {
	// Implementation would exchange code for tokens
	return nil, fmt.Errorf("not implemented")
}

// VerifyToken validates an authentication token
func (c *Client) VerifyToken(ctx context.Context, token string) (*TokenClaims, error) {
	// Implementation would verify token
	return nil, fmt.Errorf("not implemented")
}

// RefreshToken refreshes an expired access token
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	// Implementation would refresh token
	return nil, fmt.Errorf("not implemented")
}

// Logout revokes the user session
func (c *Client) Logout(ctx context.Context, sessionID string) error {
	// Implementation would revoke session
	return fmt.Errorf("not implemented")
}

// LoginResponse contains the login initiation response
type LoginResponse struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state"`
}

// AuthResult contains the authentication result
type AuthResult struct {
	User        map[string]interface{} `json:"user"`
	SessionID   string                 `json:"session_id"`
	AccessToken string                 `json:"access_token"`
	ExpiresIn   int                    `json:"expires_in"`
}

// TokenClaims contains decoded JWT claims
type TokenClaims struct {
	Subject       string `json:"sub"`
	SessionID     string `json:"sid"`
	Organization  string `json:"org"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	MFAVerified   bool   `json:"mfa"`
	AuthLevel     string `json:"aal"`
}

// TokenResponse contains token refresh response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}
```

---

## 5. API Reference

### 5.1 REST API Endpoints

#### 5.1.1 Authentication Endpoints

```
┌─────────────────────────────────────────────────────────────┐
│              Authentication API Endpoints                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  POST /auth/login                                           │
│  Initiate authentication flow                               │
│                                                             │
│  Request Body:                                              │
│  {                                                          │
│    "provider": "google",                                    │
│    "redirect_uri": "https://app.example.com/callback"       │
│  }                                                          │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "authorization_url": "https://accounts.google.com/...",  │
│    "state": "random-state-token",                           │
│    "expires_in": 300                                        │
│  }                                                          │
│                                                             │
│  Errors:                                                    │
│  • 400 AUTH_INVALID_PROVIDER - Unknown provider             │
│  • 400 AUTH_INVALID_REDIRECT - Invalid redirect URI         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  POST /auth/callback                                        │
│  Handle OAuth provider callback                             │
│                                                             │
│  Request Body:                                              │
│  {                                                          │
│    "code": "authorization-code",                            │
│    "state": "state-token",                                  │
│    "provider": "google"                                     │
│  }                                                          │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "user": {                                                │
│      "id": "user-123",                                      │
│      "email": "user@example.com",                           │
│      "name": "User Name"                                    │
│    },                                                       │
│    "session_id": "session-abc",                             │
│    "access_token": "eyJ...",                                │
│    "refresh_token": "refresh-xyz",                          │
│    "expires_in": 900                                        │
│  }                                                          │
│                                                             │
│  Errors:                                                    │
│  • 400 AUTH_STATE_MISMATCH - CSRF detected                  │
│  • 400 AUTH_CODE_EXPIRED - Code expired                     │
│  • 401 AUTH_CODE_EXCHANGE_FAILED - Token exchange failed    │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  POST /auth/refresh                                         │
│  Refresh expired access token                               │
│                                                             │
│  Request Body:                                              │
│  {                                                          │
│    "refresh_token": "refresh-xyz"                           │
│  }                                                          │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "access_token": "eyJ...",                                │
│    "refresh_token": "refresh-new",                          │
│    "expires_in": 900                                        │
│  }                                                          │
│                                                             │
│  Errors:                                                    │
│  • 401 AUTH_INVALID_REFRESH_TOKEN - Invalid token           │
│  • 401 AUTH_REFRESH_TOKEN_EXPIRED - Token expired           │
│  • 401 AUTH_SESSION_REVOKED - Session revoked               │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  POST /auth/logout                                          │
│  Revoke user session                                        │
│                                                             │
│  Request Body:                                              │
│  {                                                          │
│    "session_id": "session-abc"                              │
│  }                                                          │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "success": true,                                         │
│    "message": "Session revoked"                             │
│  }                                                          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  POST /auth/verify                                          │
│  Verify authentication token                                │
│                                                             │
│  Request Body:                                              │
│  {                                                          │
│    "token": "eyJ..."                                        │
│  }                                                          │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "valid": true,                                           │
│    "claims": {                                              │
│      "sub": "user-123",                                     │
│      "sid": "session-abc",                                  │
│      "org": "org-456",                                      │
│      "mfa": true,                                           │
│      "aal": "aal2"                                          │
│    }                                                        │
│  }                                                          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  GET /auth/users/{user_id}/sessions                         │
│  Get all active sessions for a user                         │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "sessions": [                                            │
│      {                                                      │
│        "session_id": "session-abc",                         │
│        "created_at": "2026-04-03T10:00:00Z",                │
│        "last_accessed": "2026-04-03T12:00:00Z",             │
│        "ip_address": "192.168.1.1",                         │
│        "user_agent": "Mozilla/5.0...",                      │
│        "device_fingerprint": "fp-123",                      │
│        "mfa_verified": true,                                │
│        "auth_level": "aal2"                                 │
│      }                                                      │
│    ]                                                        │
│  }                                                          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DELETE /auth/sessions/{session_id}                         │
│  Revoke a specific session                                  │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "success": true,                                         │
│    "message": "Session revoked"                             │
│  }                                                          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  POST /auth/link                                            │
│  Link a provider account to existing user                   │
│                                                             │
│  Request Body:                                              │
│  {                                                          │
│    "user_id": "user-123",                                   │
│    "provider": "github",                                    │
│    "code": "oauth-code"                                     │
│  }                                                          │
│                                                             │
│  Response (200):                                            │
│  {                                                          │
│    "success": true,                                         │
│    "link": {                                                │
│      "provider": "github",                                  │
│      "email": "user@github.com",                            │
│      "linked_at": "2026-04-03T10:00:00Z"                    │
│    }                                                        │
│  }                                                          │
│                                                             │
│  Errors:                                                    │
│  • 409 AUTH_ALREADY_LINKED - Provider already linked        │
│  • 409 AUTH_EMAIL_CONFLICT - Email linked to another user   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Response Formats

#### 5.2.1 Success Response

```json
{
  "success": true,
  "data": {
    // Response-specific data
  },
  "meta": {
    "request_id": "req-abc123",
    "timestamp": "2026-04-03T10:00:00Z"
  }
}
```

#### 5.2.2 Error Response

```json
{
  "success": false,
  "error": {
    "code": "AUTH_STATE_MISMATCH",
    "message": "State parameter mismatch - possible CSRF attack",
    "details": {
      "expected_state": "abc123",
      "received_state": "xyz789"
    },
    "suggestion": "Please try logging in again"
  },
  "meta": {
    "request_id": "req-abc123",
    "timestamp": "2026-04-03T10:00:00Z"
  }
}
```

---

## 6. Error Handling

### 6.1 Error Code Taxonomy

```
┌─────────────────────────────────────────────────────────────┐
│              Error Code Taxonomy                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  AUTH_* - Authentication Errors                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ AUTH_PROVIDER_NOT_FOUND     │ 400 │ Unknown provider │   │
│  │ AUTH_INVALID_REDIRECT       │ 400 │ Bad redirect URI │   │
│  │ AUTH_STATE_MISMATCH         │ 400 │ CSRF detected    │   │
│  │ AUTH_CODE_EXPIRED           │ 400 │ Code expired     │   │
│  │ AUTH_CODE_EXCHANGE_FAILED   │ 401 │ Token exchange   │   │
│  │ AUTH_INVALID_ID_TOKEN       │ 401 │ Bad ID token     │   │
│  │ AUTH_INVALID_CREDENTIALS    │ 401 │ Bad credentials  │   │
│  │ AUTH_INVALID_REFRESH_TOKEN  │ 401 │ Bad refresh      │   │
│  │ AUTH_REFRESH_TOKEN_EXPIRED  │ 401 │ Refresh expired  │   │
│  │ AUTH_SESSION_REVOKED        │ 401 │ Session revoked  │   │
│  │ AUTH_SESSION_CREATION_FAIL  │ 500 │ Session error    │   │
│  │ AUTH_INSUFFICIENT_SCOPE     │ 403 │ Bad scope        │   │
│  │ AUTH_ALREADY_LINKED         │ 409 │ Already linked   │   │
│  │ AUTH_EMAIL_CONFLICT         │ 409 │ Email conflict   │   │
│  │ AUTH_RATE_LIMITED           │ 429 │ Rate limited     │   │
│  │ AUTH_ACCOUNT_LOCKED         │ 423 │ Account locked   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  SESS_* - Session Errors                                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ SESS_NOT_FOUND              │ 404 │ Session missing  │   │
│  │ SESS_EXPIRED                │ 401 │ Session expired  │   │
│  │ SESS_INVALID_SIGNATURE      │ 401 │ Cookie tampered  │   │
│  │ SESS_MAX_REACHED            │ 429 │ Max sessions     │   │
│  │ SESS_DEVICE_MISMATCH        │ 403 │ Device changed   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  PROV_* - Provider Errors                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ PROV_UNAVAILABLE            │ 503 │ Provider down    │   │
│  │ PROV_RATE_LIMITED           │ 429 │ Provider limit   │   │
│  │ PROV_CONFIG_ERROR           │ 500 │ Bad config       │   │
│  │ PROV_TOKEN_REVOKED          │ 401 │ Token revoked    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  SEC_* - Security Errors                                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ SEC_RATE_LIMITED            │ 429 │ Rate limited     │   │
│  │ SEC_BRUTE_FORCE             │ 423 │ Brute force      │   │
│  │ SEC_SUSPICIOUS_ACTIVITY     │ 403 │ Suspicious       │   │
│  │ SEC_CAPTCHA_REQUIRED        │ 403 │ CAPTCHA needed   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Error Handling Strategy

```python
"""
AuthKit Error Handling - Python
Consistent error handling across all components
"""

from enum import Enum
from typing import Optional, Any
from dataclasses import dataclass, field

class ErrorCategory(Enum):
    """Error categories for classification."""
    AUTHENTICATION = "authentication"
    SESSION = "session"
    PROVIDER = "provider"
    SECURITY = "security"
    VALIDATION = "validation"
    INTERNAL = "internal"

@dataclass
class AuthKitError:
    """Base error class for all AuthKit errors."""

    code: str
    message: str
    category: ErrorCategory
    status_code: int = 400
    details: dict[str, Any] = field(default_factory=dict)
    suggestion: Optional[str] = None
    recoverable: bool = True

    def to_dict(self) -> dict:
        """Serialize error for API response."""
        result = {
            "code": self.code,
            "message": self.message,
            "category": self.category.value,
            "status_code": self.status_code,
        }
        if self.details:
            result["details"] = self.details
        if self.suggestion:
            result["suggestion"] = self.suggestion
        return result

class AuthenticationError(AuthKitError):
    """Authentication-related errors."""

    def __init__(self, code: str, message: str, **kwargs):
        super().__init__(
            code=code,
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            **kwargs
        )

class SessionError(AuthKitError):
    """Session-related errors."""

    def __init__(self, code: str, message: str, **kwargs):
        super().__init__(
            code=code,
            message=message,
            category=ErrorCategory.SESSION,
            **kwargs
        )

class ProviderError(AuthKitError):
    """Provider-related errors."""

    def __init__(self, code: str, message: str, **kwargs):
        super().__init__(
            code=code,
            message=message,
            category=ErrorCategory.PROVIDER,
            **kwargs
        )

class SecurityError(AuthKitError):
    """Security-related errors."""

    def __init__(self, code: str, message: str, **kwargs):
        super().__init__(
            code=code,
            message=message,
            category=ErrorCategory.SECURITY,
            recoverable=False,
            **kwargs
        )
```

---

## 7. Security

### 7.1 Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              AuthKit Security Architecture                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Defense in Depth Layers:                                   │
│                                                             │
│  Layer 1: Transport Security                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • HTTPS/TLS 1.3 for all endpoints                    │   │
│  │ • HSTS with preload                                  │   │
│  │ • Certificate pinning (mobile)                       │   │
│  │ • Secure cipher suites only                          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Layer 2: Authentication Security                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • PKCE mandatory for all OAuth flows                 │   │
│  │ • State parameter for CSRF protection                │   │
│  │ • Redirect URI validation                            │   │
│  │ • Token signature verification                       │   │
│  │ • Token expiration enforcement                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Layer 3: Session Security                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • HttpOnly, Secure, SameSite cookies                 │   │
│  │ • HMAC-signed cookie values                          │   │
│  │ • Session binding (IP, device fingerprint)           │   │
│  │ • Sliding expiration with max lifetime               │   │
│  │ • Immediate revocation capability                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Layer 4: Application Security                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Rate limiting per endpoint                         │   │
│  │ • Brute force protection                             │   │
│  │ • Input validation and sanitization                  │   │
│  │ • Security headers (CSP, X-Frame-Options, etc.)      │   │
│  │ • Audit logging for all operations                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Layer 5: Infrastructure Security                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Secrets management (Vault)                         │   │
│  │ • Redis encryption at rest                           │   │
│  │ • Network segmentation                               │   │
│  │ • Principle of least privilege                       │   │
│  │ • Regular security audits                            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Token Security

```
┌─────────────────────────────────────────────────────────────┐
│              Token Security Properties                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Access Token (JWT):                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Algorithm: HS256 (symmetric) or RS256 (asymmetric) │   │
│  │ • TTL: 15 minutes                                    │   │
│  │ • Claims: sub, sid, org, iat, exp, mfa, aal          │   │
│  │ • Storage: Client-side (memory, not localStorage)    │   │
│  │ • Transmission: Authorization: Bearer header         │   │
│  │ • Validation: Local signature + session lookup       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Refresh Token:                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Format: Opaque random string (64 bytes)            │   │
│  │ • TTL: 30 days                                       │   │
│  │ • Storage: Server-side (Redis)                       │   │
│  │ • Rotation: New token on each refresh                │   │
│  │ • Revocation: Immediate via Redis deletion           │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Session Cookie:                                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Format: {session_id}.{hmac_signature}              │   │
│  │ • TTL: 24 hours (sliding)                            │   │
│  │ • Attributes: HttpOnly, Secure, SameSite=Lax         │   │
│  │ • Storage: Browser cookie                            │   │
│  │ • Validation: HMAC signature + Redis lookup          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  ID Token (OIDC):                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Format: JWT signed by provider                     │   │
│  │ • TTL: Provider-defined (typically 1 hour)           │   │
│  │ • Claims: sub, iss, aud, exp, iat, nonce, email      │   │
│  │ • Validation: Provider JWKS signature verification   │   │
│  │ • Usage: User identity extraction only               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 Compliance Mapping

```
┌─────────────────────────────────────────────────────────────┐
│              Compliance Framework Mapping                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SOC 2 Type II:                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ CC6.1 Logical Access: Session management, MFA        │   │
│  │ CC6.2 Identity Verification: Multi-factor auth       │   │
│  │ CC6.3 Access Removal: Session revocation             │   │
│  │ CC6.6 Security Controls: Rate limiting, audit logs   │   │
│  │ CC7.1 Monitoring: Audit logging, alerting            │   │
│  │ CC7.2 Incident Response: Suspicious activity detect  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  GDPR:                                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Art. 5 Data Minimization: Only necessary data stored │   │
│  │ Art. 6 Lawfulness: Consent-based authentication      │   │
│  │ Art. 17 Right to Erasure: Session data deletion      │   │
│  │ Art. 20 Data Portability: User data export           │   │
│  │ Art. 25 Privacy by Design: Secure defaults           │   │
│  │ Art. 32 Security: Encryption, access controls        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  NIST SP 800-63B:                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ AAL1: Single-factor authentication                   │   │
│  │ AAL2: Multi-factor authentication (TOTP, SMS)        │   │
│  │ AAL3: Hardware-backed authentication (WebAuthn)      │   │
│  │ Password requirements: 8+ chars, breach checking     │   │
│  │ Session management: Timeout, re-authentication       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 8. Performance

### 8.1 Performance Targets

```
┌─────────────────────────────────────────────────────────────┐
│              Performance Targets                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Operation                    │ Target (p50) │ Target (p99) │
│  ─────────────────────────────┼──────────────┼──────────────│
│  JWT validation (local)       │ < 0.5ms      │ < 2ms        │
│  Session lookup (Redis)       │ < 1ms        │ < 5ms        │
│  OAuth code exchange          │ < 200ms      │ < 500ms      │
│  Token refresh                │ < 50ms       │ < 200ms      │
│  Session creation             │ < 5ms        │ < 20ms       │
│  Session revocation           │ < 10ms       │ < 50ms       │
│  Provider health check        │ < 100ms      │ < 500ms      │
│                                                             │
│  Throughput Targets:                                        │
│  • Authentication requests: 1000+ req/sec                   │
│  • Token validations: 10000+ req/sec                        │
│  • Session lookups: 5000+ req/sec                           │
│  • Concurrent sessions: 100K+                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Caching Strategy

```
┌─────────────────────────────────────────────────────────────┐
│              Caching Strategy                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  L1 Cache (In-Memory):                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • JWKS public keys (TTL: 1 hour)                     │   │
│  │ • Provider discovery documents (TTL: 24 hours)       │   │
│  │ • Rate limit counters (TTL: 1 minute)                │   │
│  │ • Session validation results (TTL: 5 seconds)        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  L2 Cache (Redis):                                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Session data (TTL: 24 hours, sliding)              │   │
│  │ • Refresh tokens (TTL: 30 days)                      │   │
│  │ • Rate limit state (TTL: 1 minute)                   │   │
│  │ • Provider health status (TTL: 5 minutes)            │   │
│  │ • Account linking data (TTL: 7 days)                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Cache Invalidation:                                        │
│  • Session revocation → Delete session + publish event      │
│  • Password change → Revoke all user sessions               │
│  • Provider config change → Clear discovery cache           │
│  • JWKS rotation → Clear JWKS cache                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. Deployment

### 9.1 Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              Deployment Architecture                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Load Balancer                          │    │
│  │  • TLS termination                                  │    │
│  │  • Health checks                                    │    │
│  │  • Rate limiting (edge)                             │    │
│  └─────────────────────────┬───────────────────────────┘    │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │              AuthKit Service (x3+)                  │    │
│  │                                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │  Instance 1 │  │  Instance 2 │  │ Instance 3 │  │    │
│  │  │             │  │             │  │            │  │    │
│  │  │ • Auth API  │  │ • Auth API  │  │ • Auth API │  │    │
│  │  │ • Session   │  │ • Session   │  │ • Session  │  │    │
│  │  │ • Provider  │  │ • Provider  │  │ • Provider │  │    │
│  │  └─────────────┘  └─────────────┘  └────────────┘  │    │
│  └─────────────────────────┬───────────────────────────┘    │
│                            │                                │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │              Redis Cluster                          │    │
│  │  • 3 masters + 3 replicas                           │    │
│  │  • AOF persistence enabled                          │    │
│  │  • Pub/Sub for session invalidation                 │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Vault (Secrets)                        │    │
│  │  • OAuth client secrets                             │    │
│  │  • JWT signing keys                                 │    │
│  │  • Redis credentials                                │    │
│  │  • Provider API keys                                │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 9.2 Environment Configuration

```
┌─────────────────────────────────────────────────────────────┐
│              Environment Configuration                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Variable                     │ Development │ Production    │
│  ─────────────────────────────┼─────────────┼────────────── │
│  AUTHKIT_BASE_URL             │ localhost   │ auth.pheno.dev│
│  AUTHKIT_LOG_LEVEL            │ debug       │ info          │
│  AUTHKIT_SESSION_TTL          │ 86400       │ 86400         │
│  AUTHKIT_ACCESS_TOKEN_TTL     │ 900         │ 900           │
│  AUTHKIT_REDIS_URL            │ redis://... │ rediss://...  │
│  AUTHKIT_VAULT_URL            │ http://...  │ https://...   │
│  AUTHKIT_ENABLE_MFA           │ false       │ true          │
│  AUTHKIT_ENABLE_PASSKEYS      │ false       │ true          │
│  AUTHKIT_RATE_LIMIT_ENABLED   │ false       │ true          │
│  AUTHKIT_AUDIT_LOG_ENABLED    │ true        │ true          │
│  AUTHKIT_CORS_ORIGINS         │ *           │ app.pheno.dev │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 10. Testing

### 10.1 Testing Strategy

```
┌─────────────────────────────────────────────────────────────┐
│              Testing Strategy                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Unit Tests:                                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • PKCE generation and validation                     │   │
│  │ • JWT token generation and parsing                   │   │
│  │ • Cookie signature generation and validation         │   │
│  │ • Session lifecycle methods                          │   │
│  │ • Provider URL generation                            │   │
│  │ • Error serialization                                │   │
│  │ Target: 90%+ code coverage                           │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Integration Tests:                                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Full OAuth 2.0 flow with mock provider             │   │
│  │ • Session creation and validation with Redis         │   │
│  │ • Token refresh flow                                 │   │
│  │ • Account linking flow                               │   │
│  │ • Provider registry operations                       │   │
│  │ Target: All critical paths covered                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  End-to-End Tests:                                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Complete login flow (browser simulation)           │   │
│  │ • Session management across requests                 │   │
│  │ • Token refresh and rotation                         │   │
│  │ • Multi-provider login and linking                   │   │
│  │ • Error handling and recovery                        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Security Tests:                                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • CSRF protection validation                         │   │
│  │ • XSS prevention (cookie attributes)                 │   │
│  │ • Token tampering detection                          │   │
│  │ • Brute force protection                             │   │
│  │ • Rate limiting effectiveness                        │   │
│  │ • Session fixation prevention                        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Performance Tests:                                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • JWT validation throughput                          │   │
│  │ • Session lookup latency                             │   │
│  │ • Concurrent session handling                        │   │
│  │ • Redis connection pool behavior                     │   │
│  │ • Memory usage under load                            │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 Test Examples

```python
"""
AuthKit Test Examples - Python
"""

import pytest
import time
from unittest.mock import AsyncMock, patch

class TestPKCE:
    """PKCE generation and validation tests."""

    def test_generate_pkce_pair(self):
        """Test PKCE pair generation."""
        pkce = PKCEPair.generate()

        assert len(pkce.code_verifier) >= 43
        assert len(pkce.code_verifier) <= 128
        assert pkce.code_challenge_method == "S256"
        assert pkce.code_challenge != pkce.code_verifier

    def test_pkce_challenge_is_deterministic(self):
        """Test that same verifier produces same challenge."""
        pkce1 = PKCEPair.generate()

        import hashlib
        import base64
        sha256 = hashlib.sha256(pkce1.code_verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(sha256).rstrip(b"=").decode()

        assert pkce1.code_challenge == expected

    def test_different_verifiers_different_challenges(self):
        """Test that different verifiers produce different challenges."""
        pkce1 = PKCEPair.generate()
        pkce2 = PKCEPair.generate()

        assert pkce1.code_verifier != pkce2.code_verifier
        assert pkce1.code_challenge != pkce2.code_challenge

class TestSessionManager:
    """Session management tests."""

    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis client."""
        redis = AsyncMock()
        redis.get.return_value = None
        redis.setex.return_value = True
        redis.sadd.return_value = 1
        redis.zadd.return_value = 1
        return redis

    def test_create_session(self, mock_redis):
        """Test session creation."""
        manager = SessionManager(
            redis_client=mock_redis,
            jwt_secret=b"test-secret",
        )

        session = manager.create_session(
            user_id="user-123",
            organization_id="org-456",
            ip_address="192.168.1.1",
        )

        assert session.user_id == "user-123"
        assert session.organization_id == "org-456"
        assert session.ip_address == "192.168.1.1"
        assert not session.is_revoked
        assert session.is_valid

    def test_session_expiration(self, mock_redis):
        """Test session expiration."""
        manager = SessionManager(
            redis_client=mock_redis,
            jwt_secret=b"test-secret",
        )

        session = manager.create_session(user_id="user-123")

        # Manually expire
        session.expires_at = time.time() - 100

        assert session.is_expired
        assert not session.is_valid

    def test_cookie_signature(self, mock_redis):
        """Test cookie signature generation and validation."""
        manager = SessionManager(
            redis_client=mock_redis,
            jwt_secret=b"test-secret",
        )

        session = manager.create_session(user_id="user-123")
        cookie_value = manager.generate_cookie_value(session.session_id)

        # Valid cookie
        extracted_id = manager.validate_cookie(cookie_value)
        assert extracted_id == session.session_id

        # Tampered cookie
        tampered = cookie_value[:-1] + ("0" if cookie_value[-1] != "0" else "1")
        assert manager.validate_cookie(tampered) is None

class TestTokenValidator:
    """JWT token validation tests."""

    def test_valid_token(self):
        """Test valid JWT token validation."""
        import jwt
        secret = b"test-secret"

        payload = {
            "sub": "user-123",
            "sid": "session-abc",
            "iat": time.time(),
            "exp": time.time() + 900,
        }

        token = jwt.encode(payload, secret, algorithm="HS256")

        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        assert decoded["sub"] == "user-123"
        assert decoded["sid"] == "session-abc"

    def test_expired_token(self):
        """Test expired JWT token rejection."""
        import jwt

        payload = {
            "sub": "user-123",
            "iat": time.time() - 2000,
            "exp": time.time() - 1000,
        }

        token = jwt.encode(payload, b"test-secret", algorithm="HS256")

        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token, b"test-secret", algorithms=["HS256"])

    def test_invalid_signature(self):
        """Test invalid signature rejection."""
        import jwt

        payload = {"sub": "user-123", "exp": time.time() + 900}
        token = jwt.encode(payload, b"test-secret", algorithm="HS256")

        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(token, b"wrong-secret", algorithms=["HS256"])
```

---

## 11. Migration Guide

### 11.1 Migration from pheno-credentials

```
┌─────────────────────────────────────────────────────────────┐
│              Migration from pheno-credentials               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Phase 1: Assessment (Week 1)                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Inventory existing OAuth configurations            │   │
│  │ • Map current credential storage patterns            │   │
│  │ • Identify all services using pheno-credentials      │   │
│  │ • Document current authentication flows              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Phase 2: Parallel Deployment (Weeks 2-4)                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Deploy AuthKit alongside pheno-credentials         │   │
│  │ • Configure AuthKit with existing provider settings  │   │
│  │ • Enable dual authentication (old + new)             │   │
│  │ • Monitor both systems for discrepancies             │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Phase 3: Gradual Migration (Weeks 5-8)                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Migrate services one by one to AuthKit             │   │
│  │ • Update credential storage to AuthKit sessions      │   │
│  │ • Test each service thoroughly                       │   │
│  │ • Roll back if issues detected                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Phase 4: Decommission (Week 9)                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ • Verify all services migrated                       │   │
│  │ • Migrate remaining credentials                      │   │
│  │ • Disable pheno-credentials authentication           │   │
│  │ • Archive pheno-credentials data                     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 11.2 Code Migration Examples

```python
"""
Migration Examples - Before and After
"""

# BEFORE: pheno-credentials OAuth flow
from pheno_credentials.oauth.flows import OAuthFlow
from pheno_credentials.oauth.providers import GoogleProvider

flow = OAuthFlow(
    provider=GoogleProvider(
        client_id="xxx",
        client_secret="yyy",
        redirect_uri="http://localhost:8000/callback",
    ),
)
auth_url = flow.get_authorization_url()

# AFTER: AuthKit OAuth flow
from authkit import AuthKitClient, AuthKitConfig

client = AuthKitClient(AuthKitConfig(
    base_url="https://auth.phenotype.dev",
    client_id="xxx",
    client_secret="yyy",
    redirect_uri="http://localhost:8000/callback",
))
result = await client.login(provider="google")
auth_url = result["authorization_url"]
```

---

## 12. Glossary

| Term | Definition |
|------|------------|
| AAL | Authentication Assurance Level (NIST) |
| ABAC | Attribute-Based Access Control |
| ACL | Access Control List |
| CSRF | Cross-Site Request Forgery |
| HMAC | Hash-based Message Authentication Code |
| ID Token | OIDC token containing user identity claims |
| JWKS | JSON Web Key Set |
| JWT | JSON Web Token |
| MFA | Multi-Factor Authentication |
| OIDC | OpenID Connect |
| OAuth | Open Authorization |
| PKCE | Proof Key for Code Exchange |
| RBAC | Role-Based Access Control |
| ReBAC | Relationship-Based Access Control |
| SAML | Security Assertion Markup Language |
| SSO | Single Sign-On |
| TTL | Time To Live |
| WebAuthn | Web Authentication API (FIDO2) |
| ZTA | Zero Trust Architecture |

---

## 13. References

| Document | Description |
|----------|-------------|
| ADR-001 | Authentication Flow Design |
| ADR-002 | Session Management Strategy |
| ADR-003 | Multi-Provider Support |
| SOTA | Authentication Toolkits State of the Art |
| RFC 6749 | OAuth 2.0 Authorization Framework |
| RFC 7636 | PKCE for OAuth 2.0 |
| RFC 7519 | JSON Web Token (JWT) |
| NIST 800-63B | Digital Identity Guidelines |
| OWASP Auth Cheat Sheet | Authentication Security Guide |

---

*Specification Version: 1.0.0*
*Last Updated: 2026-04-03*
*Authors: Phenotype Architecture Team*
*Review Cycle: Quarterly*
*Next Review: 2026-07-03*
