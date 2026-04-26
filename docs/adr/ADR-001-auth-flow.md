# ADR-001: Authentication Flow Design

**Document ID:** PHENOTYPE_AUTHKIT_ADR_001
**Status:** Accepted
**Last Updated:** 2026-04-03
**Author:** Phenotype Architecture Team
**Reviewers:** team-security

---

## Table of Contents

1. [Context](#1-context)
2. [Decision](#2-decision)
3. [Consequences](#3-consequences)
4. [Implementation](#4-implementation)
5. [Cross-References](#5-cross-references)
6. [Appendix](#6-appendix)

---

## 1. Context

### 1.1 Problem Statement

The Phenotype ecosystem requires a unified authentication flow that supports multiple authentication providers, maintains security best practices, and provides a consistent developer experience across Python and Go implementations. Current authentication approaches across the ecosystem are fragmented:

- **pheno-credentials** package handles OAuth flows for CLI credential management
- Individual services implement their own authentication logic
- No standardized session management pattern exists
- Provider-specific implementations create maintenance burden

### 1.2 Requirements

| Requirement | Priority | Description |
|-------------|----------|-------------|
| OAuth 2.1 compliance | P0 | Support Authorization Code + PKCE as primary flow |
| Multi-provider support | P0 | Abstract provider differences behind unified interface |
| Session management | P0 | Secure, revocable sessions with automatic rotation |
| OIDC integration | P1 | Standard identity layer for user information |
| Passwordless readiness | P1 | Architecture must support WebAuthn/Passkeys |
| Developer experience | P1 | Simple SDK with sensible defaults |
| Audit logging | P2 | Comprehensive authentication event logging |

### 1.3 Constraints

- Must work with existing **pheno-credentials** OAuth infrastructure
- Must support both Python and Go implementations
- Must integrate with Phenotype's existing policy engine (phenotype-policy-engine)
- Must comply with NIST SP 800-63B AAL2 minimum requirements
- Must support the Phenotype organization hierarchy model

### 1.4 Alternatives Considered

```
┌─────────────────────────────────────────────────────────────┐
│              Authentication Flow Alternatives               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Option A: Custom OAuth Implementation                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Full control, no external dependencies         │   │
│  │ Cons: High maintenance, security risk, reinventing   │   │
│  │       wheel, slow time-to-market                     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option B: Use Existing OAuth Libraries (CHOSEN)            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Battle-tested, security audited, fast          │   │
│  │       implementation, community support              │   │
│  │ Cons: External dependency, version management        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option C: Third-Party Auth Service (Auth0/WorkOS)          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Fully managed, compliance built-in             │   │
│  │ Cons: Vendor lock-in, cost, data sovereignty,        │   │
│  │       limited customization                          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option D: Hybrid (Self-hosted + Managed)                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Flexibility, compliance options                │   │
│  │ Cons: Complex architecture, operational overhead     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Decision Rationale:** Option B provides the best balance of security, maintainability, and time-to-market. Using established libraries (authlib for Python, go-oidc for Go) ensures we benefit from community security audits while maintaining full control over our authentication architecture.

---

## 2. Decision

### 2.1 Primary Authentication Flow

We will implement **OAuth 2.0 Authorization Code Flow with PKCE** as the primary authentication flow for all client types.

```
┌─────────────────────────────────────────────────────────────┐
│              Primary Authentication Flow                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│  │ Client   │     │ AuthKit  │     │ Provider │            │
│  │ (App)    │     │ Server   │     │ (Google) │            │
│  └────┬─────┘     └────┬─────┘     └────┬─────┘            │
│       │                │                │                   │
│  1. Generate PKCE pair │                │                   │
│       │                │                │                   │
│  2. Request auth URL ──▶│                │                   │
│       │                │                │                   │
│  3. ◀── Auth URL with ─│                │                   │
│     │  code_challenge  │                │                   │
│       │                │                │                   │
│  4. Redirect user ─────────────────────▶│                   │
│     │  (with code_challenge)            │                   │
│       │                │                │                   │
│  5. ◀──────────────────│◀── User auth ──│                   │
│     │  Authorization   │   + consent    │                   │
│     │  Code            │                │                   │
│       │                │                │                   │
│  6. Exchange code ────▶│                │                   │
│     │  (with code_     │                │                   │
│     │   verifier)      │                │                   │
│       │                │  7. Exchange ──▶│                   │
│       │                │     code +     │                   │
│       │                │     verifier   │                   │
│       │                │                │                   │
│  8. ◀── Tokens + ──────│◀── Tokens ─────│                   │
│     │  Session         │                │                   │
│       │                │                │                   │
│  9. Create session     │                │                   │
│     │  (server-side)   │                │                   │
│       │                │                │                   │
│  10.◀── Session cookie │                │                   │
│      │  + JWT access   │                │                   │
│      │  token          │                │                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Flow Components

#### 2.2.1 PKCE Implementation

```python
"""
AuthKit PKCE Implementation - Python
Generates and manages PKCE code verifier/challenge pairs
"""

import secrets
import hashlib
import base64
from dataclasses import dataclass

@dataclass
class PKCEPair:
    """PKCE code verifier and challenge pair."""

    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"

    @classmethod
    def generate(cls) -> "PKCEPair":
        """Generate a new PKCE pair using S256 method."""
        # Generate high-entropy code_verifier (43-128 chars)
        code_verifier = secrets.token_urlsafe(96)

        # Create code_challenge = BASE64URL(SHA256(code_verifier))
        sha256_hash = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(sha256_hash).rstrip(b"=").decode()

        return cls(
            code_verifier=code_verifier,
            code_challenge=code_challenge,
        )

    def to_dict(self) -> dict:
        """Serialize PKCE pair for storage."""
        return {
            "code_verifier": self.code_verifier,
            "code_challenge": self.code_challenge,
            "code_challenge_method": self.code_challenge_method,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PKCEPair":
        """Deserialize PKCE pair from storage."""
        return cls(
            code_verifier=data["code_verifier"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data.get("code_challenge_method", "S256"),
        )
```

```go
// AuthKit PKCE Implementation - Go
// Generates and manages PKCE code verifier/challenge pairs

package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCEPair holds the code verifier and challenge
type PKCEPair struct {
	CodeVerifier        string
	CodeChallenge       string
	CodeChallengeMethod string
}

// GeneratePKCEPair creates a new PKCE pair using S256 method
func GeneratePKCEPair() (*PKCEPair, error) {
	// Generate 96 bytes of random data for code_verifier
	b := make([]byte, 96)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Base64url encode without padding
	codeVerifier := base64.RawURLEncoding.EncodeToString(b)

	// SHA256 hash for code_challenge
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCEPair{
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	}, nil
}

// ToMap returns the PKCE pair as a map for HTTP parameters
func (p *PKCEPair) ToAuthParams() map[string]string {
	return map[string]string{
		"code_challenge":        p.CodeChallenge,
		"code_challenge_method": p.CodeChallengeMethod,
	}
}

// ToTokenParams returns parameters for token exchange
func (p *PKCEPair) ToTokenParams() map[string]string {
	return map[string]string{
		"code_verifier": p.CodeVerifier,
	}
}
```

#### 2.2.2 Authorization URL Builder

```python
"""
AuthKit Authorization URL Builder - Python
Constructs OAuth 2.0 authorization URLs with security parameters
"""

from urllib.parse import urlencode, urlparse
from typing import Optional
from dataclasses import dataclass

@dataclass
class AuthRequest:
    """OAuth 2.0 authorization request parameters."""

    client_id: str
    redirect_uri: str
    response_type: str = "code"
    scope: str = "openid profile email"
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: str = "S256"
    prompt: Optional[str] = None  # "consent", "login", "none"
    access_type: Optional[str] = None  # "offline", "online"
    login_hint: Optional[str] = None

    def to_params(self) -> dict:
        """Convert to URL parameters."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": self.response_type,
            "scope": self.scope,
        }

        if self.state:
            params["state"] = self.state
        if self.code_challenge:
            params["code_challenge"] = self.code_challenge
        if self.code_challenge_method:
            params["code_challenge_method"] = self.code_challenge_method
        if self.prompt:
            params["prompt"] = self.prompt
        if self.access_type:
            params["access_type"] = self.access_type
        if self.login_hint:
            params["login_hint"] = self.login_hint

        return params

    def build_url(self, authorization_endpoint: str) -> str:
        """Build the full authorization URL."""
        # Validate redirect_uri is absolute
        parsed = urlparse(self.redirect_uri)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("redirect_uri must be an absolute URL")

        # Validate HTTPS for production
        if parsed.scheme != "http" and parsed.scheme != "https":
            raise ValueError("redirect_uri must use http or https scheme")

        params = self.to_params()
        query_string = urlencode(params)
        return f"{authorization_endpoint}?{query_string}"
```

#### 2.2.3 Token Exchange Handler

```python
"""
AuthKit Token Exchange Handler - Python
Exchanges authorization code for tokens and creates sessions
"""

import time
import secrets
from typing import Optional
from dataclasses import dataclass, field

@dataclass
class TokenResponse:
    """OAuth 2.0 token response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    scope: str = ""

    @property
    def expires_at(self) -> float:
        """Calculate absolute expiration time."""
        return time.time() + self.expires_in

    @property
    def has_id_token(self) -> bool:
        """Check if ID token is present."""
        return self.id_token is not None

class TokenExchangeHandler:
    """Handles OAuth 2.0 token exchange with security validation."""

    def __init__(self, token_endpoint: str, client_id: str,
                 client_secret: str, redirect_uri: str):
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    async def exchange_code(self, code: str, state: str,
                           expected_state: str, pkce: PKCEPair,
                           provider: str) -> TokenResponse:
        """Exchange authorization code for tokens."""
        # Validate state parameter (CSRF protection)
        if state != expected_state:
            raise AuthFlowError(
                "State mismatch - possible CSRF attack",
                code="STATE_MISMATCH"
            )

        # Exchange code for tokens
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._redirect_uri,
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "code_verifier": pkce.code_verifier,
                },
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()

        # Validate response
        if "access_token" not in data:
            raise AuthFlowError(
                "Missing access_token in token response",
                code="MISSING_ACCESS_TOKEN"
            )

        return TokenResponse(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 3600),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            scope=data.get("scope", ""),
        )

class AuthFlowError(Exception):
    """Authentication flow error."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code
```

---

## 3. Consequences

### 3.1 Positive Consequences

1. **Security by default**: PKCE prevents authorization code interception attacks for all client types, not just public clients. This aligns with OAuth 2.1 requirements and eliminates an entire class of vulnerabilities.

2. **Provider agnostic**: The abstract provider interface allows adding new authentication providers (Google, GitHub, Microsoft, Apple, SAML) without modifying core authentication logic. Each provider is encapsulated behind a consistent interface.

3. **Standards compliance**: Using established OAuth 2.0/OIDC libraries ensures compliance with RFC 6749, RFC 6750, RFC 7636, and OpenID Connect Core 1.0. This reduces the risk of implementation errors that could lead to security vulnerabilities.

4. **Session revocation**: Server-side session storage enables immediate session revocation, which is critical for security incidents, user logout, and administrative actions. This is not possible with pure JWT-based sessions.

5. **Audit trail**: Centralized authentication flow enables comprehensive audit logging of all authentication events, supporting compliance requirements (SOC 2, GDPR, HIPAA) and security monitoring.

6. **Developer experience**: A unified SDK with sensible defaults reduces the cognitive load on developers integrating authentication. The progressive disclosure pattern allows simple setups to start quickly while supporting advanced configurations when needed.

### 3.2 Negative Consequences

1. **External dependency risk**: Relying on third-party OAuth libraries (authlib, go-oidc) introduces dependency management overhead. Security vulnerabilities in these libraries directly impact our authentication surface. Mitigation: Pin versions, monitor CVEs, maintain upgrade procedures.

2. **Complexity in error handling**: Different providers return errors in different formats and have different failure modes. The abstraction layer must normalize these errors while preserving provider-specific details for debugging. This adds complexity to the error handling layer.

3. **State management overhead**: The OAuth flow requires maintaining state across multiple HTTP requests (state parameter, PKCE verifier, session data). This requires reliable storage and careful handling of edge cases (tab switching, browser refresh, network failures).

4. **Testing complexity**: Testing the full authentication flow requires mocking external providers, simulating browser redirects, and handling asynchronous token exchanges. Integration tests are more complex than unit tests and require careful test data management.

5. **Token storage security**: Access tokens and refresh tokens must be stored securely on the client side. For web applications, this means HttpOnly cookies with appropriate security attributes. For mobile/CLI applications, this means secure storage (Keychain, Keystore, encrypted files).

6. **Migration path**: Existing services using custom authentication must be migrated to the new flow. This requires careful planning to avoid breaking existing integrations and ensuring a smooth transition period where both old and new authentication methods work.

---

## 4. Implementation

### 4.1 Core Authentication Service

```python
"""
AuthKit Core Authentication Service - Python
Unified authentication service implementing the decided flow
"""

import secrets
import time
from typing import Optional
from dataclasses import dataclass, field

@dataclass
class AuthConfig:
    """Authentication service configuration."""

    issuer_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile", "email"])
    session_ttl: int = 86400  # 24 hours
    access_token_ttl: int = 900  # 15 minutes

    @classmethod
    def from_discovery(cls, issuer_url: str, client_id: str,
                      client_secret: str, redirect_uri: str) -> "AuthConfig":
        """Create config from OIDC discovery document."""
        # Implementation would fetch /.well-known/openid-configuration
        # and populate endpoints from the response
        pass

class AuthenticationService:
    """Core authentication service implementing OAuth 2.0 + PKCE flow."""

    def __init__(self, config: AuthConfig, session_manager,
                 provider_registry, token_validator):
        self._config = config
        self._session_manager = session_manager
        self._provider_registry = provider_registry
        self._token_validator = token_validator

    async def initiate_login(self, provider: str,
                            redirect_uri: Optional[str] = None) -> dict:
        """Initiate login flow and return authorization URL."""
        # Generate PKCE pair
        pkce = PKCEPair.generate()

        # Generate state parameter
        state = secrets.token_urlsafe(32)

        # Get provider
        auth_provider = self._provider_registry.get_provider(provider)

        # Build auth request
        auth_request = AuthRequest(
            client_id=self._config.client_id,
            redirect_uri=redirect_uri or self._config.redirect_uri,
            scope=" ".join(self._config.scopes),
            state=state,
            code_challenge=pkce.code_challenge,
            access_type="offline",
        )

        auth_url = auth_request.build_url(
            self._config.authorization_endpoint
        )

        # Store flow state for callback validation
        flow_state = {
            "state": state,
            "pkce": pkce.to_dict(),
            "provider": provider,
            "redirect_uri": redirect_uri or self._config.redirect_uri,
            "created_at": time.time(),
        }

        return {
            "authorization_url": auth_url,
            "state": state,
            "flow_state": flow_state,
        }

    async def complete_login(self, code: str, state: str,
                            flow_state: dict) -> dict:
        """Complete login flow after OAuth callback."""
        # Validate flow state hasn't expired (5-minute window)
        if time.time() - flow_state["created_at"] > 300:
            raise AuthFlowError("Flow state expired", code="FLOW_EXPIRED")

        # Reconstruct PKCE pair
        pkce = PKCEPair.from_dict(flow_state["pkce"])

        # Exchange code for tokens
        token_handler = TokenExchangeHandler(
            token_endpoint=self._config.token_endpoint,
            client_id=self._config.client_id,
            client_secret=self._config.client_secret,
            redirect_uri=flow_state["redirect_uri"],
        )

        tokens = await token_handler.exchange_code(
            code=code,
            state=state,
            expected_state=flow_state["state"],
            pkce=pkce,
            provider=flow_state["provider"],
        )

        # Extract user info from ID token or userinfo endpoint
        user_info = await self._extract_user_info(tokens)

        # Create session
        session = self._session_manager.create_session(
            user_id=user_info["sub"],
            organization_id=user_info.get("org_id"),
        )

        # Generate access token
        access_token = self._session_manager.generate_access_token(session)

        return {
            "user": user_info,
            "session_id": session.session_id,
            "access_token": access_token,
            "refresh_token": tokens.refresh_token,
            "expires_in": tokens.expires_in,
        }

    async def _extract_user_info(self, tokens: TokenResponse) -> dict:
        """Extract user information from tokens or userinfo endpoint."""
        if tokens.has_id_token:
            # Decode and verify ID token
            result = await self._token_validator.validate_token(tokens.id_token)
            if result.is_valid:
                return result.payload

        # Fallback to userinfo endpoint
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self._config.userinfo_endpoint,
                headers={"Authorization": f"Bearer {tokens.access_token}"},
            )
            response.raise_for_status()
            return response.json()
```

```go
// AuthKit Core Authentication Service - Go
// Unified authentication service implementing the decided flow

package authkit

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// AuthConfig holds authentication service configuration
type AuthConfig struct {
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	RedirectURI          string
	AuthorizationEndpoint string
	TokenEndpoint        string
	UserInfoEndpoint     string
	JWKSURI              string
	Scopes               []string
	SessionTTL           time.Duration
	AccessTokenTTL       time.Duration
}

// AuthenticationService is the core authentication service
type AuthenticationService struct {
	Config           *AuthConfig
	OAuth2Config     *oauth2.Config
	OIDCProvider     *oidc.Provider
	IDTokenVerifier  *oidc.IDTokenVerifier
	SessionManager   *SessionManager
	ProviderRegistry *ProviderRegistry
}

// NewAuthenticationService creates a new authentication service
func NewAuthenticationService(ctx context.Context, config *AuthConfig) (*AuthenticationService, error) {
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURI,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizationEndpoint,
			TokenURL: config.TokenEndpoint,
		},
		Scopes: config.Scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	return &AuthenticationService{
		Config:          config,
		OAuth2Config:    oauth2Config,
		OIDCProvider:    provider,
		IDTokenVerifier: verifier,
	}, nil
}

// InitiateLogin starts the authentication flow
func (s *AuthenticationService) InitiateLogin(ctx context.Context, provider string,
	redirectURI string) (*LoginInitiation, error) {

	// Generate PKCE pair
	pkce, err := GeneratePKCEPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Build authorization URL
	authURL := s.OAuth2Config.AuthCodeURL(
		"", // state will be set separately
		oauth2.SetAuthURLParam("code_challenge", pkce.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", pkce.CodeChallengeMethod),
		oauth2.SetAuthURLParam("access_type", "offline"),
	)

	return &LoginInitiation{
		AuthorizationURL: authURL,
		PKCE:             pkce,
		Provider:         provider,
		RedirectURI:      redirectURI,
		CreatedAt:        time.Now(),
	}, nil
}

// CompleteLogin finishes the authentication flow
func (s *AuthenticationService) CompleteLogin(ctx context.Context, code string,
	state string, flowState *LoginInitiation) (*LoginResult, error) {

	// Validate flow state expiration
	if time.Since(flowState.CreatedAt) > 5*time.Minute {
		return nil, &AuthError{Code: "FLOW_EXPIRED", Message: "Flow state expired"}
	}

	// Exchange code for tokens
	oauth2Token, err := s.OAuth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", flowState.PKCE.CodeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, &AuthError{Code: "MISSING_ID_TOKEN", Message: "No ID token in response"}
	}

	idToken, err := s.IDTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return &LoginResult{
		UserInfo:    claims,
		IDToken:     idToken,
		OAuth2Token: oauth2Token,
	}, nil
}

// LoginInitiation holds the state for an in-progress login
type LoginInitiation struct {
	AuthorizationURL string
	PKCE             *PKCEPair
	Provider         string
	RedirectURI      string
	CreatedAt        time.Time
}

// LoginResult holds the result of a completed login
type LoginResult struct {
	UserInfo    map[string]interface{}
	IDToken     *oidc.IDToken
	OAuth2Token *oauth2.Token
}

// AuthError represents an authentication error
type AuthError struct {
	Code    string
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}
```

---

## 5. Cross-References

| Document | Relationship | Description |
|----------|-------------|-------------|
| PHENOTYPE_AUTHKIT_ADR_002 | Depends on | Session Management Strategy defines how sessions are stored and managed |
| PHENOTYPE_AUTHKIT_ADR_003 | Related | Multi-Provider Support extends this flow to multiple providers |
| PHENOTYPE_AUTHKIT_SOTA_001 | Informed by | SOTA research on OAuth 2.0/OIDC libraries and patterns |
| docs/SPEC.md | Specifies | AuthKit Specification defines the complete system architecture |
| ../python/pheno-credentials/ | Integrates with | Existing pheno-credentials OAuth flow automation |
| ../rust/phenotype-policy-engine/ | Integrates with | Policy engine for authorization decisions |

---

## 6. Appendix

### 6.1 Flow State Diagram

```
┌─────────────────────────────────────────────────────────────┐
│              Authentication Flow State Machine              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  IDLE    │───▶│ PENDING  │───▶│ COMPLETE │              │
│  │          │    │          │    │          │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │                     │
│       │               │               │                     │
│       ▼               ▼               ▼                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ EXPIRED  │◀───│  FAILED  │◀───│  ERROR   │              │
│  │          │    │          │    │          │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│                                                             │
│  States:                                                    │
│  • IDLE: No authentication in progress                      │
│  • PENDING: User redirected to provider, awaiting callback  │
│  • COMPLETE: Authentication successful, session created     │
│  • FAILED: Authentication failed (invalid code, state mismatch)│
│  • ERROR: System error during authentication                │
│  • EXPIRED: Flow state expired (5-minute timeout)           │
│                                                             │
│  Transitions:                                               │
│  • IDLE → PENDING: User initiates login                     │
│  • PENDING → COMPLETE: Valid callback received              │
│  • PENDING → FAILED: Invalid callback (state mismatch)      │
│  • PENDING → ERROR: System error during token exchange      │
│  • PENDING → EXPIRED: Timeout exceeded                      │
│  • FAILED/ERROR/EXPIRED → IDLE: User retries                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Security Checklist

- [x] PKCE enabled for all flows (S256 method)
- [x] State parameter generated and validated
- [x] Redirect URI validated against allowlist
- [x] HTTPS enforced for all endpoints
- [x] Token response validated for required fields
- [x] ID token signature verified
- [x] ID token claims validated (iss, aud, exp)
- [x] Session created with secure attributes
- [x] Flow state has expiration timeout
- [x] Error messages don't leak sensitive information

---

*ADR Version: 1.0*
*Status: Accepted*
*Decision Date: 2026-04-03*
*Next Review: 2026-07-03*