# ADR-003: Multi-Provider Support

**Document ID:** PHENOTYPE_AUTHKIT_ADR_003
**Status:** Proposed
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

The Phenotype ecosystem serves diverse user bases with varying identity provider preferences. Enterprise users require SAML/OIDC integration with existing identity providers (Okta, Azure AD, OneLogin), while individual developers prefer social login (Google, GitHub, Apple). The current authentication infrastructure does not support multiple providers in a unified manner:

- Each service implements its own provider-specific authentication
- No unified user identity model exists across providers
- Account linking between providers is not supported
- Provider-specific error handling and retry logic is duplicated
- No standardized provider configuration management

### 1.2 Requirements

| Requirement | Priority | Description |
|-------------|----------|-------------|
| Provider abstraction | P0 | Unified interface for all authentication providers |
| Provider registry | P0 | Dynamic registration and configuration of providers |
| Unified user model | P0 | Consistent user identity across all providers |
| Account linking | P1 | Link multiple providers to single user identity |
| Provider-specific flows | P1 | Support OAuth2, OIDC, SAML, LDAP protocols |
| Configuration management | P1 | Centralized provider configuration with secrets management |
| Error normalization | P2 | Consistent error handling across providers |
| Provider health monitoring | P2 | Monitor provider availability and response times |

### 1.3 Constraints

- Must support the providers required by existing Phenotype services
- Must handle provider outages gracefully (degraded mode)
- Must maintain security properties across all provider types
- Must support provider-specific compliance requirements (SOC 2, HIPAA)
- Must integrate with existing pheno-credentials OAuth infrastructure

### 1.4 Alternatives Considered

```
┌─────────────────────────────────────────────────────────────┐
│              Multi-Provider Architecture Alternatives       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Option A: Single Provider (Current State)                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Simple implementation, no abstraction overhead │   │
│  │ Cons: Vendor lock-in, limited user choice, no        │   │
│  │       fallback, enterprise customers cannot use      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option B: Provider-Specific Implementations                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Full control over each provider's behavior     │   │
│  │ Cons: Code duplication, inconsistent UX, high        │   │
│  │       maintenance burden, difficult to add providers │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option C: Abstract Provider Pattern (CHOSEN)               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Clean abstraction, easy to add providers,      │   │
│  │       consistent UX, centralized configuration       │   │
│  │ Cons: Abstraction overhead, may not cover all        │   │
│  │       provider-specific features                     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option D: Third-Party Aggregator (Auth0/WorkOS)            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Managed service, many providers built-in       │   │
│  │ Cons: Vendor lock-in, cost, data sovereignty,        │   │
│  │       limited customization, external dependency     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Decision Rationale:** Option C (Abstract Provider Pattern) provides the best balance of flexibility, maintainability, and control. The abstraction layer allows adding new providers without modifying core authentication logic while maintaining full control over the user experience and data handling. This aligns with the Phenotype ecosystem's philosophy of building composable, self-contained components.

---

## 2. Decision

### 2.1 Provider Abstraction Architecture

We will implement an abstract provider pattern with a registry for dynamic provider management and a unified user model for cross-provider identity management.

```
┌─────────────────────────────────────────────────────────────┐
│              Multi-Provider Architecture                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Provider Registry                      │    │
│  │                                                     │    │
│  │  ┌─────────────────────────────────────────────┐    │    │
│  │  │           Provider Configuration            │    │    │
│  │  │  • Google OAuth2 (client_id, secret, scopes)│    │    │
│  │  │  • GitHub OAuth2 (client_id, secret, scopes)│    │    │
│  │  │  • Microsoft OIDC (tenant_id, client_id...) │    │    │
│  │  │  • Apple Sign-In (team_id, key_id, key)     │    │    │
│  │  │  • SAML Enterprise (metadata_url, cert...)  │    │    │
│  │  │  • Custom OAuth2 (configurable endpoints)   │    │    │
│  │  └─────────────────────────────────────────────┘    │    │
│  │                        │                            │    │
│  │  ┌─────────────────────▼─────────────────────┐      │    │
│  │  │          Provider Adapter Layer           │      │    │
│  │  │                                           │      │    │
│  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐  │      │    │
│  │  │  │ Google   │ │ GitHub   │ │ Microsoft│  │      │    │
│  │  │  │ Adapter  │ │ Adapter  │ │ Adapter  │  │      │    │
│  │  │  └────┬─────┘ └────┬─────┘ └────┬─────┘  │      │    │
│  │  │       │            │            │         │      │    │
│  │  │  ┌────▼────────────▼────────────▼─────┐   │      │    │
│  │  │  │       Unified User Profile         │   │      │    │
│  │  │  │  • provider_id (per provider)      │   │      │    │
│  │  │  │  • email (normalized)              │   │      │    │
│  │  │  │  • name, avatar, locale            │   │      │    │
│  │  │  │  • email_verified (per provider)   │   │      │    │
│  │  │  └────────────────────────────────────┘   │      │    │
│  │  └───────────────────────────────────────────┘      │    │
│  │                        │                            │    │
│  │  ┌─────────────────────▼─────────────────────┐      │    │
│  │  │          Account Linking Service          │      │    │
│  │  │  • Link multiple providers to one user    │      │    │
│  │  │  • Resolve identity conflicts             │      │    │
│  │  │  • Manage provider preferences            │      │    │
│  │  └───────────────────────────────────────────┘      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Provider Interface

```python
"""
AuthKit Provider Interface - Python
Abstract base class defining the contract for authentication providers
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum

class ProviderProtocol(Enum):
    """Supported authentication protocols."""
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    LDAP = "ldap"
    CUSTOM = "custom"

class ProviderCapability(Enum):
    """Provider capabilities."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    REFRESH_TOKEN = "refresh_token"
    REVOKE_TOKEN = "revoke_token"
    USERINFO = "userinfo"
    ID_TOKEN = "id_token"
    PKCE = "pkce"

@dataclass
class ProviderConfig:
    """Provider configuration."""

    provider_id: str
    provider_type: str  # "google", "github", "microsoft", etc.
    protocol: ProviderProtocol
    client_id: str
    client_secret: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    redirect_uri: str = ""
    scopes: list[str] = field(default_factory=list)
    capabilities: list[ProviderCapability] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    @classmethod
    def from_discovery(cls, provider_id: str, provider_type: str,
                      issuer_url: str, client_id: str,
                      client_secret: str, redirect_uri: str,
                      scopes: list[str]) -> "ProviderConfig":
        """Create config from OIDC discovery document."""
        # Implementation would fetch /.well-known/openid-configuration
        # and populate endpoints from the response
        pass

@dataclass
class UserProfile:
    """Normalized user profile from any provider."""

    provider_id: str  # ID from the provider
    provider_type: str  # "google", "github", etc.
    email: str
    email_verified: bool
    name: str
    avatar_url: Optional[str] = None
    locale: Optional[str] = None
    phone_number: Optional[str] = None
    raw_profile: dict[str, Any] = field(default_factory=dict)

    def normalize_email(self) -> str:
        """Normalize email address (lowercase, trimmed)."""
        return self.email.lower().strip()

    def matches(self, other: "UserProfile") -> bool:
        """Check if two profiles likely represent the same user."""
        if self.normalize_email() == other.normalize_email():
            return True
        if self.provider_id == other.provider_id:
            return True
        return False

class AuthProvider(ABC):
    """Abstract base class for authentication providers."""

    def __init__(self, config: ProviderConfig):
        self._config = config

    @property
    def config(self) -> ProviderConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._config.provider_id

    @property
    def provider_type(self) -> str:
        return self._config.provider_type

    @abstractmethod
    async def get_authorization_url(self, state: str,
                                   pkce_challenge: Optional[str] = None,
                                   login_hint: Optional[str] = None) -> str:
        """Generate the authorization URL for user redirect."""
        pass

    @abstractmethod
    async def handle_callback(self, code: str, state: str,
                             pkce_verifier: Optional[str] = None) -> tuple:
        """
        Handle the OAuth callback and return (UserProfile, TokenResponse).
        """
        pass

    @abstractmethod
    async def get_user_info(self, access_token: str) -> UserProfile:
        """Fetch user information using access token."""
        pass

    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> dict:
        """Refresh an expired access token."""
        pass

    @abstractmethod
    async def revoke_access_token(self, access_token: str) -> bool:
        """Revoke an access token."""
        pass

    async def validate_token(self, access_token: str) -> bool:
        """Validate an access token (optional, default: try userinfo)."""
        try:
            await self.get_user_info(access_token)
            return True
        except Exception:
            return False

    def supports_capability(self, capability: ProviderCapability) -> bool:
        """Check if provider supports a specific capability."""
        return capability in self._config.capabilities
```

### 2.3 Account Linking Flow

```
┌─────────────────────────────────────────────────────────────┐
│              Account Linking Flow                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Scenario: User logs in with Google, then wants to link     │
│  GitHub account                                             │
│                                                             │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│  │ User     │     │ AuthKit  │     │ GitHub   │            │
│  │          │     │          │     │          │            │
│  │ 1. Clicks│     │          │     │          │            │
│  │ "Link    │     │          │     │          │            │
│  │ GitHub"  │     │          │     │          │            │
│  │          │     │          │     │          │            │
│  │          │──2. Generate link URL─────────▶│            │
│  │          │   │ (with existing user context)            │
│  │          │     │          │     │          │            │
│  │          │◀──3. Redirect to GitHub auth─────────       │
│  │          │     │          │     │          │            │
│  │ 4. Auths │     │          │     │          │            │
│  │ with     │     │          │     │          │            │
│  │ GitHub   │     │          │     │          │            │
│  │          │     │◀──5. Callback with code────────        │
│  │          │     │          │     │          │            │
│  │          │     │ 6. Exchange code for tokens            │
│  │          │     │ 7. Get GitHub user profile             │
│  │          │     │ 8. Check if GitHub email matches       │
│  │          │     │    existing user's email               │
│  │          │     │ 9. If match → link accounts            │
│  │          │     │    If no match → prompt user           │
│  │          │     │          │     │          │            │
│  │◀─10. Account linked notification                       │
│  │          │     │          │     │          │            │
│                                                             │
│  Linking Rules:                                             │
│  • Same email address → Auto-link                           │
│  • Different email → User confirmation required             │
│  • Already linked → Show existing link, no duplicate        │
│  • Primary provider cannot be unlinked                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Consequences

### 3.1 Positive Consequences

1. **User choice and flexibility**: Users can authenticate with their preferred identity provider, reducing friction during onboarding. Enterprise users can use their existing SSO (Okta, Azure AD), while individual developers can use social login (Google, GitHub). This increases adoption rates and reduces authentication-related support tickets.

2. **Provider failover**: If one provider experiences an outage, users can fall back to alternative providers. This improves system availability and resilience. For example, if Google OAuth is down, users can still authenticate via GitHub or Microsoft. The provider registry can dynamically disable unavailable providers.

3. **Unified identity management**: The account linking service creates a single user identity across multiple providers. Users can switch between providers seamlessly while maintaining their Phenotype account, preferences, and data. This eliminates the problem of duplicate accounts and fragmented user data.

4. **Centralized configuration**: Provider configuration is managed centrally through the provider registry, eliminating duplicated configuration across services. Secrets (client IDs, client secrets, signing keys) are stored securely and can be rotated without code changes. New providers can be added through configuration without deploying new code.

5. **Consistent error handling**: The provider abstraction normalizes errors across different providers, providing consistent error messages and recovery suggestions to users. Provider-specific error codes are mapped to a unified error taxonomy, simplifying error handling in consuming services.

6. **Compliance flexibility**: Different providers can be configured for different compliance requirements. For example, enterprise SAML providers can be configured for SOC 2 compliance, while social providers can be used for non-sensitive operations. The provider metadata field allows tagging providers with compliance labels.

### 3.2 Negative Consequences

1. **Abstraction leakage**: No abstraction perfectly captures all provider-specific behaviors. Some providers have unique features (Apple's private email relay, GitHub's organization membership, Microsoft's tenant selection) that don't fit neatly into the unified interface. Mitigation: Provider-specific extension points, raw profile access, capability detection.

2. **Increased testing complexity**: Each provider must be tested individually, and the account linking logic requires testing all combinations of provider pairs. Integration tests require mocking multiple providers with different response formats. Mitigation: Provider-specific test fixtures, contract testing, automated provider health checks.

3. **Configuration management overhead**: Managing credentials and configuration for multiple providers increases operational complexity. Each provider has different credential formats, rotation procedures, and expiration policies. Mitigation: Centralized secrets management (Vault, AWS Secrets Manager), automated credential rotation, configuration validation on startup.

4. **Identity resolution complexity**: Determining whether two provider profiles represent the same user is non-trivial. Email matching works for most cases but fails for providers that use email aliasing (Apple's private relay) or don't provide email addresses. Mitigation: Multi-factor identity resolution (email + name + avatar), user confirmation for ambiguous matches, manual account merging tools.

5. **Provider-specific compliance requirements**: Different providers have different data handling requirements and privacy policies. For example, Apple's Sign in with Apple requires specific handling of private email relay addresses, and GDPR requires different consent flows for different providers. Mitigation: Provider-specific compliance handlers, documented data flows, user-facing privacy controls.

6. **Performance overhead**: The provider abstraction adds a layer of indirection that can impact performance. Each provider call goes through the adapter layer, which adds latency. Mitigation: Provider-specific connection pooling, async I/O, caching of provider discovery documents, connection reuse.

---

## 4. Implementation

### 4.1 Provider Registry

```python
"""
AuthKit Provider Registry - Python
Dynamic registration and management of authentication providers
"""

import time
from typing import Optional
from dataclasses import dataclass, field

@dataclass
class ProviderHealthStatus:
    """Health status of a provider."""

    provider_id: str
    is_healthy: bool
    last_check: float = field(default_factory=time.time)
    response_time_ms: Optional[float] = None
    error_count: int = 0
    last_error: Optional[str] = None
    consecutive_failures: int = 0

    @property
    def should_disable(self) -> bool:
        """Check if provider should be auto-disabled."""
        return self.consecutive_failures >= 5

class ProviderRegistry:
    """Registry for managing authentication providers."""

    def __init__(self):
        self._providers: dict[str, AuthProvider] = {}
        self._health_status: dict[str, ProviderHealthStatus] = {}
        self._config_store: dict[str, ProviderConfig] = {}

    def register(self, provider: AuthProvider):
        """Register an authentication provider."""
        self._providers[provider.provider_id] = provider
        self._health_status[provider.provider_id] = ProviderHealthStatus(
            provider_id=provider.provider_id,
            is_healthy=True,
        )
        self._config_store[provider.provider_id] = provider.config

    def unregister(self, provider_id: str):
        """Unregister a provider."""
        self._providers.pop(provider_id, None)
        self._health_status.pop(provider_id, None)
        self._config_store.pop(provider_id, None)

    def get_provider(self, provider_id: str) -> Optional[AuthProvider]:
        """Get a registered provider by ID."""
        provider = self._providers.get(provider_id)
        if provider and not provider.config.enabled:
            return None
        return provider

    def get_healthy_provider(self, provider_id: str) -> Optional[AuthProvider]:
        """Get a provider only if it's healthy."""
        provider = self.get_provider(provider_id)
        if not provider:
            return None

        health = self._health_status.get(provider_id)
        if health and not health.is_healthy:
            return None

        return provider

    def list_providers(self, enabled_only: bool = True) -> list[AuthProvider]:
        """List all registered providers."""
        providers = list(self._providers.values())
        if enabled_only:
            providers = [p for p in providers if p.config.enabled]
        return providers

    def get_provider_types(self) -> list[str]:
        """Get list of available provider types."""
        return list(set(p.provider_type for p in self._providers.values()))

    def record_health(self, provider_id: str, success: bool,
                     response_time_ms: Optional[float] = None,
                     error: Optional[str] = None):
        """Record provider health metrics."""
        if provider_id not in self._health_status:
            self._health_status[provider_id] = ProviderHealthStatus(
                provider_id=provider_id,
                is_healthy=True,
            )

        health = self._health_status[provider_id]
        health.last_check = time.time()
        health.response_time_ms = response_time_ms

        if success:
            health.consecutive_failures = 0
            health.error_count = max(0, health.error_count - 1)
            health.is_healthy = True
        else:
            health.consecutive_failures += 1
            health.error_count += 1
            health.last_error = error
            health.is_healthy = not health.should_disable

    def get_health_report(self) -> dict[str, ProviderHealthStatus]:
        """Get health report for all providers."""
        return dict(self._health_status)
```

### 4.2 Google Provider Implementation

```python
"""
AuthKit Google Provider - Python
Google OAuth2/OIDC provider implementation
"""

import httpx
from typing import Optional

class GoogleProvider(AuthProvider):
    """Google OAuth2/OIDC provider."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self._base_url = "https://accounts.google.com"
        self._token_url = "https://oauth2.googleapis.com/token"
        self._userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"

    async def get_authorization_url(self, state: str,
                                   pkce_challenge: Optional[str] = None,
                                   login_hint: Optional[str] = None) -> str:
        """Generate Google OAuth2 authorization URL."""
        params = {
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self._config.scopes),
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }

        if pkce_challenge:
            params["code_challenge"] = pkce_challenge
            params["code_challenge_method"] = "S256"

        if login_hint:
            params["login_hint"] = login_hint

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self._base_url}/o/oauth2/v2/auth?{query}"

    async def handle_callback(self, code: str, state: str,
                             pkce_verifier: Optional[str] = None) -> tuple:
        """Handle Google OAuth2 callback."""
        async with httpx.AsyncClient() as client:
            data = {
                "code": code,
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "redirect_uri": self._config.redirect_uri,
                "grant_type": "authorization_code",
            }

            if pkce_verifier:
                data["code_verifier"] = pkce_verifier

            response = await client.post(self._token_url, data=data)
            response.raise_for_status()
            tokens = response.json()

        # Get user info
        user_info = await self.get_user_info(tokens["access_token"])

        return user_info, tokens

    async def get_user_info(self, access_token: str) -> UserProfile:
        """Fetch Google user info."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                self._userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            data = response.json()

        return UserProfile(
            provider_id=data["sub"],
            provider_type="google",
            email=data["email"],
            email_verified=data.get("email_verified", False),
            name=data.get("name", ""),
            avatar_url=data.get("picture"),
            locale=data.get("locale"),
            raw_profile=data,
        )

    async def refresh_access_token(self, refresh_token: str) -> dict:
        """Refresh Google access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._token_url,
                data={
                    "refresh_token": refresh_token,
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                    "grant_type": "refresh_token",
                },
            )
            response.raise_for_status()
            return response.json()

    async def revoke_access_token(self, access_token: str) -> bool:
        """Revoke Google access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": access_token},
            )
            return response.status_code == 200
```

### 4.3 Account Linking Service

```python
"""
AuthKit Account Linking Service - Python
Manages linking multiple providers to a single user identity
"""

from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

class LinkStatus(Enum):
    """Account link status."""
    ACTIVE = "active"
    PENDING = "pending"
    REVOKED = "revoked"

@dataclass
class ProviderLink:
    """Link between a user and a provider."""

    user_id: str
    provider_id: str
    provider_type: str
    provider_user_id: str
    email: str
    email_verified: bool
    status: LinkStatus = LinkStatus.ACTIVE
    linked_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    is_primary: bool = False
    metadata: dict = field(default_factory=dict)

class AccountLinkingService:
    """Manages account linking across providers."""

    def __init__(self, user_store, redis_client):
        self._user_store = user_store
        self._redis = redis_client

    async def link_account(self, user_id: str, profile: UserProfile,
                          provider_id: str) -> ProviderLink:
        """Link a provider account to an existing user."""
        # Check if already linked
        existing = await self.get_link(user_id, provider_id)
        if existing:
            raise AccountLinkingError(
                f"Provider {provider_id} already linked to user {user_id}",
                code="ALREADY_LINKED"
            )

        # Check for email conflicts
        conflict = await self.find_by_email(profile.email, provider_id)
        if conflict and conflict.user_id != user_id:
            raise AccountLinkingError(
                f"Email {profile.email} already linked to another user",
                code="EMAIL_CONFLICT"
            )

        # Create link
        link = ProviderLink(
            user_id=user_id,
            provider_id=provider_id,
            provider_type=profile.provider_type,
            provider_user_id=profile.provider_id,
            email=profile.email,
            email_verified=profile.email_verified,
        )

        # Store link
        await self._store_link(link)

        return link

    async def find_by_email(self, email: str,
                           exclude_provider: Optional[str] = None
                           ) -> Optional[ProviderLink]:
        """Find a provider link by email address."""
        # Implementation would query the link store
        # For now, return None
        return None

    async def get_link(self, user_id: str,
                      provider_id: str) -> Optional[ProviderLink]:
        """Get a specific provider link."""
        # Implementation would query the link store
        return None

    async def get_user_links(self, user_id: str) -> list[ProviderLink]:
        """Get all provider links for a user."""
        # Implementation would query the link store
        return []

    async def unlink_account(self, user_id: str, provider_id: str):
        """Unlink a provider account."""
        link = await self.get_link(user_id, provider_id)
        if not link:
            raise AccountLinkingError("Link not found", code="NOT_FOUND")

        if link.is_primary:
            raise AccountLinkingError(
                "Cannot unlink primary provider",
                code="PRIMARY_PROVIDER"
            )

        link.status = LinkStatus.REVOKED
        await self._store_link(link)

    async def resolve_identity(self, profile: UserProfile,
                              provider_id: str) -> Optional[str]:
        """
        Resolve a provider profile to a user ID.
        Returns existing user ID if found, None if new user.
        """
        # Check if provider is already linked
        link = await self.get_link_by_provider(provider_id, profile.provider_id)
        if link:
            return link.user_id

        # Check if email matches existing user
        link = await self.find_by_email(profile.email, provider_id)
        if link:
            return link.user_id

        return None

    async def get_link_by_provider(self, provider_id: str,
                                  provider_user_id: str) -> Optional[ProviderLink]:
        """Find a link by provider ID and provider user ID."""
        return None

    async def _store_link(self, link: ProviderLink):
        """Store a provider link."""
        # Implementation would store in database/Redis
        pass

class AccountLinkingError(Exception):
    """Account linking error."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code
```

```go
// AuthKit Provider Registry - Go
// Dynamic registration and management of authentication providers

package authkit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	ProviderID() string
	ProviderType() string
	GetAuthorizationURL(ctx context.Context, state string,
		opts AuthorizationURLOpts) (string, error)
	HandleCallback(ctx context.Context, code, state string,
		opts CallbackOpts) (*UserProfile, *TokenResponse, error)
	GetUserInfo(ctx context.Context, accessToken string) (*UserProfile, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
	RevokeAccessToken(ctx context.Context, accessToken string) error
	SupportsCapability(capability ProviderCapability) bool
}

// ProviderRegistry manages authentication providers
type ProviderRegistry struct {
	mu            sync.RWMutex
	providers     map[string]AuthProvider
	healthStatus  map[string]*ProviderHealth
	configs       map[string]*ProviderConfig
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers:    make(map[string]AuthProvider),
		healthStatus: make(map[string]*ProviderHealth),
		configs:      make(map[string]*ProviderConfig),
	}
}

// Register adds a provider to the registry
func (r *ProviderRegistry) Register(provider AuthProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[provider.ProviderID()] = provider
	r.healthStatus[provider.ProviderID()] = &ProviderHealth{
		ProviderID: provider.ProviderID(),
		IsHealthy:  true,
	}
}

// GetProvider retrieves a provider by ID
func (r *ProviderRegistry) GetProvider(providerID string) AuthProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.providers[providerID]
}

// ListProviders returns all registered providers
func (r *ProviderRegistry) ListProviders() []AuthProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]AuthProvider, 0, len(r.providers))
	for _, p := range r.providers {
		providers = append(providers, p)
	}
	return providers
}

// RecordHealth records health metrics for a provider
func (r *ProviderRegistry) RecordHealth(providerID string, success bool,
	responseTime time.Duration, err error) {

	r.mu.Lock()
	defer r.mu.Unlock()

	health, exists := r.healthStatus[providerID]
	if !exists {
		health = &ProviderHealth{ProviderID: providerID, IsHealthy: true}
		r.healthStatus[providerID] = health
	}

	health.LastCheck = time.Now()
	health.ResponseTime = responseTime

	if success {
		health.ConsecutiveFailures = 0
		health.IsHealthy = true
	} else {
		health.ConsecutiveFailures++
		health.ErrorCount++
		health.LastError = err
		health.IsHealthy = health.ConsecutiveFailures < 5
	}
}

// ProviderHealth tracks provider health status
type ProviderHealth struct {
	ProviderID          string
	IsHealthy           bool
	LastCheck           time.Time
	ResponseTime        time.Duration
	ErrorCount          int
	LastError           error
	ConsecutiveFailures int
}

// AuthorizationURLOpts contains options for generating authorization URLs
type AuthorizationURLOpts struct {
	PKCEChallenge string
	LoginHint     string
	Prompt        string
	AccessType    string
}

// CallbackOpts contains options for handling OAuth callbacks
type CallbackOpts struct {
	PKCEVerifier string
	ExpectedState string
}

// UserProfile represents a normalized user profile
type UserProfile struct {
	ProviderID    string
	ProviderType  string
	Email         string
	EmailVerified bool
	Name          string
	AvatarURL     string
	Locale        string
	RawProfile    map[string]interface{}
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	IDToken      string
	Scope        string
}

// ProviderCapability represents a provider capability
type ProviderCapability string

const (
	CapabilityAuthorizationCode ProviderCapability = "authorization_code"
	CapabilityClientCredentials ProviderCapability = "client_credentials"
	CapabilityRefreshToken      ProviderCapability = "refresh_token"
	CapabilityRevokeToken       ProviderCapability = "revoke_token"
	CapabilityPKCE              ProviderCapability = "pkce"
)

// ProviderConfig holds provider configuration
type ProviderConfig struct {
	ProviderID             string
	ProviderType           string
	ClientID               string
	ClientSecret           string
	RedirectURI            string
	Scopes                 []string
	AuthorizationEndpoint  string
	TokenEndpoint          string
	UserInfoEndpoint       string
	JWKSURI                string
	Capabilities           []ProviderCapability
	Enabled                bool
	Metadata               map[string]interface{}
}

// NewGoogleProvider creates a Google OAuth2 provider
func NewGoogleProvider(config *ProviderConfig) AuthProvider {
	return &GoogleProvider{config: config}
}

// GoogleProvider implements AuthProvider for Google OAuth2
type GoogleProvider struct {
	config *ProviderConfig
}

func (p *GoogleProvider) ProviderID() string { return p.config.ProviderID }
func (p *GoogleProvider) ProviderType() string { return p.config.ProviderType }

func (p *GoogleProvider) GetAuthorizationURL(ctx context.Context, state string,
	opts AuthorizationURLOpts) (string, error) {

	return fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?"+
			"client_id=%s&redirect_uri=%s&response_type=code&"+
			"scope=%s&state=%s&access_type=offline&prompt=consent",
		p.config.ClientID,
		p.config.RedirectURI,
		"openid+profile+email",
		state,
	), nil
}

func (p *GoogleProvider) HandleCallback(ctx context.Context, code, state string,
	opts CallbackOpts) (*UserProfile, *TokenResponse, error) {
	// Implementation would exchange code for tokens and fetch user info
	return nil, nil, fmt.Errorf("not implemented")
}

func (p *GoogleProvider) GetUserInfo(ctx context.Context,
	accessToken string) (*UserProfile, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *GoogleProvider) RefreshAccessToken(ctx context.Context,
	refreshToken string) (*TokenResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *GoogleProvider) RevokeAccessToken(ctx context.Context,
	accessToken string) error {
	return fmt.Errorf("not implemented")
}

func (p *GoogleProvider) SupportsCapability(capability ProviderCapability) bool {
	for _, c := range p.config.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}
```

---

## 5. Cross-References

| Document | Relationship | Description |
|----------|-------------|-------------|
| PHENOTYPE_AUTHKIT_ADR_001 | Depends on | Authentication Flow Design uses providers for authentication |
| PHENOTYPE_AUTHKIT_ADR_002 | Related | Session Management Strategy handles sessions from all providers |
| PHENOTYPE_AUTHKIT_SOTA_001 | Informed by | SOTA research on multi-provider authentication patterns |
| docs/SPEC.md | Specifies | AuthKit Specification defines provider architecture |
| ../python/pheno-credentials/ | Integrates with | Existing OAuth provider implementations |

---

## 6. Appendix

### 6.1 Provider Comparison Matrix

```
┌─────────────────────────────────────────────────────────────┐
│              Provider Comparison Matrix                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Feature              │ Google │ GitHub │ Microsoft │ Apple │
│  ─────────────────────┼────────┼────────┼───────────┼───────│
│  Protocol             │ OIDC   │ OAuth2 │ OIDC      │ OIDC  │
│  PKCE Support         │ Yes    │ Yes    │ Yes       │ Yes   │
│  Refresh Tokens       │ Yes    │ Yes    │ Yes       │ No    │
│  Token Revocation     │ Yes    │ No     │ Yes       │ Yes   │
│  Email Verification   │ Yes    │ Yes    │ Yes       │ Via   │
│                       │        │        │           │ relay │
│  User Info Endpoint   │ Yes    │ Yes    │ Yes       │ No    │
│  ID Token Claims      │ Rich   │ None   │ Rich      │ Basic │
│  Private Email Relay  │ No     │ No     │ No        │ Yes   │
│  Organization Data    │ No     │ Yes    │ Yes       │ No    │
│  Enterprise SSO       │ Yes    │ Yes    │ Yes       │ No    │
│  Rate Limits          │ High   │ Medium │ High      │ High  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Provider Onboarding Checklist

- [ ] Register application with provider (get client_id, client_secret)
- [ ] Configure redirect URIs in provider console
- [ ] Define required scopes for the provider
- [ ] Implement provider adapter (extend AuthProvider)
- [ ] Add provider configuration to registry
- [ ] Test authorization flow end-to-end
- [ ] Test token exchange and refresh
- [ ] Test user info extraction and normalization
- [ ] Test error handling and retry logic
- [ ] Configure health monitoring
- [ ] Document provider-specific quirks and limitations
- [ ] Add provider to integration test suite

### 6.3 Security Checklist

- [x] Provider client secrets stored securely (not in code)
- [x] State parameter validated for all providers
- [x] PKCE enforced for all OAuth2 providers
- [x] Redirect URIs validated against allowlist
- [x] Provider discovery documents cached with TTL
- [x] Provider health monitoring with auto-disable
- [x] Account linking requires email verification
- [x ] Primary provider cannot be unlinked
- [x] Provider-specific rate limiting implemented
- [x] Audit logging for all provider operations

---

*ADR Version: 1.0*
*Status: Proposed*
*Decision Date: 2026-04-03*
*Next Review: Pending acceptance*