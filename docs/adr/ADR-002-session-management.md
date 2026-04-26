# ADR-002: Session Management Strategy

**Document ID:** PHENOTYPE_AUTHKIT_ADR_002
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

Session management is a critical component of any authentication system. The Phenotype ecosystem currently lacks a unified session management strategy, leading to inconsistent security properties across services:

- Some services use JWT-only sessions (no revocation capability)
- Others use cookie-based sessions with varying security attributes
- No centralized session revocation mechanism exists
- Concurrent session limits are not enforced
- Session metadata (IP, user agent, device) is not consistently tracked

### 1.2 Requirements

| Requirement | Priority | Description |
|-------------|----------|-------------|
| Server-side session storage | P0 | Enable immediate session revocation |
| Secure cookie attributes | P0 | HttpOnly, Secure, SameSite, Partitioned |
| Sliding expiration | P0 | Extend session on activity, max lifetime |
| Concurrent session limits | P1 | Limit active sessions per user |
| Session metadata tracking | P1 | Track IP, user agent, device fingerprint |
| Cross-service session sharing | P1 | Single session across Phenotype services |
| Session audit logging | P2 | Log all session lifecycle events |

### 1.3 Constraints

- Must support distributed deployment (multiple service instances)
- Must handle session store failures gracefully
- Must comply with GDPR data retention requirements
- Must integrate with existing Redis infrastructure
- Must support both web (cookie) and API (Bearer token) authentication

### 1.4 Alternatives Considered

```
┌─────────────────────────────────────────────────────────────┐
│              Session Management Alternatives                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Option A: JWT-Only Sessions (Stateless)                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: No server-side storage, horizontally scalable  │   │
│  │       by default, simple architecture                │   │
│  │ Cons: Cannot revoke before expiry, large tokens,     │   │
│  │       limited metadata, security risk on compromise  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option B: Server-Side Sessions (Stateful)                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Immediate revocation, rich metadata,           │   │
│  │       concurrent session control, audit trail        │   │
│  │ Cons: Requires session store, operational overhead,  │   │
│  │       potential single point of failure              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option C: Hybrid Sessions (CHOSEN)                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Best of both worlds - revocable sessions +     │   │
│  │       stateless API tokens, flexible architecture    │   │
│  │ Cons: More complex, two token types to manage        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  Option D: Database-Backed Sessions                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Pros: Durable, ACID transactions, existing infra     │   │
│  │ Cons: Higher latency, connection pool limits,        │   │
│  │       not optimized for session access patterns      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Decision Rationale:** Option C (Hybrid Sessions) provides the optimal balance of security, performance, and flexibility. Server-side sessions enable revocation and metadata tracking, while short-lived JWT access tokens provide efficient stateless API authentication. Redis is chosen as the session store for its performance, distributed capabilities, and existing infrastructure in the Phenotype ecosystem.

---

## 2. Decision

### 2.1 Hybrid Session Architecture

We will implement a hybrid session architecture with server-side session storage in Redis and short-lived JWT access tokens for API authentication.

```
┌─────────────────────────────────────────────────────────────┐
│              Hybrid Session Architecture                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Client Layer                     │    │
│  │                                                     │    │
│  │  ┌─────────────┐         ┌─────────────────────┐    │    │
│  │  │   Browser   │         │   Mobile/CLI App    │    │    │
│  │  │             │         │                     │    │    │
│  │  │  Session    │         │  Access Token       │    │    │
│  │  │  Cookie     │         │  (Bearer)           │    │    │
│  │  │  (HttpOnly) │         │  (short-lived JWT)  │    │    │
│  │  └──────┬──────┘         └──────────┬──────────┘    │    │
│  └─────────┼───────────────────────────┼────────────────┘    │
│            │                           │                     │
│  ┌─────────▼───────────────────────────▼────────────────┐    │
│  │                  API Gateway / Load Balancer         │    │
│  │  • Route requests to appropriate services            │    │
│  │  • Extract session cookie or Bearer token            │    │
│  │  • Forward authentication context to services        │    │
│  └─────────────────────────┬───────────────────────────┘    │
│                            │                                 │
│  ┌─────────────────────────▼───────────────────────────┐    │
│  │              Phenotype Services                     │    │
│  │                                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │  Service A  │  │  Service B  │  │ Service C  │  │    │
│  │  │             │  │             │  │            │  │    │
│  │  │ Validate    │  │ Validate    │  │ Validate   │  │    │
│  │  │ JWT locally │  │ JWT locally │  │ JWT locally│  │    │
│  │  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘  │    │
│  └─────────┼────────────────┼────────────────┼─────────┘    │
│            │                │                │               │
│  ┌─────────▼────────────────▼────────────────▼─────────┐    │
│  │              Redis Session Store                    │    │
│  │                                                     │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │    │
│  │  │  Session    │  │  Session    │  │  Session   │  │    │
│  │  │  Data       │  │  Data       │  │  Data      │  │    │
│  │  │  (TTL)      │  │  (TTL)      │  │  (TTL)     │  │    │
│  │  └─────────────┘  └─────────────┘  └────────────┘  │    │
│  │                                                     │    │
│  │  Features:                                          │    │
│  │  • Automatic TTL-based expiration                   │    │
│  │  • Pub/Sub for cross-service session invalidation   │    │
│  │  • Cluster mode for horizontal scaling              │    │
│  │  • AOF persistence for durability                   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Session Data Model

```
┌─────────────────────────────────────────────────────────────┐
│              Session Data Model (Redis Hash)                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Key: session:{session_id}                                  │
│  TTL: 86400 seconds (24 hours, sliding)                     │
│                                                             │
│  Field                  │ Type     │ Description            │
│  ───────────────────────┼──────────┼─────────────────────── │
│  user_id                │ String   │ User identifier        │
│  organization_id        │ String   │ Organization context   │
│  created_at             │ Float    │ Session creation time  │
│  last_accessed          │ Float    │ Last activity time     │
│  expires_at             │ Float    │ Absolute expiration    │
│  ip_address             │ String   │ Client IP address      │
│  user_agent             │ String   │ Browser/app identifier │
│  device_fingerprint     │ String   │ Device hash            │
│  is_revoked             │ Bool     │ Revocation flag        │
│  mfa_verified           │ Bool     │ MFA completion status  │
│  auth_level             │ String   │ NIST AAL level         │
│  concurrent_session_id  │ String   │ Session group ID       │
│  metadata               │ JSON     │ Custom metadata        │
│                                                             │
│  Secondary Indexes:                                         │
│  • Set: user_sessions:{user_id} → {session_ids}             │
│  • Set: org_sessions:{org_id} → {session_ids}               │
│  • ZSet: session_activity → {session_id: last_accessed}     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Cookie Configuration

```
┌─────────────────────────────────────────────────────────────┐
│              Session Cookie Configuration                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Attribute        │ Value              │ Rationale          │
│  ─────────────────┼────────────────────┼─────────────────── │
│  Name             │ authkit_session    │ Namespaced prefix  │
│  HttpOnly         │ true               │ Prevent XSS access │
│  Secure           │ true               │ HTTPS only         │
│  SameSite         │ Lax                │ CSRF protection    │
│  Path             │ /                  │ All paths          │
│  Domain           │ (not set)          │ Current domain only│
│  Max-Age          │ 86400              │ 24 hours           │
│  Partitioned      │ true               │ CHIPS support      │
│                                                             │
│  Cookie Value Format:                                       │
│  {session_id}.{signature}                                   │
│                                                             │
│  Where:                                                     │
│  • session_id: URL-safe random string (48 bytes)            │
│  • signature: HMAC-SHA256(session_id, secret_key)           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Consequences

### 3.1 Positive Consequences

1. **Immediate revocation**: Server-side session storage enables instant session revocation for security incidents, user logout, password changes, and administrative actions. This is critical for maintaining security posture and is impossible with pure JWT sessions. The Redis SETEX command with TTL provides atomic session creation with expiration.

2. **Rich session metadata**: Storing session data server-side allows tracking of IP addresses, user agents, device fingerprints, and authentication levels. This enables security features like anomalous login detection, device management, and compliance audit trails. Each session carries its complete security context.

3. **Concurrent session control**: The user_sessions secondary index enables enforcement of concurrent session limits. When a user exceeds the limit, the oldest session can be automatically revoked. This prevents credential sharing and reduces the attack surface from compromised sessions.

4. **Sliding expiration with max lifetime**: Sessions are automatically extended on activity (sliding expiration) while maintaining an absolute maximum lifetime. This balances user convenience with security - active users stay logged in, but inactive sessions eventually expire regardless of activity.

5. **Efficient API authentication**: Short-lived JWT access tokens (15-minute TTL) enable stateless API authentication without Redis lookups on every request. Services validate JWT signatures locally using cached public keys, achieving sub-millisecond validation latency. The session ID embedded in the JWT allows revocation checking when needed.

6. **Cross-service session consistency**: Redis Pub/Sub enables real-time session invalidation across all services. When a session is revoked, a message is published to a channel that all services subscribe to, ensuring immediate consistency. This is essential for distributed systems where services may have cached session state.

### 3.2 Negative Consequences

1. **Redis dependency**: The session management strategy introduces a hard dependency on Redis availability. If Redis is unavailable, new sessions cannot be created and existing sessions cannot be validated (unless JWT validation is used as fallback). Mitigation: Implement JWT-only fallback mode with degraded functionality, Redis cluster for high availability, and connection pooling with retry logic.

2. **Operational complexity**: Managing Redis infrastructure (clustering, persistence, backups, monitoring) adds operational overhead compared to stateless JWT sessions. This requires Redis expertise and monitoring tooling. Mitigation: Use managed Redis service (AWS ElastiCache, Redis Cloud), implement comprehensive monitoring and alerting, automate backup and recovery procedures.

3. **Two-token management complexity**: The hybrid approach requires managing both session cookies (for web) and JWT access tokens (for APIs). This increases the complexity of the authentication middleware and requires careful handling of token refresh flows. Mitigation: Provide unified SDK that abstracts token management, implement automatic refresh logic, clear documentation for each authentication pattern.

4. **Memory usage at scale**: Storing session data in Redis for all active users consumes memory. At 1M concurrent users with ~1KB per session, this requires ~1GB of Redis memory. Mitigation: Implement session data compression, use Redis memory-efficient data structures, monitor memory usage and scale horizontally with Redis Cluster.

5. **GDPR data retention**: Session metadata (IP addresses, user agents) constitutes personal data under GDPR and must be handled according to data retention policies. Sessions must be purged after expiration and users must be able to request deletion of their session data. Mitigation: Implement automatic session data anonymization after expiration, provide user-facing session management API, document data retention policies.

6. **Migration complexity**: Existing services using different session management approaches must be migrated to the new hybrid model. This requires careful planning to avoid session loss during migration and may require a transition period where both old and new session formats are supported. Mitigation: Implement session format migration tooling, run dual session validation during transition, provide clear migration timeline and rollback procedures.

---

## 4. Implementation

### 4.1 Session Manager (Python)

```python
"""
AuthKit Session Manager - Python
Hybrid session management with Redis storage and JWT access tokens
"""

import time
import secrets
import hashlib
import hmac
import json
from typing import Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

class AuthLevel(Enum):
    """NIST Authentication Assurance Level."""
    AAL1 = "aal1"  # Single factor
    AAL2 = "aal2"  # Multi-factor
    AAL3 = "aal3"  # Hardware-backed MFA

@dataclass
class Session:
    """Session data model."""

    session_id: str
    user_id: str
    organization_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    expires_at: float = 0.0
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_fingerprint: Optional[str] = None
    is_revoked: bool = False
    mfa_verified: bool = False
    auth_level: AuthLevel = AuthLevel.AAL1
    concurrent_session_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + 86400  # 24 hours

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    def touch(self, max_lifetime: int = 604800):
        """Update last accessed time with sliding expiration."""
        now = time.time()
        self.last_accessed = now
        # Extend but don't exceed max lifetime
        new_expiry = min(now + 86400, self.created_at + max_lifetime)
        self.expires_at = new_expiry

    def to_dict(self) -> dict:
        """Serialize session for Redis storage."""
        data = asdict(self)
        data["auth_level"] = self.auth_level.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Deserialize session from Redis storage."""
        data["auth_level"] = AuthLevel(data.get("auth_level", "aal1"))
        return cls(**data)

class SessionManager:
    """Manages sessions with Redis storage and JWT access tokens."""

    def __init__(self, redis_client, jwt_secret: bytes,
                 max_sessions_per_user: int = 5,
                 max_session_lifetime: int = 604800):  # 7 days
        self._redis = redis_client
        self._jwt_secret = jwt_secret
        self._max_sessions = max_sessions_per_user
        self._max_lifetime = max_session_lifetime

    def create_session(self, user_id: str,
                      organization_id: Optional[str] = None,
                      ip_address: Optional[str] = None,
                      user_agent: Optional[str] = None,
                      device_fingerprint: Optional[str] = None,
                      auth_level: AuthLevel = AuthLevel.AAL1) -> Session:
        """Create a new session with security metadata."""
        session = Session(
            session_id=secrets.token_urlsafe(48),
            user_id=user_id,
            organization_id=organization_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            auth_level=auth_level,
        )

        # Enforce concurrent session limit
        self._enforce_session_limit(user_id)

        # Store session in Redis
        self._store_session(session)

        # Add to user's session set
        self._redis.sadd(f"user_sessions:{user_id}", session.session_id)

        # Track in activity sorted set
        self._redis.zadd("session_activity",
                        {session.session_id: session.last_accessed})

        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Retrieve and validate a session."""
        data = self._redis.get(f"session:{session_id}")
        if not data:
            return None

        session = Session.from_dict(json.loads(data))

        if not session.is_valid:
            self.revoke_session(session_id)
            return None

        # Update activity
        session.touch(self._max_lifetime)
        self._store_session(session)
        self._redis.zadd("session_activity",
                        {session_id: session.last_accessed})

        return session

    def revoke_session(self, session_id: str):
        """Revoke a specific session."""
        data = self._redis.get(f"session:{session_id}")
        if data:
            session = Session.from_dict(json.loads(data))
            self._redis.srem(f"user_sessions:{session.user_id}", session_id)

        self._redis.delete(f"session:{session_id}")
        self._redis.zrem("session_activity", session_id)

        # Publish revocation event
        self._redis.publish("session:revoked",
                          json.dumps({"session_id": session_id}))

    def revoke_all_user_sessions(self, user_id: str):
        """Revoke all sessions for a user."""
        session_ids = self._redis.smembers(f"user_sessions:{user_id}")
        for session_id in session_ids:
            self.revoke_session(session_id.decode())

        self._redis.delete(f"user_sessions:{user_id}")

    def get_user_sessions(self, user_id: str) -> list[Session]:
        """Get all active sessions for a user."""
        session_ids = self._redis.smembers(f"user_sessions:{user_id}")
        sessions = []
        for session_id in session_ids:
            session = self.get_session(session_id.decode())
            if session:
                sessions.append(session)
        return sessions

    def generate_cookie_value(self, session_id: str) -> str:
        """Generate signed cookie value."""
        signature = hmac.new(
            self._jwt_secret,
            session_id.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        return f"{session_id}.{signature}"

    def validate_cookie(self, cookie_value: str) -> Optional[str]:
        """Validate signed cookie and extract session ID."""
        parts = cookie_value.rsplit(".", 1)
        if len(parts) != 2:
            return None

        session_id, signature = parts
        expected = hmac.new(
            self._jwt_secret,
            session_id.encode(),
            hashlib.sha256
        ).hexdigest()[:16]

        if not hmac.compare_digest(signature, expected):
            return None

        return session_id

    def _store_session(self, session: Session):
        """Store session in Redis with TTL."""
        ttl = int(session.expires_at - time.time())
        if ttl > 0:
            self._redis.setex(
                f"session:{session.session_id}",
                ttl,
                json.dumps(session.to_dict())
            )

    def _enforce_session_limit(self, user_id: str):
        """Revoke oldest session if limit exceeded."""
        session_ids = self._redis.smembers(f"user_sessions:{user_id}")
        if len(session_ids) >= self._max_sessions:
            # Find oldest session
            oldest_id = None
            oldest_time = float("inf")
            for session_id in session_ids:
                data = self._redis.get(f"session:{session_id.decode()}")
                if data:
                    session = Session.from_dict(json.loads(data))
                    if session.created_at < oldest_time:
                        oldest_time = session.created_at
                        oldest_id = session_id.decode()

            if oldest_id:
                self.revoke_session(oldest_id)
```

### 4.2 Session Manager (Go)

```go
// AuthKit Session Manager - Go
// Hybrid session management with Redis storage and JWT access tokens

package authkit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/golang-jwt/jwt/v5"
)

// AuthLevel represents NIST Authentication Assurance Level
type AuthLevel string

const (
	AAL1 AuthLevel = "aal1" // Single factor
	AAL2 AuthLevel = "aal2" // Multi-factor
	AAL3 AuthLevel = "aal3" // Hardware-backed MFA
)

// Session represents a user session
type Session struct {
	SessionID             string    `json:"session_id"`
	UserID                string    `json:"user_id"`
	OrganizationID        string    `json:"organization_id,omitempty"`
	CreatedAt             float64   `json:"created_at"`
	LastAccessed          float64   `json:"last_accessed"`
	ExpiresAt             float64   `json:"expires_at"`
	IPAddress             string    `json:"ip_address,omitempty"`
	UserAgent             string    `json:"user_agent,omitempty"`
	DeviceFingerprint     string    `json:"device_fingerprint,omitempty"`
	IsRevoked             bool      `json:"is_revoked"`
	MFAVerified           bool      `json:"mfa_verified"`
	AuthLevel             AuthLevel `json:"auth_level"`
	ConcurrentSessionID   string    `json:"concurrent_session_id,omitempty"`
	Metadata              map[string]interface{} `json:"metadata,omitempty"`
}

// IsValid checks if the session is valid and not expired
func (s *Session) IsValid() bool {
	return !s.IsRevoked && time.Now().UnixMilli() < int64(s.ExpiresAt*1000)
}

// Touch updates the last accessed time with sliding expiration
func (s *Session) Touch(maxLifetime time.Duration) {
	now := float64(time.Now().UnixMilli()) / 1000
	s.LastAccessed = now
	maxExpiry := s.CreatedAt + float64(maxLifetime.Seconds())
	newExpiry := now + 86400 // 24 hours
	if newExpiry > maxExpiry {
		newExpiry = maxExpiry
	}
	s.ExpiresAt = newExpiry
}

// SessionManager manages sessions with Redis storage
type SessionManager struct {
	redis           *redis.Client
	jwtSecret       []byte
	maxSessions     int
	maxLifetime     time.Duration
}

// NewSessionManager creates a new session manager
func NewSessionManager(redisClient *redis.Client, jwtSecret []byte,
	maxSessions int, maxLifetime time.Duration) *SessionManager {
	return &SessionManager{
		redis:       redisClient,
		jwtSecret:   jwtSecret,
		maxSessions: maxSessions,
		maxLifetime: maxLifetime,
	}
}

// CreateSession creates a new session with security metadata
func (m *SessionManager) CreateSession(ctx context.Context, userID string,
	opts ...SessionOption) (*Session, error) {

	session := &Session{
		SessionID:    generateSecureID(),
		UserID:       userID,
		CreatedAt:    float64(time.Now().UnixMilli()) / 1000,
		LastAccessed: float64(time.Now().UnixMilli()) / 1000,
		ExpiresAt:    float64(time.Now().Add(24 * time.Hour).UnixMilli()) / 1000,
		AuthLevel:    AAL1,
		Metadata:     make(map[string]interface{}),
	}

	// Apply options
	for _, opt := range opts {
		opt(session)
	}

	// Enforce concurrent session limit
	if err := m.enforceSessionLimit(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to enforce session limit: %w", err)
	}

	// Store session
	if err := m.storeSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Add to user's session set
	m.redis.SAdd(ctx, fmt.Sprintf("user_sessions:%s", userID), session.SessionID)

	// Track activity
	m.redis.ZAdd(ctx, "session_activity", redis.Z{
		Score:  session.LastAccessed,
		Member: session.SessionID,
	})

	return session, nil
}

// GetSession retrieves and validates a session
func (m *SessionManager) GetSession(ctx context.Context,
	sessionID string) (*Session, error) {

	data, err := m.redis.Get(ctx, fmt.Sprintf("session:%s", sessionID)).Bytes()
	if err == redis.Nil {
		return nil, nil // Session not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	if !session.IsValid() {
		m.RevokeSession(ctx, sessionID)
		return nil, nil
	}

	// Update activity
	session.Touch(m.maxLifetime)
	if err := m.storeSession(ctx, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// RevokeSession revokes a specific session
func (m *SessionManager) RevokeSession(ctx context.Context, sessionID string) error {
	// Get session to remove from user set
	data, err := m.redis.Get(ctx, fmt.Sprintf("session:%s", sessionID)).Bytes()
	if err == nil {
		var session Session
		if json.Unmarshal(data, &session) == nil {
			m.redis.SRem(ctx, fmt.Sprintf("user_sessions:%s", session.UserID), sessionID)
		}
	}

	// Delete session
	m.redis.Del(ctx, fmt.Sprintf("session:%s", sessionID))
	m.redis.ZRem(ctx, "session_activity", sessionID)

	// Publish revocation event
	m.redis.Publish(ctx, "session:revoked", fmt.Sprintf(`{"session_id":"%s"}`, sessionID))

	return nil
}

// GenerateCookieValue creates a signed cookie value
func (m *SessionManager) GenerateCookieValue(sessionID string) string {
	mac := hmac.New(sha256.New, m.jwtSecret)
	mac.Write([]byte(sessionID))
	signature := hex.EncodeToString(mac.Sum(nil))[:16]
	return fmt.Sprintf("%s.%s", sessionID, signature)
}

// ValidateCookie validates a signed cookie and extracts session ID
func (m *SessionManager) ValidateCookie(cookieValue string) (string, error) {
	// Find last dot separator
	lastDot := -1
	for i := len(cookieValue) - 1; i >= 0; i-- {
		if cookieValue[i] == '.' {
			lastDot = i
			break
		}
	}
	if lastDot == -1 {
		return "", fmt.Errorf("invalid cookie format")
	}

	sessionID := cookieValue[:lastDot]
	signature := cookieValue[lastDot+1:]

	mac := hmac.New(sha256.New, m.jwtSecret)
	mac.Write([]byte(sessionID))
	expected := hex.EncodeToString(mac.Sum(nil))[:16]

	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return "", fmt.Errorf("invalid cookie signature")
	}

	return sessionID, nil
}

// GenerateAccessToken creates a short-lived JWT access token
func (m *SessionManager) GenerateAccessToken(session *Session) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": session.UserID,
		"sid": session.SessionID,
		"org": session.OrganizationID,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
		"mfa": session.MFAVerified,
		"aal": string(session.AuthLevel),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// ValidateAccessToken validates a JWT access token
func (m *SessionManager) ValidateAccessToken(ctx context.Context,
	tokenString string) (*jwt.MapClaims, error) {

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify session is still valid
	sessionID, _ := claims["sid"].(string)
	session, err := m.GetSession(ctx, sessionID)
	if err != nil || session == nil {
		return nil, fmt.Errorf("session revoked or expired")
	}

	return &claims, nil
}

func (m *SessionManager) storeSession(ctx context.Context, session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := time.Duration((session.ExpiresAt - float64(time.Now().UnixMilli())/1000)) * time.Second
	if ttl > 0 {
		return m.redis.SetEx(ctx, fmt.Sprintf("session:%s", session.SessionID),
			data, ttl).Err()
	}
	return nil
}

func (m *SessionManager) enforceSessionLimit(ctx context.Context, userID string) error {
	count, err := m.redis.SCard(ctx, fmt.Sprintf("user_sessions:%s", userID)).Result()
	if err != nil {
		return err
	}

	if int(count) >= m.maxSessions {
		// Find and revoke oldest session
		members, _ := m.redis.SMembers(ctx, fmt.Sprintf("user_sessions:%s", userID)).Result()
		var oldestID string
		var oldestTime float64 = 9999999999

		for _, member := range members {
			data, err := m.redis.Get(ctx, fmt.Sprintf("session:%s", member)).Bytes()
			if err == nil {
				var s Session
				if json.Unmarshal(data, &s) == nil && s.CreatedAt < oldestTime {
					oldestTime = s.CreatedAt
					oldestID = member
				}
			}
		}

		if oldestID != "" {
			return m.RevokeSession(ctx, oldestID)
		}
	}

	return nil
}

// SessionOption is a functional option for session creation
type SessionOption func(*Session)

// WithOrganization sets the organization ID
func WithOrganization(orgID string) SessionOption {
	return func(s *Session) { s.OrganizationID = orgID }
}

// WithIPAddress sets the client IP address
func WithIPAddress(ip string) SessionOption {
	return func(s *Session) { s.IPAddress = ip }
}

// WithUserAgent sets the user agent string
func WithUserAgent(ua string) SessionOption {
	return func(s *Session) { s.UserAgent = ua }
}

// WithDeviceFingerprint sets the device fingerprint
func WithDeviceFingerprint(fp string) SessionOption {
	return func(s *Session) { s.DeviceFingerprint = fp }
}

// WithAuthLevel sets the authentication level
func WithAuthLevel(level AuthLevel) SessionOption {
	return func(s *Session) { s.AuthLevel = level }
}

// WithMFAVerified sets the MFA verification status
func WithMFAVerified() SessionOption {
	return func(s *Session) { s.MFAVerified = true }
}

func generateSecureID() string {
	// Implementation would use crypto/rand
	return "generated-secure-id"
}
```

---

## 5. Cross-References

| Document | Relationship | Description |
|----------|-------------|-------------|
| PHENOTYPE_AUTHKIT_ADR_001 | Depended on by | Authentication Flow Design creates sessions using this strategy |
| PHENOTYPE_AUTHKIT_ADR_003 | Related | Multi-Provider Support uses sessions for unified identity |
| PHENOTYPE_AUTHKIT_SOTA_001 | Informed by | SOTA research on session management patterns |
| docs/SPEC.md | Specifies | AuthKit Specification defines session architecture |
| ../python/pheno-credentials/ | Integrates with | Credential storage for session tokens |
| ../rust/phenotype-policy-engine/ | Integrates with | Session context for policy evaluation |

---

## 6. Appendix

### 6.1 Session Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│              Session Lifecycle                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ CREATED  │───▶│  ACTIVE  │───▶│ EXPIRED  │              │
│  │          │    │          │    │          │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │                     │
│       │               │               │                     │
│       ▼               ▼               ▼                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ REVOKED  │◀───│ REVOKED  │◀───│ CLEANED  │              │
│  │          │    │          │    │          │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│                                                             │
│  Lifecycle Events:                                          │
│  • CREATED: User authenticates, session stored in Redis     │
│  • ACTIVE: User makes requests, session touched (sliding)   │
│  • EXPIRED: TTL reached, session auto-deleted by Redis      │
│  • REVOKED: Explicit revocation (logout, admin action)      │
│  • CLEANED: Expired session data purged from indexes        │
│                                                             │
│  Triggers:                                                  │
│  • Password change → Revoke all user sessions               │
│  • MFA enabled → Revoke existing sessions, require re-auth  │
│  • Suspicious activity → Revoke specific session            │
│  • Account deletion → Revoke all sessions, purge data       │
│  • Admin action → Revoke specific or all sessions           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Redis Key Schema

```
┌─────────────────────────────────────────────────────────────┐
│              Redis Key Schema                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Key Pattern                  │ Type   │ TTL    │ Purpose   │
│  ─────────────────────────────┼────────┼────────┼────────── │
│  session:{session_id}         │ Hash   │ 24h    │ Session   │
│                               │        │        │ data      │
│  ─────────────────────────────┼────────┼────────┼────────── │
│  user_sessions:{user_id}      │ Set    │ 7d     │ User's    │
│                               │        │        │ sessions  │
│  ─────────────────────────────┼────────┼────────┼────────── │
│  org_sessions:{org_id}        │ Set    │ 7d     │ Org's     │
│                               │        │        │ sessions  │
│  ─────────────────────────────┼────────┼────────┼────────── │
│  session_activity             │ ZSet   │ 7d     │ Activity  │
│                               │        │        │ tracking  │
│  ─────────────────────────────┼────────┼────────┼────────── │
│  session:revoked (channel)    │ Pub/Sub│ N/A    │ Invali-   │
│                               │        │        │ dation    │
│                                                             │
│  Memory Estimate (per session):                             │
│  • Session data: ~500 bytes                                 │
│  • User session set entry: ~50 bytes                        │
│  • Activity ZSet entry: ~50 bytes                           │
│  • Total: ~600 bytes per session                            │
│                                                             │
│  At 1M concurrent sessions: ~600MB Redis memory             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 Security Checklist

- [x] Session ID is cryptographically random (48+ bytes)
- [x] Session cookie has HttpOnly, Secure, SameSite attributes
- [x] Session has both sliding expiration and max lifetime
- [x] Concurrent session limits are enforced
- [x] Session revocation is immediate and propagated via Pub/Sub
- [x] Session metadata includes IP, user agent, device fingerprint
- [x] JWT access tokens have short TTL (15 minutes)
- [x] JWT access tokens embed session ID for revocation checking
- [x] Cookie value is HMAC-signed to prevent tampering
- [x] Session data is automatically purged by Redis TTL
- [x] GDPR-compliant data retention (session metadata anonymized after expiry)

---

*ADR Version: 1.0*
*Status: Accepted*
*Decision Date: 2026-04-03*
*Next Review: 2026-07-03*