# AuthKit Functional Requirements & Gaps

> **Note**: This file originated in the archived `Authvault` repository as
> `docs/requirements/authvault-frnfr.md`. The table is preserved for
> traceability. FRs shipped before the archive remain on `Authvault` main
> (commit `c7994b9`); FRs shipped after are landed in this AuthKit
> crate. New FR IDs continue from the `FR-AUTHV-*` series to preserve
> cross-references in upstream design docs.

## 1. Functional Requirements (Authvault-era)

| ID | Area | Title | Status | PR |
|----|------|-------|--------|-----|
| FR-AUTHV-001 | OAuth2 | Authorization Code grant | SHIPPED | #1 |
| FR-AUTHV-002 | OAuth2 | Client Credentials grant | SHIPPED | #2 |
| FR-AUTHV-003 | OAuth2 | Refresh Token grant | SHIPPED | #3 |
| FR-AUTHV-004 | OAuth2 | PKCE support (S256) | SHIPPED | #4 |
| FR-AUTHV-005 | JWT | HS256 token signing | SHIPPED | #5 |
| FR-AUTHV-006 | JWT | iss/aud/exp/nbf/iat claim validation | SHIPPED | #6 |
| FR-AUTHV-007 | RBAC | Role-based access control | SHIPPED | #7 |
| FR-AUTHV-008 | ABAC | Attribute-based policy engine | SHIPPED | #8 |
| FR-AUTHV-009 | Sessions | Encrypted session token storage | SHIPPED | #9 |
| FR-AUTHV-010 | Bearer | Authorization: Bearer header extraction | SHIPPED | #10 |
| FR-AUTHV-011 | Error | RFC 6749 §5.2 error responses | SHIPPED | #11 |
| FR-AUTHV-012 | Tokens | Revocation list (RFC 7009) | SHIPPED | #16 |
| FR-AUTHV-013 | Tokens | Refresh-token rotation (RFC 6749 §6) | SHIPPED | #18 |
| FR-AUTHV-014 | Logging | Redacted auth-event logging (no secret material) | SHIPPED | #19 |
| FR-AUTHV-015 | Audit | Auth-event audit trail (sign-in, sign-out, refresh) | SHIPPED | #21 |
| FR-AUTHV-016 | JWT | alg=none rejection (RFC 7515 §10.7) | SHIPPED | #24 |
| FR-AUTHV-017 | JWT | RS256 / ES256 asymmetric signing keys | SHIPPED | #39 |
| FR-AUTHV-018 | PKCE | **State→session binding at middleware (this crate)** | **SHIPPED → AuthKit** | **#1 (AuthKit)** |

---

## 2. FR-AUTHV-018 — PKCE State Binding to Server Session at Middleware

| Field | Value |
|-------|-------|
| **Title** | Middleware-enforced binding of OAuth `state` to the active server session |
| **Repo** | KooshaPari/AuthKit |
| **Branch** | `feat/authkit-absorb-gap-008` |
| **Status** | SHIPPED |

**Description**  
The system SHALL bind OAuth `state` tokens to the server session that initiated the authorization
request and enforce that binding in the callback middleware. On an OAuth callback, the middleware
MUST extract the `state` query parameter and session cookie, verify the pair against the session
binding store, and reject the callback with a 401 JSON body when the state is missing, unbound, or
bound to a different session.

**Acceptance Criteria**

1. A callback with a valid `state` and matching session cookie passes through to the handler.
2. A callback with no `state` query parameter returns `401` with `{"error":"invalid_state",...}`.
3. A callback with a missing session cookie returns `401` with `{"error":"invalid_state",...}`.
4. A callback whose `state` is bound to a different session returns `401` with `{"error":"invalid_state",...}`.
5. An expired binding is treated as invalid and rejected with the same 401 response.

**Traceability**  
`src/domain/session_store.rs` — `SessionStore`, `InMemorySessionStore`.  
`src/middleware/pkce_state_session.rs` — `enforce_pkce_state_session()`, query/cookie extraction, 401 JSON response.  
Tests: `bind_and_verify_state_succeeds`, `verify_wrong_session_fails`, `verify_missing_state_fails`,
`revoke_state_removes_binding`, `expired_state_is_rejected`, `rebinding_state_overwrites_previous_session`,
`valid_binding_allows_callback`, `missing_state_is_rejected`, `missing_cookie_is_rejected`,
`wrong_session_binding_is_rejected`, `expired_state_is_rejected`.

---

## 3. Gaps / PLANNED (Authvault-era, migration status)

| ID | Area | Gap | Status |
|----|------|-----|--------|
| GAP-001 | Storage | Encrypted at rest with KMS-backed keys (currently local AES-GCM) | PLANNED → AuthKit AUT-SOTA-005 |
| GAP-002 | PKCE | Plain (not S256) method rejected at request time | SHIPPED → FR-AUTHV-004 |
| GAP-003 | Sessions | Session-fixation defense on sign-in | SHIPPED → FR-AUTHV-009 |
| GAP-004 | JWT | `alg=none` bypass — surface (RFC 7515 §10.7) and prevents `alg=none` bypass | SHIPPED → FR-AUTHV-016 |
| GAP-005 | Tokens | Refresh-token rotation — `refresh_token()` re-uses the same `sub`/`roles` without invalidating the prior token | SHIPPED → FR-AUTHV-013 |
| GAP-006 | Tokens | Token revocation list — no mechanism to revoke a non-expired JWT before its `exp` | SHIPPED → FR-AUTHV-012 |
| GAP-007 | Bearer | Asymmetric (RS256/ES256) signing key support — current implementation is HMAC-only | SHIPPED → FR-AUTHV-017 |
| GAP-008 | PKCE | State binding to server session — `OAuthState` is generated but the server-side session association is not enforced at the middleware layer | **SHIPPED → FR-AUTHV-018 (this AuthKit crate)** |
| GAP-009 | General | Rate-limiting on failed auth attempts — no brute-force protection for verifier/state/bearer endpoints | PLANNED → AuthKit AUT-SOTA-006 |
| GAP-010 | General | Tracera / AgilePlus middleware adapter — wiring of these requirements into Axum tower layers for consumer repos not yet documented | PLANNED → AuthKit AUT-SOTA-007 |
