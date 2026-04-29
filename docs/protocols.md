# Protocol Scope

AuthKit keeps protocol-specific complexity behind a consistent SDK model.

## OAuth 2.0

- Authorization Code with PKCE for web, SPA, and mobile clients.
- Client Credentials for service-to-service flows.
- Device Code for CLI and input-constrained clients.

## OpenID Connect

- Discovery and issuer metadata.
- ID token validation.
- Claims mapping for cross-language SDK users.

## Enterprise And Passwordless

- SAML 2.0 for enterprise SSO.
- WebAuthn and passkeys for passwordless authentication.
- JWT validation for API and service boundaries.

## Security Posture

AuthKit should prefer secure defaults, explicit provider configuration, and
testable protocol boundaries over one-off app-specific auth code.
