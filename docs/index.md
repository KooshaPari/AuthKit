# AuthKit

AuthKit is the shared authentication SDK surface for the Phenotype ecosystem. It
standardizes identity and access-management concepts across Rust, TypeScript,
Python, and Go packages.

## Core Scope

| Area | Coverage |
| --- | --- |
| OAuth 2.0 | Authorization Code + PKCE, Client Credentials, Device Code |
| OpenID Connect | Identity layer, discovery, claims, token validation |
| SAML 2.0 | Enterprise SSO surface |
| WebAuthn | Passkeys and passwordless authentication |
| JWT | Token validation and API security |

## Where To Start

- Use [Protocol Scope](./protocols.md) to understand supported auth flows.
- Use [Package Surfaces](./packages.md) to find the language-specific package.
- Use [Functional Requirements](./FUNCTIONAL_REQUIREMENTS.md) for traceability.

## Status

AuthKit is under active implementation and SDK hardening. The docs site is the
published entrypoint for the shared contract; implementation details remain in
language-specific package READMEs.
