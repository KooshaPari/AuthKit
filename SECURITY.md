# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security@omniroute.dev or use GitHub private vulnerability reporting
3. Include: description, steps to reproduce, potential impact
4. You should receive an acknowledgment within 48 hours

## Disclosure Policy

We follow coordinated disclosure. We'll work with you to understand and address the issue before any public disclosure.

## Security Measures

- Automated dependency auditing (cargo-deny / npm audit)
- Secret scanning (trufflehog / gitleaks)
- Static analysis (CodeQL / Clippy)
- Pre-commit hooks for sensitive data detection
