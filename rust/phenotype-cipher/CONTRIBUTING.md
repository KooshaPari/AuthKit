# Contributing to phenotype-cipher

Thank you for your interest in contributing to phenotype-cipher.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Phenotype-Enterprise/phenotype-cipher
cd phenotype-cipher

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build

# Test
cargo test --all-features

# Lint
cargo clippy
cargo fmt --check

# Security audit
cargo audit
```

## Features

- **Encryption**: AES-GCM, ChaCha20-Poly1305
- **Hashing**: SHA-256, BLAKE3, Argon2
- **Signatures**: Ed25519, ECDSA
- **Key Derivation**: HKDF, PBKDF2

## Security Requirements

- All cryptographic operations must be constant-time where possible
- Use secure defaults, require explicit insecure options
- Never log keys or sensitive data
- Fail loudly on cryptographic failures

## Making Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Add comprehensive tests
5. Run full audit and test suite
6. Ensure all checks pass
7. Commit using conventional commits
8. Push and create PR (require review for crypto changes)

## Testing Requirements

- Full test coverage for cryptographic primitives
- Property-based tests for key derivation
- Integration tests for real-world scenarios
