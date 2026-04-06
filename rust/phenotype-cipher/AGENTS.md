# AGENTS.md - phenotype-cipher

## Project Overview

- **Name**: phenotype-cipher
- **Description**: Simple, safe cryptography for Rust
- **Language**: Rust (edition 2021)
- **Location**: Phenotype repos shelf

## Features

- **Encryption**: AES-GCM, ChaCha20-Poly1305
- **Hashing**: SHA-256, BLAKE3, Argon2
- **Signatures**: Ed25519, ECDSA
- **Key Derivation**: HKDF, PBKDF2

## Agent Rules

### Project-Specific Rules

1. **Security First**
   - All cryptographic operations must be constant-time where possible
   - Use secure defaults, require explicit insecure options
   - Never log keys or sensitive data
   - Fail loudly on cryptographic failures

2. **Code Quality**
   - Full test coverage for cryptographic primitives
   - Property-based tests for key derivation
   - Integration tests for real-world scenarios
   - Document security properties clearly

3. **Error Handling**
   - Use descriptive error types
   - No silent failures in crypto operations
   - Clear error messages for debugging

### Phenotype Org Standard Rules

1. **UTF-8 encoding** in all text files
2. **Worktree discipline**: canonical repo stays on `main`
3. **CI completeness**: fix all CI failures before merging
4. **Never commit** agent directories (`.claude/`, `.codex/`, `.cursor/`)

## Quality Standards

```bash
# Build
cargo build

# Test
cargo test --all-features

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt --check

# Audit dependencies
cargo audit
```

## Git Workflow

1. Create feature branch: `git checkout -b feat/my-feature`
2. Add comprehensive tests
3. Run full audit and test suite
4. Create PR with security considerations
5. Require review for crypto changes
