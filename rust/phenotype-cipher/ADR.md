# Architecture Decision Records — phenotype-cipher

## ADR-001 — RustCrypto as Underlying Implementation

**Status:** Accepted  
**Date:** 2026-03-27

### Context
Implementing cryptographic primitives from scratch is dangerous. RustCrypto provides audited, pure-Rust implementations of AES-GCM, ChaCha20-Poly1305, SHA-2, and more.

### Decision
All primitives wrap RustCrypto crates (aes-gcm, chacha20poly1305, sha2, blake3, argon2, ed25519-dalek, p256).

### Consequences
- Security audit coverage from RustCrypto audits.
- phenotype-cipher adds only ergonomics and misuse prevention on top.
- Updating primitives requires updating crate versions.

---

## ADR-002 — Opaque Nonce Generation

**Status:** Accepted  
**Date:** 2026-03-27

### Context
Nonce reuse under AES-GCM is catastrophic (full plaintext recovery). Allowing callers to supply nonces creates a misuse surface.

### Decision
All encryption functions generate nonces internally using OS-provided randomness (`rand::rngs::OsRng`). The nonce is included in the returned ciphertext blob.

### Consequences
- Callers cannot reuse nonces.
- The ciphertext format is: `[nonce (12 bytes)] || [ciphertext] || [tag (16 bytes)]`.

---

## ADR-003 — Newtype Keys for Type Safety

**Status:** Accepted  
**Date:** 2026-03-27

### Context
Passing a signing key where an encryption key is expected is a compiler-invisible bug with `[u8; 32]`.

### Decision
Each key type is a distinct newtype: `AesKey(Box<[u8; 32]>)`, `Ed25519SigningKey(...)`, etc. The compiler rejects key type confusion.

### Consequences
- Key confusion bugs become compile-time errors.
- Key types implement `Zeroize` and `Drop` for secure erasure.
