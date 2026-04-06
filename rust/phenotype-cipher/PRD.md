# PRD — phenotype-cipher

## Overview

`phenotype-cipher` is a safe, simple cryptography library for Rust. It provides high-level APIs for symmetric encryption (AES-GCM, ChaCha20-Poly1305), hashing (SHA-256, BLAKE3, Argon2), digital signatures (Ed25519, ECDSA), and key derivation (HKDF, PBKDF2).

## Goals

- Expose an ergonomic Rust API that prevents common cryptographic misuse (nonce reuse, key confusion, etc.).
- Wrap well-audited underlying crates (RustCrypto, ring) rather than implementing primitives.
- Serve as the single cryptographic dependency for all Phenotype Rust services.

## Epics

### E1 — Symmetric Encryption
- E1.1 AES-256-GCM encrypt/decrypt with automatic nonce generation.
- E1.2 ChaCha20-Poly1305 encrypt/decrypt.
- E1.3 AEAD interface: encrypt returns (ciphertext, nonce, tag) tuple.

### E2 — Hashing
- E2.1 SHA-256 and SHA-512 for general-purpose hashing.
- E2.2 BLAKE3 for high-performance hashing.
- E2.3 Argon2id for password hashing with configurable work factors.

### E3 — Digital Signatures
- E3.1 Ed25519 sign and verify.
- E3.2 ECDSA (P-256, P-384) sign and verify.
- E3.3 Key generation for all supported algorithms.

### E4 — Key Derivation
- E4.1 HKDF for deriving keys from a master secret.
- E4.2 PBKDF2 for password-based key derivation.
- E4.3 Secure random byte generation.

### E5 — Safety Guarantees
- E5.1 Nonces are always generated randomly; callers cannot supply nonces directly (prevents reuse).
- E5.2 All key types are newtype wrappers preventing key confusion.
- E5.3 Secrets are zeroed on drop using `zeroize`.

## Acceptance Criteria

- A message encrypted with AES-GCM decrypts correctly with the same key.
- An incorrect decryption key returns an authenticated decryption error, not silently corrupt data.
- Password hashes produced by Argon2id verify correctly against the original password.
