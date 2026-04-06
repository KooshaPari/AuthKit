# Functional Requirements — phenotype-cipher

## FR-SYMENC — Symmetric Encryption

| ID | Requirement |
|----|-------------|
| FR-SYMENC-001 | The library SHALL provide AES-256-GCM encryption with automatic random nonce generation. |
| FR-SYMENC-002 | The library SHALL provide ChaCha20-Poly1305 encryption with automatic random nonce generation. |
| FR-SYMENC-003 | Decryption SHALL return an error on authentication tag mismatch without exposing plaintext. |
| FR-SYMENC-004 | The library SHALL NOT expose nonce as a caller-supplied parameter to prevent reuse. |

## FR-HASH — Hashing

| ID | Requirement |
|----|-------------|
| FR-HASH-001 | The library SHALL provide SHA-256 and SHA-512 hashing functions. |
| FR-HASH-002 | The library SHALL provide BLAKE3 hashing for high-performance use cases. |
| FR-HASH-003 | The library SHALL provide Argon2id password hashing with configurable memory, iterations, and parallelism. |
| FR-HASH-004 | The library SHALL provide a verify function for Argon2id hashes. |

## FR-SIG — Digital Signatures

| ID | Requirement |
|----|-------------|
| FR-SIG-001 | The library SHALL provide Ed25519 key generation, signing, and verification. |
| FR-SIG-002 | The library SHALL provide ECDSA (P-256, P-384) key generation, signing, and verification. |
| FR-SIG-003 | Signature verification SHALL return a typed error, not a boolean. |

## FR-KDF — Key Derivation

| ID | Requirement |
|----|-------------|
| FR-KDF-001 | The library SHALL provide HKDF for deriving keys from a master secret and salt. |
| FR-KDF-002 | The library SHALL provide PBKDF2 for password-based key derivation. |
| FR-KDF-003 | The library SHALL provide a secure random byte generation function. |

## FR-SAFE — Safety

| ID | Requirement |
|----|-------------|
| FR-SAFE-001 | All secret key types SHALL implement zeroize::Zeroize and be zeroed on drop. |
| FR-SAFE-002 | Key types SHALL be newtype wrappers preventing accidental key confusion. |
| FR-SAFE-003 | The library SHALL compile with no unsafe blocks in library code. |
