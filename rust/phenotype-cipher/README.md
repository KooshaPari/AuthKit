# cipher

Simple, safe cryptography for Rust. Encryption, hashing, signatures.

## Features

- **Encryption**: AES-GCM, ChaCha20-Poly1305
- **Hashing**: SHA-256, BLAKE3, Argon2
- **Signatures**: Ed25519, ECDSA
- **Key Derivation**: HKDF, PBKDF2

## Installation

```toml
[dependencies]
cipher = { git = "https://github.com/KooshaPari/cipher" }
```

## Usage

```rust
use cipher::{encrypt, decrypt, hash};

let encrypted = encrypt(plaintext, &key)?;
let decrypted = decrypt(encrypted, &key)?;
let signature = cipher::sign(message, &private_key)?;
cipher::verify(message, &signature, &public_key)?;
```

## License

MIT
