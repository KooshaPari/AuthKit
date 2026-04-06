//! Phenotype Cipher Library
//!
//! Simple, safe cryptography for Rust. Encryption, hashing, signatures.
//!
//! ## Features
//!
//! - **Encryption**: AES-GCM-256, ChaCha20-Poly1305 authenticated encryption
//! - **Hashing**: SHA-256, BLAKE3, BLAKE2b
//! - **Signatures**: Ed25519
//! - **Key Derivation**: Argon2, HKDF
//!
//! ## Installation
//!
//! ```toml
//! [dependencies]
//! phenotype-cipher = { path = "../phenotype-cipher" }
//! ```
//!
//! ## Quick Start
//!
//! ```rust
//! use phenotype_cipher::{AesGcmCipher, Sha256Hasher, CipherResult};
//!
//! # fn main() -> CipherResult<()> {
//! // Encryption - generate_key returns Vec<u8> directly
//! let key = AesGcmCipher::generate_key();
//! let cipher = AesGcmCipher::new(&key)?;
//! let ciphertext = cipher.encrypt(b"hello world")?;
//! let plaintext = cipher.decrypt(&ciphertext)?;
//! # Ok(())
//! # }
//! ```

pub mod core;

// Re-export main types
pub use core::encryption::{AesGcmCipher, ChaChaCipher, Ciphertext};
pub use core::hashing::{Sha256Hasher, Blake3Hasher, Blake2bHasher};
pub use core::signatures::{Ed25519Signer, Signature, PublicKey, SecretKey};
pub use core::{CipherError, CipherResult, Key, Nonce};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[test]
    fn test_signature_unique_per_message() {
        let (_, secret_key) = Ed25519Signer::generate_keypair();
        let msg1 = b"message one";
        let msg2 = b"message two";

        let sig1 = Ed25519Signer::sign(msg1, &secret_key).unwrap();
        let sig2 = Ed25519Signer::sign(msg2, &secret_key).unwrap();

        // Different messages should produce different signatures
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_public_key_derivation() {
        let (public_key, secret_key) = Ed25519Signer::generate_keypair();

        // Verify keys are non-empty
        assert!(!public_key.is_empty());
        assert!(!secret_key.is_empty());
    }
    #[test]
    fn test_chacha_encryption() {
        let key = ChaChaCipher::generate_key();
        let cipher = ChaChaCipher::new(&key).unwrap();
        let plaintext = b"hello chacha";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext[..], decrypted[..]);
    }

    #[test]
    fn test_chacha_empty_data() {
        let key = ChaChaCipher::generate_key();
        let cipher = ChaChaCipher::new(&key).unwrap();
        let plaintext = b"";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext[..], decrypted[..]);
    }

    #[test]
    fn test_aes_gcm_large_data() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext = vec![0u8; 1024 * 1024]; // 1MB
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_different_ciphertexts() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext = b"hello world";
        let ct1 = cipher.encrypt(plaintext).unwrap();
        let ct2 = cipher.encrypt(plaintext).unwrap();
        // Different nonces should produce different ciphertexts
        assert_ne!(ct1.data, ct2.data);
        assert_ne!(ct1.nonce, ct2.nonce);
    }

    #[test]
    fn test_aes_tampered_ciphertext() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext = b"hello world";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();
        // Tamper with the ciphertext
        ciphertext.data[0] ^= 0xFF;
        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha_different_ciphertexts() {
        let key = ChaChaCipher::generate_key();
        let cipher = ChaChaCipher::new(&key).unwrap();
        let plaintext = b"hello world";
        let ct1 = cipher.encrypt(plaintext).unwrap();
        let ct2 = cipher.encrypt(plaintext).unwrap();
        // Different nonces should produce different ciphertexts
        assert_ne!(ct1.data, ct2.data);
        assert_ne!(ct1.nonce, ct2.nonce);
    }

    #[test]
    fn test_sha256_hashing() {
        let hash1 = Sha256Hasher::hash(b"hello");
        let hash2 = Sha256Hasher::hash(b"hello");
        let hash3 = Sha256Hasher::hash(b"world");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_blake3_hashing() {
        let hash1 = Blake3Hasher::hash(b"hello");
        let hash2 = Blake3Hasher::hash(b"hello");
        let hash3 = Blake3Hasher::hash(b"world");

        assert_eq!(hash1.0, hash2.0);
        assert_ne!(hash1.0, hash3.0);
    }

    #[test]
    fn test_blake2b_hashing() {
        let hash1 = Blake2bHasher::hash(b"hello");
        let hash2 = Blake2bHasher::hash(b"hello");
        let hash3 = Blake2bHasher::hash(b"world");

        assert_eq!(hash1.0, hash2.0);
        assert_ne!(hash1.0, hash3.0);
    }

    #[test]
    #[test]
    fn test_ed25519_sign_and_verify() {
        let (public_key, secret_key) = Ed25519Signer::generate_keypair();
        let message = b"hello world";
        let signature = Ed25519Signer::sign(message, &secret_key).unwrap();

        assert!(Ed25519Signer::verify(message, &signature, &public_key).unwrap());
    }

    #[test]
    fn test_ed25519_verify_wrong_message() {
        let (public_key, secret_key) = Ed25519Signer::generate_keypair();
        let message = b"hello world";
        let signature = Ed25519Signer::sign(message, &secret_key).unwrap();

        // Wrong message
        assert!(!Ed25519Signer::verify(b"wrong message", &signature, &public_key).unwrap());
    }

    #[test]
    fn test_ed25519_deterministic_signatures() {
        let (_, secret_key) = Ed25519Signer::generate_keypair();
        let message = b"test message";

        let sig1 = Ed25519Signer::sign(message, &secret_key).unwrap();
        let sig2 = Ed25519Signer::sign(message, &secret_key).unwrap();

        // Ed25519 uses deterministic nonce, so signatures should be identical
        assert_eq!(sig1, sig2);
    }
    #[test]
    fn test_key_generation_unique() {
        let key1 = AesGcmCipher::generate_key();
        let key2 = AesGcmCipher::generate_key();
        assert_ne!(key1, key2);

        let chacha_key1 = ChaChaCipher::generate_key();
        let chacha_key2 = ChaChaCipher::generate_key();
        assert_ne!(chacha_key1, chacha_key2);
    }

    #[test]
    fn test_aes_key_size() {
        let key = AesGcmCipher::generate_key();
        assert_eq!(key.len(), 32); // AES-256 requires 32 bytes
    }

    #[test]
    fn test_chacha_cipher_key_generation() {
        let key = ChaChaCipher::generate_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_cipher_error_display() {
        let err = CipherError::InvalidKey("test".to_string());
        assert!(err.to_string().contains("InvalidKey"));
    }
}
