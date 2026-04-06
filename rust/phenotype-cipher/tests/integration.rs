//! Integration tests for phenotype-cipher
//!
//! These tests verify end-to-end functionality across all cipher modules.

use phenotype_cipher::{
    AesGcmCipher, ChaChaCipher, Sha256Hasher, Blake3Hasher, Blake2bHasher,
    Ed25519Signer, KeyPair, CipherResult
};

// ============================================================================
// Encryption Integration Tests
// ============================================================================

#[test]
fn test_aes_gcm_full_workflow() {
    let key = AesGcmCipher::generate_key().unwrap();
    let cipher = AesGcmCipher::new(&key).unwrap();

    let plaintext = b"hello world";
    let ciphertext = cipher.encrypt(plaintext).unwrap();
    let decrypted = cipher.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_aes_gcm_large_data() {
    let key = AesGcmCipher::generate_key().unwrap();
    let cipher = AesGcmCipher::new(&key).unwrap();

    let plaintext = vec![0u8; 10000];
    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    let decrypted = cipher.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_aes_gcm_empty_data() {
    let key = AesGcmCipher::generate_key().unwrap();
    let cipher = AesGcmCipher::new(&key).unwrap();

    let plaintext = b"";
    let ciphertext = cipher.encrypt(plaintext).unwrap();
    let decrypted = cipher.decrypt(&ciphertext).unwrap();

    assert!(decrypted.is_empty());
}

#[test]
fn test_chacha20_full_workflow() {
    let key = ChaChaCipher::generate_key().unwrap();
    let cipher = ChaChaCipher::new(&key).unwrap();

    let plaintext = b"hello world";
    let ciphertext = cipher.encrypt(plaintext).unwrap();
    let decrypted = cipher.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_chacha20_large_data() {
    let key = ChaChaCipher::generate_key().unwrap();
    let cipher = ChaChaCipher::new(&key).unwrap();

    let plaintext = vec![0u8; 10000];
    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    let decrypted = cipher.decrypt(&ciphertext).unwrap();

    assert_eq!(plaintext, decrypted);
}

// ============================================================================
// Hashing Integration Tests
// ============================================================================

#[test]
fn test_sha256_basic() {
    let hash = Sha256Hasher::hash(b"hello world");
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_sha256_empty() {
    let hash = Sha256Hasher::hash(b"");
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_blake3_basic() {
    let hash = Blake3Hasher::hash(b"hello world");
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_blake3_empty() {
    let hash = Blake3Hasher::hash(b"");
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_blake3_large_data() {
    let data = vec![0u8; 10000];
    let hash = Blake3Hasher::hash(&data);
    assert_eq!(hash.as_bytes().len(), 32);
}

#[test]
fn test_blake2b_basic() {
    let hash = Blake2bHasher::hash(b"hello world");
    assert_eq!(hash.as_bytes().len(), 64);
}

#[test]
fn test_hash_consistency() {
    let data = b"test data";
    let hash1 = Sha256Hasher::hash(data);
    let hash2 = Sha256Hasher::hash(data);
    assert_eq!(hash1.as_bytes(), hash2.as_bytes());
}

#[test]
fn test_hash_uniqueness() {
    let hash1 = Sha256Hasher::hash(b"data1");
    let hash2 = Sha256Hasher::hash(b"data2");
    assert_ne!(hash1.as_bytes(), hash2.as_bytes());
}

// ============================================================================
// Signature Integration Tests
// ============================================================================

#[test]
fn test_ed25519_sign_verify() {
    let keypair = Ed25519Signer::generate_keypair().unwrap();
    let signer = Ed25519Signer::new(&keypair).unwrap();

    let message = b"hello world";
    let signature = signer.sign(message).unwrap();

    assert!(signer.verify(message, &signature).is_ok());
}

#[test]
fn test_ed25519_tampered_message() {
    let keypair = Ed25519Signer::generate_keypair().unwrap();
    let signer = Ed25519Signer::new(&keypair).unwrap();

    let message = b"hello world";
    let signature = signer.sign(message).unwrap();

    let tampered = b"tampered message";
    assert!(signer.verify(tampered, &signature).is_err());
}

#[test]
fn test_ed25519_empty_message() {
    let keypair = Ed25519Signer::generate_keypair().unwrap();
    let signer = Ed25519Signer::new(&keypair).unwrap();

    let message = b"";
    let signature = signer.sign(message).unwrap();

    assert!(signer.verify(message, &signature).is_ok());
}

// ============================================================================
// End-to-End Integration Tests
// ============================================================================

#[test]
fn test_encryption_hashing_workflow() {
    // Encrypt data
    let key = AesGcmCipher::generate_key().unwrap();
    let cipher = AesGcmCipher::new(&key).unwrap();

    let plaintext = b"sensitive data";
    let ciphertext = cipher.encrypt(plaintext).unwrap();

    // Hash the ciphertext
    let hash = Sha256Hasher::hash(&ciphertext);
    assert_eq!(hash.as_bytes().len(), 32);

    // Decrypt and verify
    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_sign_then_encrypt() {
    // Sign message
    let keypair = Ed25519Signer::generate_keypair().unwrap();
    let signer = Ed25519Signer::new(&keypair).unwrap();

    let message = b"important message";
    let signature = signer.sign(message).unwrap();

    // Encrypt message and signature
    let key = AesGcmCipher::generate_key().unwrap();
    let cipher = AesGcmCipher::new(&key).unwrap();

    let signature_bytes = signature.to_bytes();
    let combined = [message.as_slice(), &signature_bytes].concat();
    let ciphertext = cipher.encrypt(&combined).unwrap();

    // Decrypt
    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    assert!(decrypted.len() > message.len());
}

#[test]
fn test_keypair_serialization() {
    let keypair = Ed25519Signer::generate_keypair().unwrap();

    let bytes = keypair.to_bytes();
    let restored = KeyPair::from_bytes(&bytes).unwrap();

    assert_eq!(bytes, restored.to_bytes());
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[test]
fn test_aes_encryption_roundtrip_various_sizes() {
    let key = AesGcmCipher::generate_key().unwrap();
    let cipher = AesGcmCipher::new(&key).unwrap();

    for size in [0, 1, 16, 100, 1024, 10000] {
        let data = vec![0xABu8; size];
        let ciphertext = cipher.encrypt(&data).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(data, decrypted, "Failed for size {}", size);
    }
}

#[test]
fn test_all_hashers_produce_different_outputs() {
    let data = b"test data";

    let sha256 = Sha256Hasher::hash(data);
    let blake3 = Blake3Hasher::hash(data);
    let blake2b = Blake2bHasher::hash(data);

    // All should be different (with extremely high probability)
    assert_ne!(sha256.as_bytes(), blake3.as_bytes());
    assert_ne!(sha256.as_bytes(), blake2b.as_bytes());
    assert_ne!(blake3.as_bytes(), blake2b.as_bytes()[..32]);
}

#[test]
fn test_signature_determinism() {
    let keypair = Ed25519Signer::generate_keypair().unwrap();
    let signer = Ed25519Signer::new(&keypair).unwrap();

    let message = b"test message";
    let sig1 = signer.sign(message).unwrap();
    let sig2 = signer.sign(message).unwrap();

    // Ed25519 uses deterministic signatures, so they should be identical
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}
