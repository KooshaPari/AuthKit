//! Hashing Module
//!
//! Provides cryptographic hash functions including SHA-256, SHA-512, and Blake3

use blake3::Hasher as Blake3Hasher;
use sha2::{Digest, Sha256, Sha512};

/// Hash algorithm selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake3,
}

/// Hash data using SHA-256
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using SHA-512
pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using Blake3
pub fn blake3(data: &[u8]) -> Vec<u8> {
    Blake3Hasher::new().update(data).finalize().as_bytes().to_vec()
}

/// Hash with algorithm selection
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => sha256(data),
        HashAlgorithm::Sha512 => sha512(data),
        HashAlgorithm::Blake3 => blake3(data),
    }
}

/// Compute HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC-SHA256
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello world";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"test data";
        let h1 = sha256(data);
        let h2 = sha256(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha512() {
        let data = b"hello world";
        let hash = sha512(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake3() {
        let data = b"hello world";
        let hash = blake3(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_deterministic() {
        let data = b"test data";
        let h1 = blake3(data);
        let h2 = blake3(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_hashes_different() {
        let data = b"same input";
        let sha = sha256(data);
        let blake = blake3(data);
        assert_ne!(sha, blake);
    }

    #[test]
    fn test_hash_sha256() {
        let data = b"test";
        let h1 = sha256(data);
        let h2 = hash(data, HashAlgorithm::Sha256);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_sha512() {
        let data = b"test";
        let h1 = sha512(data);
        let h2 = hash(data, HashAlgorithm::Sha512);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_blake3() {
        let data = b"test";
        let h1 = blake3(data);
        let h2 = hash(data, HashAlgorithm::Blake3);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"secret key";
        let data = b"message to authenticate";
        let mac = hmac_sha256(key, data);
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn test_hmac_verify_valid() {
        let key = b"secret key";
        let data = b"message to authenticate";
        let mac = hmac_sha256(key, data);
        assert!(verify_hmac_sha256(key, data, &mac));
    }

    #[test]
    fn test_hmac_verify_invalid() {
        let key = b"secret key";
        let data = b"message to authenticate";
        let mac = hmac_sha256(key, data);
        
        let wrong_data = b"different message";
        assert!(!verify_hmac_sha256(key, wrong_data, &mac));
    }

    #[test]
    fn test_hmac_different_keys() {
        let key1 = b"key one";
        let key2 = b"key two";
        let data = b"same data";
        
        let mac1 = hmac_sha256(key1, data);
        let mac2 = hmac_sha256(key2, data);
        
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_large_data_hashing() {
        let data = vec![0u8; 100000];
        let sha = sha256(&data);
        let blake = blake3(&data);
        assert_eq!(sha.len(), 32);
        assert_eq!(blake.len(), 32);
    }

    #[test]
    fn test_hash_algorithm_debug() {
        let alg = HashAlgorithm::Blake3;
        let debug_str = format!("{:?}", alg);
        assert!(debug_str.contains("Blake3"));
    }

    #[test]
    fn test_hash_algorithm_equality() {
        assert_eq!(HashAlgorithm::Sha256, HashAlgorithm::Sha256);
        assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Blake3);
    }
}
