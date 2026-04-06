//! Digital Signatures Module
//!
//! Provides Ed25519 digital signatures for authentication and non-repudiation

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;
use thiserror::Error;

/// Signature errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum SignatureError {
    #[error("Invalid signature length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

/// Signing key pair
#[derive(Clone)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &"[REDACTED 32 bytes]")
            .field("secret_key", &"[REDACTED 32 bytes]")
            .finish()
    }
}

/// Generate a new Ed25519 key pair
pub fn generate_keypair() -> KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    
    KeyPair {
        public_key: verifying_key.to_bytes().to_vec(),
        secret_key: signing_key.to_bytes().to_vec(),
    }
}

/// Sign a message
pub fn sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, SignatureError> {
    if secret_key.len() != 32 {
        return Err(SignatureError::InvalidSecretKey);
    }
    
    let key_bytes: [u8; 32] = secret_key.try_into()
        .map_err(|_| SignatureError::InvalidSecretKey)?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a signature
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignatureError> {
    if signature.len() != 64 {
        return Err(SignatureError::InvalidLength { 
            expected: 64, 
            got: signature.len() 
        });
    }
    
    if public_key.len() != 32 {
        return Err(SignatureError::InvalidPublicKey);
    }
    
    let pk_bytes: [u8; 32] = public_key.try_into()
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    
    let sig_bytes: [u8; 64] = signature.try_into()
        .map_err(|_| SignatureError::InvalidLength { expected: 64, got: signature.len() })?;
    let sig = Signature::from_bytes(&sig_bytes);
    
    verifying_key.verify(message, &sig)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Derive public key from secret key
pub fn derive_public_key(secret_key: &[u8]) -> Result<Vec<u8>, SignatureError> {
    if secret_key.len() != 32 {
        return Err(SignatureError::InvalidSecretKey);
    }
    
    let key_bytes: [u8; 32] = secret_key.try_into()
        .map_err(|_| SignatureError::InvalidSecretKey)?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let verifying_key = signing_key.verifying_key();
    
    Ok(verifying_key.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = generate_keypair();
        assert_eq!(kp.public_key.len(), 32);
        assert_eq!(kp.secret_key.len(), 32);
    }

    #[test]
    fn test_keypair_unique() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        assert_ne!(kp1.public_key, kp2.public_key);
        assert_ne!(kp1.secret_key, kp2.secret_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = generate_keypair();
        let message = b"Hello, World!";
        
        let signature = sign(message, &kp.secret_key).unwrap();
        assert_eq!(signature.len(), 64);
        
        verify(message, &signature, &kp.public_key).unwrap();
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = generate_keypair();
        let message = b"original message";
        let wrong_message = b"different message";
        
        let signature = sign(message, &kp.secret_key).unwrap();
        let result = verify(wrong_message, &signature, &kp.public_key);
        
        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let message = b"test message";
        
        let signature = sign(message, &kp1.secret_key).unwrap();
        let result = verify(message, &signature, &kp2.public_key);
        
        assert!(matches!(result, Err(SignatureError::VerificationFailed)));
    }

    #[test]
    fn test_invalid_secret_key_length() {
        let result = sign(b"test", &[0u8; 16]);
        assert!(matches!(result, Err(SignatureError::InvalidSecretKey)));
    }

    #[test]
    fn test_invalid_signature_length() {
        let kp = generate_keypair();
        let result = verify(b"test", &[0u8; 32], &kp.public_key);
        assert!(matches!(result, Err(SignatureError::InvalidLength { expected: 64, got: 32 })));
    }

    #[test]
    fn test_invalid_public_key_length() {
        let kp = generate_keypair();
        let message = b"test";
        let sig = sign(message, &kp.secret_key).unwrap();
        
        let result = verify(message, &sig, &[0u8; 16]);
        assert!(matches!(result, Err(SignatureError::InvalidPublicKey)));
    }

    #[test]
    fn test_derive_public_key() {
        let kp = generate_keypair();
        let derived = derive_public_key(&kp.secret_key).unwrap();
        assert_eq!(derived, kp.public_key);
    }

    #[test]
    fn test_empty_message() {
        let kp = generate_keypair();
        let signature = sign(b"", &kp.secret_key).unwrap();
        verify(b"", &signature, &kp.public_key).unwrap();
    }

    #[test]
    fn test_large_message() {
        let kp = generate_keypair();
        let message = vec![0u8; 10000];
        let signature = sign(&message, &kp.secret_key).unwrap();
        verify(&message, &signature, &kp.public_key).unwrap();
    }

    #[test]
    fn test_deterministic_verification() {
        let kp = generate_keypair();
        let message = b"test message";
        let signature = sign(message, &kp.secret_key).unwrap();
        
        // Verify multiple times
        for _ in 0..10 {
            verify(message, &signature, &kp.public_key).unwrap();
        }
    }

    #[test]
    fn test_signature_unique() {
        let kp = generate_keypair();
        let message = b"same message";
        
        let sig1 = sign(message, &kp.secret_key).unwrap();
        let sig2 = sign(message, &kp.secret_key).unwrap();
        
        // Ed25519 signatures are deterministic, so they should be the same
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_keypair_debug_redacts_keys() {
        let kp = generate_keypair();
        let debug_str = format!("{:?}", kp);
        assert!(!debug_str.contains(&hex::encode(&kp.secret_key)));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_error_display() {
        let err = SignatureError::VerificationFailed;
        assert_eq!(err.to_string(), "Signature verification failed");
    }

    #[test]
    fn test_error_debug() {
        let err = SignatureError::InvalidPublicKey;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidPublicKey"));
    }

    #[test]
    fn test_error_clone() {
        let err = SignatureError::SigningFailed("test".to_string());
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn test_error_equality() {
        let err1 = SignatureError::VerificationFailed;
        let err2 = SignatureError::VerificationFailed;
        let err3 = SignatureError::InvalidPublicKey;
        
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }
}
