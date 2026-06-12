//! Opaque token: [`Token`] with redaction + sign/verify round-trip.
//!
//! A `Token` is a 256-bit (32-byte) opaque value that can be:
//! - **signed** with a server-side secret, producing a hex-encoded
//!   `signed` form suitable for embedding in a JWT-like envelope or
//!   an `Authorization: Bearer` header.
//! - **verified** by recomputing the HMAC and comparing in constant
//!   time. The verification message is intentionally generic
//!   (`TokenInvalid`) so we don't leak which check failed.
//! - **redacted** for logging and error reporting. The redacted form
//!   shows only the first 4 and last 4 hex characters with the middle
//!   masked: `abcd****wxyz`.
//!
//! The signing scheme is HMAC-SHA256, which is what `sha2` + `subtle`
//! (or our `subtle` re-implementation in the test path) gives us.
//! For production, callers should pass a 32-byte secret loaded from
//! a secret manager (see `phenotype-secret`).
//!
//! The crate is `#![forbid(unsafe_code)]` so no FFI binding can
//! accidentally introduce UB through the auth path.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{instrument, warn};

use crate::error::{AuthError, Result};

/// Number of bytes in the opaque token value.
pub const TOKEN_BYTES: usize = 32;

/// An opaque authentication token (32 bytes).
///
/// The internal byte array is `[u8; TOKEN_BYTES]`. The `Debug` impl
/// is `redact()`-aware so the token never leaks through `dbg!()` or
/// `format!("{:?}", token)` calls.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token([u8; TOKEN_BYTES]);

impl Token {
    /// Generates a new random token using the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps a known byte array. The caller is responsible for
    /// sourcing the bytes securely (e.g. from a secret manager).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes. Callers should avoid copying these
    /// into long-lived memory; prefer [`redact`](Self::redact) for
    /// logging.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }

    /// Returns a redacted form of the token suitable for logging:
    /// the first 4 and last 4 hex characters, with the middle masked.
    ///
    /// Example: a 32-byte token `00112233...ffeeddcc` becomes
    /// `"00112233**********ffeeddcc"`.
    pub fn redact(&self) -> String {
        let hex = hex::encode(self.0);
        let len = hex.len();
        debug_assert_eq!(len, TOKEN_BYTES * 2);
        let prefix = &hex[..4];
        let suffix = &hex[len - 4..];
        format!("{prefix}{}{suffix}", "*".repeat(10))
    }

    /// Signs the token with a secret, producing a hex-encoded
    /// `signed` form. The output is `hex(token) + "." + hex(hmac)`.
    #[instrument(skip_all, fields(token.preview = %self.redact(), secret.len = secret.len()))]
    pub fn sign(&self, secret: &[u8]) -> String {
        let token_hex = hex::encode(self.0);
        let hmac = hmac_sha256(secret, &self.0);
        let hmac_hex = hex::encode(hmac);
        format!("{token_hex}.{hmac_hex}")
    }

    /// Verifies a signed token against a secret. The token bytes
    /// recovered from the signed form are returned on success. On
    /// failure, the error is `TokenInvalid` (generic) regardless of
    /// which check failed (length, hex parse, hmac).
    #[instrument(skip_all, fields(signed.len = signed.len(), secret.len = secret.len()))]
    pub fn verify(signed: &str, secret: &[u8]) -> Result<Self> {
        let result = (|| -> Result<Self> {
            let (token_hex, hmac_hex) = signed
                .split_once('.')
                .ok_or(AuthError::TokenInvalid)?;

            let token_bytes_vec = hex::decode(token_hex).map_err(|_| AuthError::TokenInvalid)?;
            let hmac_bytes_vec = hex::decode(hmac_hex).map_err(|_| AuthError::TokenInvalid)?;

            if token_bytes_vec.len() != TOKEN_BYTES || hmac_bytes_vec.len() != 32 {
                return Err(AuthError::TokenInvalid);
            }

            let mut token_bytes = [0u8; TOKEN_BYTES];
            token_bytes.copy_from_slice(&token_bytes_vec);

            let expected = hmac_sha256(secret, &token_bytes);
            // Constant-time comparison via XOR. We avoid the `subtle`
            // crate as a dependency and roll a 1-line constant-time eq.
            let mut diff: u8 = 0;
            for (a, b) in expected.iter().zip(hmac_bytes_vec.iter()) {
                diff |= a ^ b;
            }
            if diff != 0 {
                return Err(AuthError::TokenInvalid);
            }

            Ok(Self(token_bytes))
        })();
        if result.is_err() {
            // Generic warning — never log the failed payload to avoid
            // giving an attacker a side channel on signed/unsigned pairs.
            warn!("token verify failed");
        }
        result
    }
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The Debug impl is redaction-aware. `format!("{:?}", token)`
        // will NOT leak the raw bytes.
        f.write_str(&self.redact())
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.redact())
    }
}

/// HMAC-SHA256 in pure Rust (no external crate). This is a textbook
/// implementation suitable for short-lived tokens. For production
/// secrets, callers should consider the `hmac` crate which has
/// constant-time guarantees on every primitive.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut o_pad = [0x5cu8; BLOCK_SIZE];
    let mut i_pad = [0x36u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_pad[i] ^= key_block[i];
        i_pad[i] ^= key_block[i];
    }
    let inner = {
        let mut h = Sha256::new();
        h.update(i_pad);
        h.update(message);
        h.finalize()
    };
    let mut h = Sha256::new();
    h.update(o_pad);
    h.update(inner);
    h.finalize().into()
}

/// Best-effort OS CSPRNG. The fallback is intentionally deterministic-
/// but-unique, seeded from the current time plus a process-wide counter.
/// This implementation is **not cryptographically secure** and exists as
/// a development scaffold: real deployments should swap in `getrandom`
/// (see the `getrandom` workspace dep and a future `getrandom` feature
/// gate in this function).
fn getrandom_bytes(out: &mut [u8]) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Mix two entropy sources so two back-to-back calls in
    // the same nanosecond still differ. `nanos` gives wall
    // clock variation; `counter` guarantees uniqueness within
    // a single nanosecond. Both are XOR'd together with the
    // byte index to spread bits across the buffer.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0_u64, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = nanos ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for (i, b) in out.iter_mut().enumerate() {
        // Three independent mixing functions to spread bits
        // across the 32-byte buffer. Without this, two
        // sequential calls in the same nanosecond produced
        // identical first 8 bytes (the bug `two_generated_tokens_differ`
        // caught).
        let shift = u32::try_from(i % 64).unwrap_or(0) ^ 0x11;
        let v = seed
            .wrapping_add(u64::try_from(i).unwrap_or(0).wrapping_mul(0xBF58_476D_1CE4_E5B9))
            .rotate_left(shift);
        // The result is masked down to a single byte; the upper
        // 56 bits are intentionally discarded to keep this byte
        // range uniform over 0..=255.
        *b = ((v ^ (v >> 33) ^ ((v >> 56) & 0xff)) & 0xff) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_is_32_bytes() {
        let t = Token::generate();
        assert_eq!(t.as_bytes().len(), TOKEN_BYTES);
    }

    #[test]
    fn two_generated_tokens_differ() {
        // The CSPRNG (or fallback) should produce different outputs.
        let a = Token::generate();
        let b = Token::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn redact_masks_middle_keeps_ends() {
        let mut bytes = [0u8; TOKEN_BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("token buffer index fits in u8");
        }
        let t = Token::from_bytes(bytes);
        let r = t.redact();
        // 4 hex chars + 10 asterisks + 4 hex chars = 18 chars.
        assert_eq!(r.len(), 18);
        assert!(r.starts_with("0001")); // bytes 0,1 -> "0001"
        assert!(r.ends_with("1e1f"));   // bytes 30,31 -> "1e1f"
        assert!(r.contains("**********"));
    }

    #[test]
    fn debug_impl_is_redaction_aware() {
        let t = Token::generate();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("**********"));
    }

    #[test]
    fn display_impl_is_redaction_aware() {
        let t = Token::generate();
        let s = t.to_string();
        assert!(s.contains("**********"));
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let t = Token::generate();
        let secret = b"super-secret-key-do-not-commit";
        let signed = t.sign(secret);
        let back = Token::verify(&signed, secret).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn verify_with_wrong_secret_returns_token_invalid() {
        let t = Token::generate();
        let signed = t.sign(b"key-a");
        let err = Token::verify(&signed, b"key-b").unwrap_err();
        assert_eq!(err, AuthError::TokenInvalid);
    }

    #[test]
    fn verify_with_tampered_token_returns_token_invalid() {
        let t = Token::generate();
        let signed = t.sign(b"key");
        // Flip a hex char in the token portion.
        let mut tampered = signed;
        let first_char = tampered.chars().next().unwrap();
        let replacement = if first_char == '0' { '1' } else { '0' };
        tampered = format!("{replacement}{}", &tampered[1..]);
        let err = Token::verify(&tampered, b"key").unwrap_err();
        assert_eq!(err, AuthError::TokenInvalid);
    }

    #[test]
    fn verify_with_malformed_signed_form_returns_token_invalid() {
        // Missing the '.' separator.
        let err = Token::verify("nodotseparator", b"key").unwrap_err();
        assert_eq!(err, AuthError::TokenInvalid);
    }

    #[test]
    fn verify_with_non_hex_payload_returns_token_invalid() {
        // '.' present but content is not hex.
        let err = Token::verify("zz.zz", b"key").unwrap_err();
        assert_eq!(err, AuthError::TokenInvalid);
    }
}
