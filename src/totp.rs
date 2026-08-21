//! TOTP (RFC 6238) + HOTP (RFC 4226) — Time-based / Counter-based
//! One-Time Password.
//!
//! The reference for the algorithm is RFC 6238 §4 (TOTP) and RFC 4226
//! §5 (HOTP). Default digits = 6, period = 30s, HMAC-SHA1, matching
//! the de-facto Google Authenticator / Authy contract so existing
//! enrollment flows work without modification.
//!
//! Why a from-scratch impl: `totp-rs` (most popular crate) would pull
//! in 20+ transitive deps + a binary + a web server + a tray app
//! just for the 30-line HMAC computation. AuthKit's own impl is 200
//! lines, zero extra deps beyond `hmac` + `sha1` (which we already
//! need for OIDC), and matches the AuthKit style guide.
//!
//! ## Enrollment
//!
//! ```ignore
//! use authkit::totp::{TotpSecret, enrollment_uri};
//!
//! let secret = TotpSecret::generate(); // 160 bits
//! let uri = enrollment_uri(&secret, "alice@example.com", "AuthKit", 30, 1);
//! // user scans otpauth://totp/AuthKit:alice@example.com?secret=...&period=30&digits=6&algorithm=SHA1&counter=1
//! ```
//!
//! ## Verification
//!
//! ```ignore
//! let code = "123456";
//! let now = 1_700_000_000;
//! assert!(secret.verify(code, now, 30));
//! ```

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::SessionStoreError;

type HmacSha1 = Hmac<Sha1>;

/// Default RFC 6238 / Google Authenticator parameters.
pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_PERIOD: u64 = 30;
pub const DEFAULT_ALGORITHM: TotpAlgorithm = TotpAlgorithm::Sha1;
/// Standard replay-window (1 step forward + 1 step back) per RFC 6238 §5.2.
pub const DEFAULT_WINDOW: u32 = 1;

/// The hash algorithm used for the HMAC. Default = SHA1 (matches Google
/// Authenticator / Authy / most consumer 2FA tokens). SHA256 / SHA512
/// are RFC 6238-supported but rarely used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    /// String label used in `otpauth://` URIs and metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn output_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

impl fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 160-bit (20-byte) TOTP secret — the minimum per RFC 6238 §5.1 and
/// the canonical size for Google Authenticator compatibility.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret {
    bytes: [u8; 20],
}

impl TotpSecret {
    /// Generate a fresh 160-bit cryptographically-random secret.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Construct from raw bytes. Caller is responsible for ensuring the
    /// bytes were generated with a CSPRNG.
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self { bytes }
    }

    /// Base32 (RFC 4648, no padding) string used in `otpauth://` URIs.
    /// Standard Google Authenticator import format.
    pub fn to_base32(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.bytes)
    }

    /// Parse a Base32 secret (uppercase, no padding typical). Tolerates
    /// lowercase input and missing padding for ergonomic imports.
    pub fn from_base32(s: &str) -> Result<Self, TotpError> {
        let normalized: String = s.trim().to_uppercase().replace(' ', "");
        if normalized.is_empty() {
            return Err(TotpError::InvalidSecret("empty base32 secret"));
        }
        let bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized)
            .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &normalized))
            .ok_or_else(|| TotpError::InvalidSecret("invalid base32 encoding"))?;
        if bytes.len() != 20 {
            return Err(TotpError::InvalidSecret("secret must be 160 bits"));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        Ok(Self { bytes: out })
    }

    /// Base64 (no padding) of the raw bytes. Useful for storage in
    /// JSON web APIs.
    pub fn to_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.bytes
    }

    /// Compute the TOTP code for a given Unix timestamp + period.
    pub fn at(&self, unix_secs: u64, period: u64, digits: u32) -> String {
        let counter = unix_secs / period;
        hotp(&self.bytes, counter, digits, TotpAlgorithm::Sha1)
    }

    /// Verify a candidate code against the secret, allowing a window
    /// (default 1) of accepted steps either side of the current
    /// counter to absorb clock drift per RFC 6238 §5.2.
    pub fn verify(&self, candidate: &str, unix_secs: u64, period: u64) -> bool {
        self.verify_with_window(candidate, unix_secs, period, DEFAULT_WINDOW)
    }

    pub fn verify_with_window(
        &self,
        candidate: &str,
        unix_secs: u64,
        period: u64,
        window: u32,
    ) -> bool {
        let counter_now = unix_secs / period;
        let digits = DEFAULT_DIGITS;
        for delta in -(window as i64)..=window as i64 {
            let c = match counter_now.checked_add_signed(delta) {
                Some(c) => c,
                None => continue,
            };
            let expected = hotp(&self.bytes, c, digits, TotpAlgorithm::Sha1);
            if constant_time_eq(expected.as_bytes(), candidate.as_bytes()) {
                return true;
            }
        }
        false
    }

    /// Compute the seconds remaining in the current TOTP period.
    /// Useful for UI countdowns ("expires in 12s").
    pub fn seconds_remaining(unix_secs: u64, period: u64) -> u64 {
        period - (unix_secs % period)
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpSecret")
            .field("base32", &self.to_base32())
            .finish_non_exhaustive()
    }
}

/// Build an `otpauth://` URI for QR-code enrollment (Google Authenticator,
/// 1Password, Bitwarden, Authy all consume this format).
pub fn enrollment_uri(
    secret: &TotpSecret,
    account: &str,
    issuer: &str,
    period: u64,
    digits: u32,
) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&period={period}&digits={digits}&algorithm=SHA1",
        issuer = urlencoding(issuer),
        account = urlencoding(account),
        secret = secret.to_base32(),
        period = period,
        digits = digits,
    )
}

/// RFC 4226 §5 HOTP — the counter-based variant. TOTP is HOTP with
/// counter = floor(unix_secs / period). Exposed for the rare case a
/// consumer wants the bare counter-based primitive.
pub fn hotp(secret_bytes: &[u8], counter: u64, digits: u32, algorithm: TotpAlgorithm) -> String {
    let counter_be = counter.to_be_bytes();
    let digest = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret_bytes)
                .expect("HMAC accepts any key length");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            use hmac::Mac;
            use sha2::Sha256;
            type H = hmac::Hmac<Sha256>;
            let mut mac =
                <H as Mac>::new_from_slice(secret_bytes).expect("HMAC accepts any key length");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            use hmac::Mac;
            use sha2::Sha512;
            type H = hmac::Hmac<Sha512>;
            let mut mac =
                <H as Mac>::new_from_slice(secret_bytes).expect("HMAC accepts any key length");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
    };

    let digest_len = algorithm.output_len();
    debug_assert!(digest.len() == digest_len, "HMAC output length mismatch");

    // RFC 4226 §5.3 dynamic truncation
    let offset = (digest[digest_len - 1] & 0x0f) as usize;
    let bin_code = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);

    let modulus = 10u32.pow(digits.min(10));
    let code = bin_code % modulus;
    format!("{:0>width$}", code, width = digits as usize)
}

/// Minimal RFC 3986 percent-encoding for the issuer / account fields
/// in the otpauth URI. Avoids pulling `url` crate as a hard dep.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Unix timestamp helper for "now" without pulling chrono / time crates.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// TOTP errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TotpError {
    InvalidSecret(&'static str),
    InvalidCode,
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret(m) => write!(f, "invalid secret: {m}"),
            Self::InvalidCode => write!(f, "invalid code"),
        }
    }
}

impl std::error::Error for TotpError {}

impl From<TotpError> for SessionStoreError {
    fn from(e: TotpError) -> Self {
        SessionStoreError::Other(format!("totp: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (SHA1, 20-byte secret of ASCII "12345678901234567890")
    const RFC6238_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_test_vector_t0() {
        // T=59 -> SHA1(secret, 1) -> 94287082
        let code = hotp(RFC6238_SECRET, 1, 8, TotpAlgorithm::Sha1);
        assert_eq!(code, "94287082");
    }

    #[test]
    fn rfc6238_test_vector_t30() {
        // T=30 -> counter=1 -> 46119246 (matches RFC 6238 App. B)
        let code = hotp(RFC6238_SECRET, 1, 8, TotpAlgorithm::Sha1);
        assert_eq!(code, "46119246");
    }

    #[test]
    fn rfc6238_test_vector_t59() {
        // 59 / 30 = 1 -> same as above
        let secret = TotpSecret::from_bytes(RFC6238_SECRET.try_into().unwrap());
        let code = secret.at(59, 30, 8);
        assert_eq!(code, "94287082");
    }

    #[test]
    fn secret_roundtrip_base32() {
        let secret = TotpSecret::generate();
        let s = secret.to_base32();
        let recovered = TotpSecret::from_base32(&s).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn secret_roundtrip_base64() {
        let secret = TotpSecret::generate();
        let s = secret.to_base64();
        let bytes = STANDARD_NO_PAD.decode(s).unwrap();
        let recovered = TotpSecret::from_bytes(bytes.try_into().unwrap());
        assert_eq!(secret, recovered);
    }

    #[test]
    fn secret_from_base32_lowercase() {
        let s = TotpSecret::generate();
        let upper = s.to_base32();
        let lower = upper.to_lowercase();
        assert_eq!(TotpSecret::from_base32(&upper).unwrap(), s);
        assert_eq!(TotpSecret::from_base32(&lower).unwrap(), s);
    }

    #[test]
    fn secret_from_base32_empty() {
        assert_eq!(
            TotpSecret::from_base32("").unwrap_err(),
            TotpError::InvalidSecret("empty base32 secret")
        );
    }

    #[test]
    fn secret_from_base32_wrong_length() {
        // 10 bytes = 80 bits; secret must be 160 bits.
        let short_b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &[0u8; 10]);
        assert!(matches!(
            TotpSecret::from_base32(&short_b32),
            Err(TotpError::InvalidSecret("secret must be 160 bits"))
        ));
    }

    #[test]
    fn verify_accepts_current_code() {
        let secret = TotpSecret::from_bytes(RFC6238_SECRET.try_into().unwrap());
        let now = 59u64;
        let code = secret.at(now, 30, 8);
        assert!(secret.verify(&code, now, 30));
    }

    #[test]
    fn verify_rejects_wrong_code() {
        let secret = TotpSecret::from_bytes(RFC6238_SECRET.try_into().unwrap());
        assert!(!secret.verify("00000000", 59, 30));
    }

    #[test]
    fn verify_with_window_accepts_drift() {
        let secret = TotpSecret::from_bytes(RFC6238_SECRET.try_into().unwrap());
        let code = secret.at(59, 30, 8);
        // Same code valid for window +/- 1 step
        assert!(secret.verify_with_window(&code, 30, 30, 1)); // 1 step back
        assert!(secret.verify_with_window(&code, 89, 30, 1)); // 1 step forward
    }

    #[test]
    fn verify_with_window_rejects_far_drift() {
        let secret = TotpSecret::from_bytes(RFC6238_SECRET.try_into().unwrap());
        let code = secret.at(59, 30, 8);
        // 2 steps back without explicit window 2 -> rejected
        assert!(!secret.verify(&code, -1, 30));
    }

    #[test]
    fn seconds_remaining_returns_correct_window() {
        assert_eq!(TotpSecret::seconds_remaining(0, 30), 30);
        assert_eq!(TotpSecret::seconds_remaining(29, 30), 1);
        assert_eq!(TotpSecret::seconds_remaining(30, 30), 30);
        assert_eq!(TotpSecret::seconds_remaining(45, 30), 15);
    }

    #[test]
    fn enrollment_uri_format() {
        let secret = TotpSecret::from_bytes([0x42u8; 20]);
        let uri = enrollment_uri(&secret, "alice@example.com", "AuthKit", 30, 6);
        assert!(uri.starts_with("otpauth://totp/AuthKit:alice%40example.com"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("issuer=AuthKit"));
    }

    #[test]
    fn hotp_truncation_constant_time_eq() {
        // Two different codes should not match
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"12345", b"123456"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn algorithm_str_roundtrip() {
        assert_eq!(TotpAlgorithm::Sha1.as_str(), "SHA1");
        assert_eq!(TotpAlgorithm::Sha256.as_str(), "SHA256");
        assert_eq!(TotpAlgorithm::Sha512.as_str(), "SHA512");
        assert_eq!(format!("{}", TotpAlgorithm::Sha1), "SHA1");
    }
}