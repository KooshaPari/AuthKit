//! Infrastructure error handling.

use std::fmt;

/// AuthKit-specific errors.
#[derive(Debug)]
pub enum AuthKitError {
    /// Configuration error.
    Config(String),
    /// Initialization error.
    Init(String),
    /// Runtime error.
    Runtime(String),
    /// Security error.
    Security(String),
}

impl fmt::Display for AuthKitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthKitError::Config(msg) => write!(f, "Configuration error: {}", msg),
            AuthKitError::Init(msg) => write!(f, "Initialization error: {}", msg),
            AuthKitError::Runtime(msg) => write!(f, "Runtime error: {}", msg),
            AuthKitError::Security(msg) => write!(f, "Security error: {}", msg),
        }
    }
}

impl std::error::Error for AuthKitError {}
