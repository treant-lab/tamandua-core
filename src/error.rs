//! Error types for Tamandua Core
//!
//! This module provides a comprehensive error taxonomy for all
//! operations in the Tamandua Core library.

use thiserror::Error;

/// Result type alias for Tamandua Core operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for Tamandua Core
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Platform API error
    #[error("Platform API error: {0}")]
    Platform(String),

    /// Telemetry collection error
    #[error("Telemetry error: {0}")]
    Telemetry(String),

    /// Detection engine error
    #[error("Detection error: {0}")]
    Detection(String),

    /// Response execution error
    #[error("Response error: {0}")]
    Response(String),

    /// Transport/connectivity error
    #[error("Transport error: {0}")]
    Transport(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// YARA error
    #[cfg(feature = "yara-integration")]
    #[error("YARA error: {0}")]
    Yara(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Operation timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Invalid argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Internal error (bug)
    #[error("Internal error: {0}")]
    Internal(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Create a configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a platform error
    pub fn platform(msg: impl Into<String>) -> Self {
        Self::Platform(msg.into())
    }

    /// Create a telemetry error
    pub fn telemetry(msg: impl Into<String>) -> Self {
        Self::Telemetry(msg.into())
    }

    /// Create a detection error
    pub fn detection(msg: impl Into<String>) -> Self {
        Self::Detection(msg.into())
    }

    /// Create a response error
    pub fn response(msg: impl Into<String>) -> Self {
        Self::Response(msg.into())
    }

    /// Create a transport error
    pub fn transport(msg: impl Into<String>) -> Self {
        Self::Transport(msg.into())
    }

    /// Create a permission denied error
    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }

    /// Create a not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    /// Create a timeout error
    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    /// Create an invalid argument error
    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        Self::InvalidArgument(msg.into())
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Transport(_) | Error::Timeout(_) | Error::Io(_))
    }

    /// Check if error indicates a transient failure
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Transport(_) | Error::Timeout(_))
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Other(err.to_string())
    }
}

#[cfg(feature = "yara-integration")]
impl From<yara::Error> for Error {
    fn from(err: yara::Error) -> Self {
        Error::Yara(err.to_string())
    }
}
