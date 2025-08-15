use std::fmt;

/// Custom error type for CodeQL analysis operations
#[derive(Debug)]
pub enum CodeQLError {
    /// Configuration error
    ConfigError(String),

    /// File read error
    FileReadError(String),

    /// File write error
    FileWriteError(String),

    /// JSON parsing error
    JsonParseError(String),

    /// Network/HTTP error
    NetworkError(String),

    /// API error from external services
    ApiError(String),

    /// IO error
    IoError(std::io::Error),

    /// Serialization error
    SerializationError(serde_json::Error),

    /// HTTP client error
    HttpError(reqwest::Error),
}

impl fmt::Display for CodeQLError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeQLError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            CodeQLError::FileReadError(msg) => write!(f, "File read error: {}", msg),
            CodeQLError::FileWriteError(msg) => write!(f, "File write error: {}", msg),
            CodeQLError::JsonParseError(msg) => write!(f, "JSON parsing error: {}", msg),
            CodeQLError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            CodeQLError::ApiError(msg) => write!(f, "API error: {}", msg),
            CodeQLError::IoError(err) => write!(f, "IO error: {}", err),
            CodeQLError::SerializationError(err) => write!(f, "Serialization error: {}", err),
            CodeQLError::HttpError(err) => write!(f, "HTTP error: {}", err),
        }
    }
}

impl std::error::Error for CodeQLError {}

impl From<std::io::Error> for CodeQLError {
    fn from(err: std::io::Error) -> Self {
        CodeQLError::IoError(err)
    }
}

impl From<serde_json::Error> for CodeQLError {
    fn from(err: serde_json::Error) -> Self {
        CodeQLError::SerializationError(err)
    }
}

impl From<reqwest::Error> for CodeQLError {
    fn from(err: reqwest::Error) -> Self {
        CodeQLError::HttpError(err)
    }
}

/// Result type for CodeQL operations
pub type Result<T> = std::result::Result<T, CodeQLError>;
