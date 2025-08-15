//! Code Report - Advanced Security Analysis with AI Integration
//!
//! This library provides tools for analyzing CodeQL results and generating comprehensive security reports
//! using ChatGPT AI integration. It supports multiple report levels and automatic code correction generation.
//!
//! ## Features
//!
//! - **CodeQL Integration**: Parse and analyze CodeQL static analysis results
//! - **AI-Powered Analysis**: Generate detailed security reports using ChatGPT
//! - **Multiple Report Levels**: Easy, medium, and advanced report formats
//! - **Code Generation**: Automatically generate corrected code for identified vulnerabilities
//! - **Configurable**: Flexible configuration options for different use cases
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use codeql_corelib::{CodeQLAnalyzer, Config};
//!
//! #[tokio::main]
//! async fn main() -> codeql_corelib::Result<()> {
//!     let config = Config::default();
//!     let analyzer = CodeQLAnalyzer::new(config)?;
//!     
//!     analyzer.analyze("results.json").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Report Levels
//!
//! - **Easy**: Basic statistics and findings summary
//! - **Medium**: Detailed analysis with code snippets and explanations
//! - **Advanced**: Comprehensive report with correction recommendations
//!
//! ## Code Generation
//!
//! The library can automatically generate corrected code for identified vulnerabilities:
//!
//! ```rust,no_run
//! use codeql_corelib::{CodeQLAnalyzer, Config};
//!
//! #[tokio::main]
//! async fn main() -> codeql_corelib::Result<()> {
//!     let config = Config::default();
//!     let analyzer = CodeQLAnalyzer::new(config)?;
//!     
//!     analyzer.generate_fixed_code("results.json", "fixed_code.py").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Configuration
//!
//! Configure the analyzer using environment variables or programmatically:
//!
//! ```rust
//! use codeql_corelib::Config;
//! use std::path::PathBuf;
//!
//! let config = Config {
//!     openai_api_key: "your-api-key".to_string(),
//!     model: "gpt-3.5-turbo".to_string(),
//!     project_root: PathBuf::from("."),
//!     output_file: PathBuf::from("report.md"),
//!     include_fixes: true,
//!     report_level: "advanced".to_string(),
//!     temperature: 0.8,
//!     timeout_seconds: 120,
//!     openai_base_url: "https://api.openai.com/v1/chat/completions".to_string(),
//!     max_file_bytes: 350_000,
//!     max_payload_tokens: 120_000,
//!     chunk_target_tokens: 3_000,
//!     rate_limit_rps: 30,
//! };
//! ```

pub mod analyzer;
pub mod chatgpt;
pub mod config;
pub mod error;
pub mod types;

pub use analyzer::CodeQLAnalyzer;
pub use config::Config;
pub use error::{CodeQLError, Result};
pub use types::*;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration values
pub mod defaults {
    /// Default OpenAI API base URL
    pub const OPENAI_BASE_URL: &str = "https://api.openai.com/v1/chat/completions";

    /// Default ChatGPT model
    pub const DEFAULT_MODEL: &str = "gpt-3.5-turbo";

    /// Default temperature for ChatGPT
    pub const DEFAULT_TEMPERATURE: f32 = 0.8;

    /// Default maximum file size in bytes
    pub const DEFAULT_MAX_FILE_BYTES: usize = 350_000;

    /// Default maximum payload tokens
    pub const DEFAULT_MAX_PAYLOAD_TOKENS: usize = 120_000;

    /// Default chunk target tokens
    pub const DEFAULT_CHUNK_TARGET_TOKENS: usize = 3_000;

    /// Default rate limit requests per second
    pub const DEFAULT_RATE_LIMIT_RPS: u32 = 30;

    /// Default timeout in seconds
    pub const DEFAULT_TIMEOUT_SECONDS: u64 = 120;

    /// Default output file name
    pub const DEFAULT_OUTPUT_FILE: &str = "codeql-analysis-report.md";

    /// Default report level
    pub const DEFAULT_REPORT_LEVEL: &str = "medium";
}

/// Utility functions for common operations
pub mod utils {
    use std::path::Path;

    /// Validates if a file path is safe for processing
    pub fn is_safe_file_path(path: &Path) -> bool {
        // Check for path traversal attempts
        let path_str = path.to_string_lossy();
        !path_str.contains("..") && !path_str.contains("~")
    }

    /// Sanitizes a file path for safe processing
    pub fn sanitize_file_path(path: &str) -> String {
        path.replace("..", "").replace("~", "").replace("\\", "/")
    }

    /// Estimates token count for a text string
    pub fn estimate_tokens(text: &str) -> usize {
        // Rough estimation: 1 token ≈ 4 characters
        text.len() / 4
    }

    /// Formats file size in human-readable format
    pub fn format_file_size(bytes: usize) -> String {
        const KB: usize = 1024;
        const MB: usize = KB * 1024;
        const GB: usize = MB * 1024;

        match bytes {
            0..KB => format!("{} B", bytes),
            KB..MB => format!("{:.1} KB", bytes as f64 / KB as f64),
            MB..GB => format!("{:.1} MB", bytes as f64 / MB as f64),
            _ => format!("{:.1} GB", bytes as f64 / GB as f64),
        }
    }
}

/// Security-related utilities and constants
pub mod security {
    /// Common dangerous patterns for input validation
    pub const DANGEROUS_PATTERNS: &[&str] = &[
        r"[;&|`$]",     // Command separators
        r"\.\./",       // Path traversal
        r"rm\s+-rf",    // Dangerous rm command
        r"sudo",        // Privilege escalation
        r"chmod\s+777", // Dangerous permissions
    ];

    /// Safe command execution patterns
    pub const SAFE_COMMANDS: &[&str] = &[
        "ls", "pwd", "whoami", "date", "echo", "cat", "grep", "head", "tail",
    ];

    /// Validates if a command is considered safe
    pub fn is_safe_command(command: &str) -> bool {
        let command_parts: Vec<&str> = command.split_whitespace().collect();
        if let Some(first_part) = command_parts.first() {
            SAFE_COMMANDS.contains(first_part)
        } else {
            false
        }
    }

    /// Validates input for dangerous patterns
    pub fn validate_input(input: &str) -> bool {
        for pattern in DANGEROUS_PATTERNS {
            if regex::Regex::new(pattern).unwrap().is_match(input) {
                return false;
            }
        }
        true
    }
}
