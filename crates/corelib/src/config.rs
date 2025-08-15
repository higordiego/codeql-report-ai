use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the CodeQL analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// OpenAI API key for ChatGPT integration
    pub openai_api_key: String,

    /// ChatGPT model to use (e.g., "gpt-3.5-turbo", "gpt-4")
    pub model: String,

    /// Project root directory for analysis
    pub project_root: PathBuf,

    /// Output file path for the generated report
    pub output_file: PathBuf,

    /// Whether to include code correction suggestions in the report
    pub include_fixes: bool,

    /// Report level (easy, medium, advanced)
    pub report_level: String,

    /// OpenAI API base URL
    pub openai_base_url: String,

    /// Temperature setting for ChatGPT (0.0 to 2.0)
    pub temperature: f32,

    /// Maximum file size in bytes for processing
    pub max_file_bytes: usize,

    /// Maximum payload tokens for API requests
    pub max_payload_tokens: usize,

    /// Target tokens per chunk for processing
    pub chunk_target_tokens: usize,

    /// Rate limit requests per second
    pub rate_limit_rps: u32,

    /// Timeout in seconds for API requests
    pub timeout_seconds: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            openai_api_key: "sk-demo-key-for-development".to_string(),
            model: "gpt-3.5-turbo".to_string(),
            project_root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            output_file: PathBuf::from("codeql-analysis-report.md"),
            include_fixes: false,
            report_level: "medium".to_string(),
            openai_base_url: "https://api.openai.com/v1/chat/completions".to_string(),
            temperature: 0.8,
            max_file_bytes: 350000,
            max_payload_tokens: 120000,
            chunk_target_tokens: 3000,
            rate_limit_rps: 30,
            timeout_seconds: 120,
        }
    }
}

impl Config {
    /// Creates a new configuration from environment variables
    pub fn from_env() -> crate::Result<Self> {
        let openai_api_key = std::env::var("OPENAI_API_KEY")
            .unwrap_or_else(|_| "sk-demo-key-for-development".to_string());

        let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-3.5-turbo".to_string());

        let project_root = std::env::current_dir().map_err(|e| {
            crate::error::CodeQLError::ConfigError(format!(
                "Failed to get current directory: {}",
                e
            ))
        })?;

        let output_file = PathBuf::from(
            std::env::var("OUTPUT_FILE")
                .unwrap_or_else(|_| "codeql-analysis-report.md".to_string()),
        );

        let include_fixes = std::env::var("INCLUDE_FIXES")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let report_level = std::env::var("REPORT_LEVEL").unwrap_or_else(|_| "medium".to_string());

        let openai_base_url = std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1/chat/completions".to_string());

        let temperature = std::env::var("OPENAI_TEMPERATURE")
            .unwrap_or_else(|_| "0.8".to_string())
            .parse()
            .unwrap_or(0.8);

        let max_file_bytes = std::env::var("MAX_FILE_BYTES")
            .unwrap_or_else(|_| "350000".to_string())
            .parse()
            .unwrap_or(350000);

        let max_payload_tokens = std::env::var("MAX_PAYLOAD_TOKENS")
            .unwrap_or_else(|_| "120000".to_string())
            .parse()
            .unwrap_or(120000);

        let chunk_target_tokens = std::env::var("CHUNK_TARGET_TOKENS")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .unwrap_or(3000);

        let rate_limit_rps = std::env::var("RATE_LIMIT_RPS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .unwrap_or(30);

        let timeout_seconds = std::env::var("TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "120".to_string())
            .parse()
            .unwrap_or(120);

        Ok(Config {
            openai_api_key,
            model,
            project_root,
            output_file,
            include_fixes,
            report_level,
            openai_base_url,
            temperature,
            max_file_bytes,
            max_payload_tokens,
            chunk_target_tokens,
            rate_limit_rps,
            timeout_seconds,
        })
    }

    /// Validates the configuration
    pub fn validate(&self) -> crate::Result<()> {
        if self.openai_api_key.is_empty() {
            return Err(crate::error::CodeQLError::ConfigError(
                "OpenAI API key is required".to_string(),
            ));
        }

        if self.temperature < 0.0 || self.temperature > 2.0 {
            return Err(crate::error::CodeQLError::ConfigError(
                "Temperature must be between 0.0 and 2.0".to_string(),
            ));
        }

        if self.max_file_bytes == 0 {
            return Err(crate::error::CodeQLError::ConfigError(
                "Max file bytes must be greater than 0".to_string(),
            ));
        }

        if self.max_payload_tokens == 0 {
            return Err(crate::error::CodeQLError::ConfigError(
                "Max payload tokens must be greater than 0".to_string(),
            ));
        }

        if self.chunk_target_tokens == 0 {
            return Err(crate::error::CodeQLError::ConfigError(
                "Chunk target tokens must be greater than 0".to_string(),
            ));
        }

        if self.rate_limit_rps == 0 {
            return Err(crate::error::CodeQLError::ConfigError(
                "Rate limit RPS must be greater than 0".to_string(),
            ));
        }

        if self.timeout_seconds == 0 {
            return Err(crate::error::CodeQLError::ConfigError(
                "Timeout seconds must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.report_level, "medium");
        assert_eq!(config.model, "gpt-3.5-turbo");
        assert_eq!(config.temperature, 0.8);
        assert_eq!(config.timeout_seconds, 120);
        assert_eq!(
            config.openai_base_url,
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn test_config_from_env() {
        // Test only one environment variable to avoid conflicts
        env::set_var("OPENAI_API_KEY", "test-key");

        let config = Config::from_env().unwrap();
        assert_eq!(config.openai_api_key, "test-key");

        env::remove_var("OPENAI_API_KEY");
    }

    #[test]
    fn test_config_from_env_with_defaults() {
        // Clean up any existing environment variables first
        env::remove_var("REPORT_LEVEL");
        env::remove_var("OPENAI_API_KEY");
        env::remove_var("OPENAI_MODEL");
        env::remove_var("OPENAI_TEMPERATURE");
        env::remove_var("TIMEOUT_SECONDS");
        env::remove_var("OPENAI_BASE_URL");

        // Don't set any environment variables
        let config = Config::from_env().unwrap();

        assert_eq!(config.report_level, "medium");
        assert_eq!(config.model, "gpt-3.5-turbo");
        assert_eq!(config.temperature, 0.8);
        assert_eq!(config.timeout_seconds, 120);
        assert_eq!(
            config.openai_base_url,
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn test_config_invalid_temperature() {
        env::set_var("OPENAI_TEMPERATURE", "invalid");

        let result = Config::from_env();
        assert!(result.is_ok()); // Should use default value instead of error

        env::remove_var("OPENAI_TEMPERATURE");
    }

    #[test]
    fn test_config_invalid_timeout() {
        env::set_var("TIMEOUT_SECONDS", "invalid");

        let result = Config::from_env();
        assert!(result.is_ok()); // Should use default value instead of error

        env::remove_var("TIMEOUT_SECONDS");
    }
}
