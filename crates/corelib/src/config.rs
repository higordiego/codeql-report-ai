use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuração para a análise de CodeQL com ChatGPT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Chave da API do OpenAI
    pub openai_api_key: String,

    /// URL base da API do OpenAI
    #[serde(default = "default_openai_url")]
    pub openai_base_url: String,

    /// Modelo do ChatGPT a ser usado
    #[serde(default = "default_model")]
    pub model: String,

    /// Temperatura para geração de respostas
    #[serde(default = "default_temperature")]
    pub temperature: f32,

    /// Diretório raiz do projeto
    pub project_root: PathBuf,

    /// Tamanho máximo de arquivo em bytes
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,

    /// Limite total de tokens para o payload
    #[serde(default = "default_max_payload_tokens")]
    pub max_payload_tokens: usize,

    /// Alvo de tokens por chunk
    #[serde(default = "default_chunk_target_tokens")]
    pub chunk_target_tokens: usize,

    /// Rate limit em requisições por segundo
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u32,

    /// Timeout para requisições HTTP em segundos
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    /// Arquivo de saída para o relatório Markdown
    pub output_file: PathBuf,
}

impl Config {
    /// Cria uma nova configuração a partir de variáveis de ambiente
    pub fn from_env() -> crate::Result<Self> {
        let openai_api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| crate::Error::Config("OPENAI_API_KEY não encontrada".to_string()))?;

        let project_root = std::env::var("PROJECT_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        let output_file = std::env::var("OUTPUT_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("codeql-analysis-report.md"));

        Ok(Config {
            openai_api_key,
            openai_base_url: std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| default_openai_url()),
            model: std::env::var("OPENAI_MODEL").unwrap_or_else(|_| default_model()),
            temperature: std::env::var("OPENAI_TEMPERATURE")
                .unwrap_or_else(|_| default_temperature().to_string())
                .parse()
                .unwrap_or(default_temperature()),
            project_root,
            max_file_bytes: std::env::var("MAX_FILE_BYTES")
                .unwrap_or_else(|_| default_max_file_bytes().to_string())
                .parse()
                .unwrap_or(default_max_file_bytes()),
            max_payload_tokens: std::env::var("MAX_PAYLOAD_TOKENS")
                .unwrap_or_else(|_| default_max_payload_tokens().to_string())
                .parse()
                .unwrap_or(default_max_payload_tokens()),
            chunk_target_tokens: std::env::var("CHUNK_TARGET_TOKENS")
                .unwrap_or_else(|_| default_chunk_target_tokens().to_string())
                .parse()
                .unwrap_or(default_chunk_target_tokens()),
            rate_limit_rps: std::env::var("RATE_LIMIT_RPS")
                .unwrap_or_else(|_| default_rate_limit_rps().to_string())
                .parse()
                .unwrap_or(default_rate_limit_rps()),
            timeout_seconds: std::env::var("TIMEOUT_SECONDS")
                .unwrap_or_else(|_| default_timeout_seconds().to_string())
                .parse()
                .unwrap_or(default_timeout_seconds()),
            output_file,
        })
    }

    /// Valida a configuração
    pub fn validate(&self) -> crate::Result<()> {
        if self.openai_api_key.is_empty() {
            return Err(crate::Error::Config(
                "OPENAI_API_KEY não pode estar vazia".to_string(),
            ));
        }

        if !self.project_root.exists() {
            return Err(crate::Error::Config(format!(
                "Diretório do projeto não existe: {:?}",
                self.project_root
            )));
        }

        if self.temperature < 0.0 || self.temperature > 2.0 {
            return Err(crate::Error::Config(
                "Temperatura deve estar entre 0.0 e 2.0".to_string(),
            ));
        }

        if self.rate_limit_rps == 0 {
            return Err(crate::Error::Config(
                "Rate limit deve ser maior que 0".to_string(),
            ));
        }

        Ok(())
    }
}

// Funções de default
fn default_openai_url() -> String {
    "https://api.openai.com/v1/chat/completions".to_string()
}

fn default_model() -> String {
    "gpt-3.5-turbo".to_string()
}

fn default_temperature() -> f32 {
    0.2
}

fn default_max_file_bytes() -> usize {
    350_000 // ~350 KB
}

fn default_max_payload_tokens() -> usize {
    120_000
}

fn default_chunk_target_tokens() -> usize {
    3_000
}

fn default_rate_limit_rps() -> u32 {
    2
}

fn default_timeout_seconds() -> u64 {
    30
}
