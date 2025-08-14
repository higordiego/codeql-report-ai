use thiserror::Error;

/// Tipo de erro personalizado para a biblioteca
#[derive(Error, Debug)]
pub enum Error {
    #[error("Erro de I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("Erro de JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Erro de requisição HTTP: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Erro de configuração: {0}")]
    Config(String),

    #[error("Erro do CodeQL: {0}")]
    CodeQL(String),

    #[error("Erro do ChatGPT: {0}")]
    ChatGPT(String),

    #[error("Arquivo não encontrado: {0}")]
    FileNotFound(String),

    #[error("Formato inválido: {0}")]
    InvalidFormat(String),

    #[error("Rate limit excedido")]
    RateLimit,

    #[error("Token limit excedido")]
    TokenLimit,

    #[error("Erro de autenticação: {0}")]
    Authentication(String),

    #[error("Erro interno: {0}")]
    Internal(String),
}

/// Tipo de resultado para a biblioteca
pub type Result<T> = std::result::Result<T, Error>;


