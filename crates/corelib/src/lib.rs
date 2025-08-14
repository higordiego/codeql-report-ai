//! Biblioteca para análise de resultados CodeQL com ChatGPT
//!
//! Esta biblioteca permite:
//! - Ler resultados JSON do CodeQL
//! - Analisar arquivos de código encontrados nas falhas
//! - Integrar com ChatGPT para análise detalhada
//! - Gerar planos de ação em formato Markdown

pub mod analyzer;
pub mod chatgpt;
pub mod codeql;
pub mod config;
pub mod error;
pub mod logging;
pub mod markdown;
pub mod types;
pub mod utils;

pub use analyzer::CodeQLAnalyzer;
pub use config::Config;
pub use error::{Error, Result};
pub use types::*;

/// Versão da biblioteca
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Re-exportações principais para facilitar o uso
pub mod prelude {
    pub use crate::{
        ChatGPTAnalysis, CodeQLAnalysis, CodeQLAnalyzer, Config, Error, Finding, Recommendation,
        Result,
    };
}
