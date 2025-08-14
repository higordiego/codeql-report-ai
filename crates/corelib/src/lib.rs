//! Biblioteca para análise de resultados CodeQL com ChatGPT
//! 
//! Esta biblioteca permite:
//! - Ler resultados JSON do CodeQL
//! - Analisar arquivos de código encontrados nas falhas
//! - Integrar com ChatGPT para análise detalhada
//! - Gerar planos de ação em formato Markdown

pub mod config;
pub mod types;
pub mod logging;
pub mod error;
pub mod codeql;
pub mod chatgpt;
pub mod analyzer;
pub mod markdown;
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
        CodeQLAnalyzer,
        Config,
        Error,
        Result,
        CodeQLAnalysis,
        ChatGPTAnalysis,
        Finding,
        Recommendation,
    };
}
