//! Configuração e utilitários de logging

use tracing::Level;
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    FmtSubscriber,
};

/// Configura o sistema de logging
pub fn setup_logging(level: Level) -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_timer(UtcTime::rfc_3339())
        .with_span_events(FmtSpan::CLOSE)
        .with_max_level(level)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

/// Configura logging com nível padrão (info)
pub fn setup_default_logging() -> Result<(), Box<dyn std::error::Error>> {
    setup_logging(Level::INFO)
}

/// Configura logging para debug
pub fn setup_debug_logging() -> Result<(), Box<dyn std::error::Error>> {
    setup_logging(Level::DEBUG)
}

/// Configura logging para trace completo
pub fn setup_trace_logging() -> Result<(), Box<dyn std::error::Error>> {
    setup_logging(Level::TRACE)
}
