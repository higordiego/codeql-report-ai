use clap::{Parser, Subcommand};
use codeql_corelib::{CodeQLAnalyzer, Config, Result};
use colored::*;
use std::path::PathBuf;
use tracing::{info, Level};

fn print_banner(show_quick_start: bool) {
    // Espaços no top para melhor visualização das cores
    println!();
    println!();
    println!();

    // Banner do Code Report
    println!(
        "{}",
        "   ██████╗ ██████╗ ██████╗ ███████╗    ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗"
            .bright_blue()
    );
    println!(
        "{}",
        "  ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝"
            .bright_blue()
    );
    println!(
        "{}",
        "  ██║     ██║   ██║██║  ██║█████╗      ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║   "
            .bright_blue()
    );
    println!(
        "{}",
        "  ██║     ██║   ██║██║  ██║██╔══╝      ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║   "
            .bright_blue()
    );
    println!(
        "{}",
        "  ╚██████╗╚██████╔╝██████╔╝███████╗    ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║   "
            .bright_blue()
    );
    println!(
        "{}",
        "   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   "
            .bright_blue()
    );
    println!();
    println!(
        "{}",
        "                    🔍 Advanced Security Analysis Tool".bright_white()
    );
    println!(
        "{}",
        "                    🤖 Powered by AI & Static Analysis".bright_white()
    );
    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════════════════╗"
            .bright_blue()
    );
    println!(
        "{}",
        "║  🛡️  Security Analysis | 🔍 Static Analysis | 🤖 AI-Powered | 📊 Reports  ║"
            .bright_cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════════════╝"
            .bright_blue()
    );
    println!();
    println!("{}", "🚀 Initializing Code Report v1.0.0...".bright_green());
    println!();

    if show_quick_start {
        // Dicas de uso para desenvolvedores
        println!("{}", "💡 Quick Start:".bright_yellow());
        println!("{}", "   ./codeql-ai -i results.json -p .".bright_white());
        println!(
            "{}",
            "   ./codeql-ai -i results.json -p . -v debug".bright_white()
        );
        println!("{}", "   ./codeql-ai --help".bright_white());
        println!();
    }
}

#[derive(Parser)]
#[command(
    name = "codeql-ai",
    about = "🔍 Code Report - Advanced CodeQL Analysis with AI Integration",
    version,
    long_about = "Code Report is a professional security analysis tool that combines CodeQL static analysis with ChatGPT AI to generate comprehensive security reports and action plans in Markdown format.",
    after_help = "💡 Examples:\n  ./codeql-ai -i results.json\n  ./codeql-ai -i results.json -o report.md\n  ./codeql-ai -i results.json -v debug\n  ./codeql-ai fix -i results.json -p . -o fixed_code.py"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Arquivo JSON com resultados do CodeQL
    #[arg(short, long, value_name = "FILE", help_heading = "INPUT")]
    input: Option<PathBuf>,

    /// Diretório raiz do projeto
    #[arg(short, long, value_name = "PATH", help_heading = "CONFIGURATION")]
    project_root: Option<PathBuf>,

    /// Arquivo de saída para o relatório
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value = "codeql-analysis-report.md",
        help_heading = "OUTPUT"
    )]
    output: PathBuf,

    /// Chave da API do OpenAI (opcional, usa OPENAI_API_KEY env var ou demo key)
    #[arg(long, value_name = "KEY", help_heading = "API")]
    openai_api_key: Option<String>,

    /// Modelo do ChatGPT a ser usado
    #[arg(
        long,
        value_name = "MODEL",
        default_value = "gpt-3.5-turbo",
        help_heading = "AI"
    )]
    model: String,

    /// Nível de verbosidade
    #[arg(
        short,
        long,
        value_name = "LEVEL",
        default_value = "info",
        help_heading = "LOGGING"
    )]
    verbosity: Option<Level>,

    /// Incluir sugestões de código corrigido no relatório
    #[arg(short, long, help_heading = "ANALYSIS")]
    include_fixes: bool,

    /// Nível do relatório (easy, medium, advanced)
    #[arg(
        short,
        long,
        value_name = "LEVEL",
        default_value = "medium",
        help_heading = "ANALYSIS"
    )]
    report_level: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Gera código corrigido baseado nas vulnerabilidades encontradas
    Fix {
        /// Arquivo JSON com resultados do CodeQL
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Diretório raiz do projeto
        #[arg(short, long, value_name = "PATH")]
        project_root: PathBuf,

        /// Arquivo de saída para o código corrigido
        #[arg(short, long, value_name = "FILE", default_value = "fixed_code.py")]
        output: PathBuf,

        /// Chave da API do OpenAI (opcional)
        #[arg(long, value_name = "KEY")]
        openai_api_key: Option<String>,

        /// Modelo do ChatGPT a ser usado
        #[arg(long, value_name = "MODEL", default_value = "gpt-3.5-turbo")]
        model: String,

        /// Nível de verbosidade
        #[arg(short, long, value_name = "LEVEL", default_value = "info")]
        verbosity: Option<Level>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse dos argumentos CLI
    let cli = Cli::parse();

    // Configura logging se verbosidade for maior que info (incluindo -v)
    if let Some(verbosity) = cli.verbosity {
        if verbosity > Level::INFO {
            tracing_subscriber::fmt().with_max_level(verbosity).init();
        }
    }

    // Mostra o banner (sem Quick Start quando há comando)
    let show_quick_start = cli.input.is_none();
    print_banner(show_quick_start);

    // Log apenas se verbosidade for maior que info (incluindo -v)
    if let Some(verbosity) = cli.verbosity {
        if verbosity > Level::INFO {
            info!("🚀 Code Report initialized");
        }
    }

    // Obtém a chave da API do OpenAI (com fallback para desenvolvimento)
    let openai_api_key = cli
        .openai_api_key
        .or_else(|| std::env::var("OPENAI_API_KEY").ok())
        .unwrap_or_else(|| "sk-demo-key-for-development".to_string());

    // Guarda o caminho do output para usar depois
    let output_path = cli.output.clone();

    // Cria configuração
    let config =
        match Config::from_env() {
            Ok(mut config) => {
                config.openai_api_key = openai_api_key;
                config.model = cli.model;
                config.project_root = cli.project_root.clone().unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                config.output_file = cli.output;
                config.include_fixes = cli.include_fixes;
                config.report_level = cli.report_level;
                config
            }
            Err(_) => Config {
                openai_api_key,
                model: cli.model,
                project_root: cli.project_root.clone().unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                }),
                output_file: cli.output,
                include_fixes: cli.include_fixes,
                report_level: cli.report_level,
                openai_base_url: "https://api.openai.com/v1/chat/completions".to_string(),
                temperature: 0.8,
                max_file_bytes: 350000,
                max_payload_tokens: 120000,
                chunk_target_tokens: 3000,
                rate_limit_rps: 30,
                timeout_seconds: 120,
            },
        };

    // Cria o analisador (sem logs visíveis)
    let analyzer = CodeQLAnalyzer::new(config)?;

    // Verifica se foi fornecido um comando específico
    match &cli.command {
        Some(Commands::Fix {
            input,
            project_root,
            output,
            openai_api_key,
            model,
            verbosity,
        }) => {
            // Configura logging para o comando fix
            if let Some(verbosity) = verbosity {
                if *verbosity > Level::INFO {
                    tracing_subscriber::fmt().with_max_level(*verbosity).init();
                }
            }

            // Obtém a chave da API do OpenAI para o comando fix
            let fix_openai_api_key = openai_api_key
                .clone()
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .unwrap_or_else(|| "sk-demo-key-for-development".to_string());

            // Cria configuração específica para o comando fix
            let fix_config = Config {
                openai_api_key: fix_openai_api_key,
                model: model.clone(),
                project_root: project_root.clone(),
                output_file: output.clone(),
                include_fixes: true,
                report_level: "advanced".to_string(),
                openai_base_url: "https://api.openai.com/v1/chat/completions".to_string(),
                temperature: 0.8,
                max_file_bytes: 350000,
                max_payload_tokens: 120000,
                chunk_target_tokens: 3000,
                rate_limit_rps: 30,
                timeout_seconds: 120,
            };

            // Cria o analisador para o comando fix
            let fix_analyzer = CodeQLAnalyzer::new(fix_config)?;

            // Executa a geração de código corrigido
            fix_analyzer
                .generate_fixed_code(&input.to_string_lossy(), &output.to_string_lossy())
                .await?;

            println!();
            println!(
                "{}",
                "╔══════════════════════════════════════════════════════════════════════════════╗"
                    .bright_green()
            );
            println!(
                "{}",
                "║                            🔧 CODE FIXED SUCCESSFULLY 🔧                    ║"
                    .bright_green()
            );
            println!(
                "{}",
                "╚══════════════════════════════════════════════════════════════════════════════╝"
                    .bright_green()
            );
            println!();
            println!("{}", "✅ Code fixed successfully!".bright_green());
            println!(
                "{}",
                format!("📄 Fixed code saved to: {}", output.display()).bright_blue()
            );
            println!(
                "{}",
                "🔒 Security vulnerabilities have been addressed".bright_red()
            );
            println!(
                "{}",
                "💡 AI-powered code corrections applied".bright_magenta()
            );
            println!("{}", "🛡️  Code is now more secure".bright_yellow());
            println!();
            println!(
                "{}",
                "🚀 Code Report - Fix Mission Accomplished!".bright_cyan()
            );
            return Ok(());
        }
        None => {
            // Comportamento original para análise de relatório
            match &cli.input {
                Some(input_file) => {
                    // Executa a análise
                    analyzer.analyze(&input_file.to_string_lossy()).await?;
                }
                None => {
                    // Mostra mensagem de boas-vindas simplificada
                    println!(
                        "{}",
                        "🎯 Ready to analyze CodeQL results with AI".bright_cyan()
                    );
                    println!();
                    println!("{}", "📋 Usage:".bright_yellow());
                    println!(
                        "{}",
                        "   ./codeql-ai -i <file.json> -p <path>".bright_white()
                    );
                    println!(
                        "{}",
                        "   ./codeql-ai -i <file.json> -p <path> -o report.md".bright_white()
                    );
                    println!(
                        "{}",
                        "   ./codeql-ai -i <file.json> -p <path> -v debug".bright_white()
                    );
                    println!();
                    println!("{}", "🔧 Commands:".bright_yellow());
                    println!(
                        "{}",
                        "   ./codeql-ai fix -i <file.json> -p <path> -o fixed_code.py"
                            .bright_white()
                    );
                    println!();
                    println!("{}", "🔧 Options:".bright_yellow());
                    println!(
                        "{}",
                        "   -i <file>     Input CodeQL results file (required)".bright_white()
                    );
                    println!(
                        "{}",
                        "   -p <path>     Project root directory (required)".bright_white()
                    );
                    println!(
                        "{}",
                        "   -o <file>     Output report file (default: codeql-analysis-report.md)"
                            .bright_white()
                    );
                    println!(
                        "{}",
                        "   -v <level>    Verbosity: debug, trace".bright_white()
                    );
                    println!("{}", "   --help        Show all options".bright_white());
                    println!();
                    return Ok(());
                }
            }
        }
    }

    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════════════════════════════════╗"
            .bright_green()
    );
    println!(
        "{}",
        "║                            🎯 ANALYSIS COMPLETE 🎯                        ║"
            .bright_green()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════════════╝"
            .bright_green()
    );
    println!();
    println!("{}", "✅ Analysis completed successfully!".bright_green());
    println!(
        "{}",
        format!("📄 Report saved to: {}", output_path.display()).bright_blue()
    );
    println!(
        "{}",
        "🔒 Security vulnerabilities identified and documented".bright_red()
    );
    println!(
        "{}",
        "💡 AI-powered recommendations generated".bright_magenta()
    );
    println!(
        "{}",
        "🛡️  Security posture assessment completed".bright_yellow()
    );
    println!();
    println!("{}", "🚀 Code Report - Mission Accomplished!".bright_cyan());
    Ok(())
}
