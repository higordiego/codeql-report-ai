use clap::{Parser, Subcommand};
use codeql_corelib::{CodeQLAnalyzer, Config, Result};
use colored::*;
use std::path::PathBuf;
use tracing::{info, Level};

fn print_banner(show_quick_start: bool) {
    // Spaces at the top for better color visualization
    println!();
    println!();
    println!();

    // Code Report Banner
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
        // Usage tips for developers
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

    /// CodeQL results JSON file
    #[arg(short, long, value_name = "FILE", help_heading = "INPUT")]
    input: Option<PathBuf>,

    /// Project root directory
    #[arg(short, long, value_name = "PATH", help_heading = "CONFIGURATION")]
    project_root: Option<PathBuf>,

    /// Output file for the report
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value = "codeql-analysis-report.md",
        help_heading = "OUTPUT"
    )]
    output: PathBuf,

    /// OpenAI API key (optional, uses OPENAI_API_KEY env var or demo key)
    #[arg(long, value_name = "KEY", help_heading = "API")]
    openai_api_key: Option<String>,

    /// ChatGPT model to use
    #[arg(
        long,
        value_name = "MODEL",
        default_value = "gpt-3.5-turbo",
        help_heading = "AI"
    )]
    model: String,

    /// Verbosity level
    #[arg(
        short,
        long,
        value_name = "LEVEL",
        default_value = "info",
        help_heading = "LOGGING"
    )]
    verbosity: Option<Level>,

    /// Include code correction suggestions in the report
    #[arg(long, help_heading = "ANALYSIS")]
    include_fixes: bool,

    /// Report level (easy, medium, advanced)
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
    /// Generate corrected code based on found vulnerabilities
    Fix {
        /// CodeQL results JSON file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Project root directory
        #[arg(short, long, value_name = "PATH")]
        project_root: PathBuf,

        /// Output file for corrected code
        #[arg(short, long, value_name = "FILE", default_value = "fixed_code.py")]
        output: PathBuf,

        /// OpenAI API key (optional)
        #[arg(long, value_name = "KEY")]
        openai_api_key: Option<String>,

        /// ChatGPT model to use
        #[arg(long, value_name = "MODEL", default_value = "gpt-3.5-turbo")]
        model: String,

        /// Verbosity level
        #[arg(short, long, value_name = "LEVEL", default_value = "info")]
        verbosity: Option<Level>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Configure logging if verbosity is greater than info (including -v)
    if let Some(verbosity) = cli.verbosity {
        if verbosity > Level::INFO {
            tracing_subscriber::fmt().with_max_level(verbosity).init();
        }
    }

    // Show banner (without Quick Start when there's a command)
    let show_quick_start = cli.input.is_none();
    print_banner(show_quick_start);

    // Log only if verbosity is greater than info (including -v)
    if let Some(verbosity) = cli.verbosity {
        if verbosity > Level::INFO {
            info!("🚀 Code Report initialized");
        }
    }

    // Get OpenAI API key (with fallback for development)
    let openai_api_key = cli
        .openai_api_key
        .or_else(|| std::env::var("OPENAI_API_KEY").ok())
        .unwrap_or_else(|| "sk-demo-key-for-development".to_string());

    // Store output path for later use
    let output_path = cli.output.clone();

    // Create configuration
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

    // Create analyzer (without visible logs)
    let analyzer = CodeQLAnalyzer::new(config)?;

    // Check if a specific command was provided
    match &cli.command {
        Some(Commands::Fix {
            input,
            project_root,
            output,
            openai_api_key,
            model,
            verbosity,
        }) => {
            // Configure logging for fix command
            if let Some(verbosity) = verbosity {
                if *verbosity > Level::INFO {
                    tracing_subscriber::fmt().with_max_level(*verbosity).init();
                }
            }

            // Get OpenAI API key for fix command
            let fix_openai_api_key = openai_api_key
                .clone()
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                .unwrap_or_else(|| "sk-demo-key-for-development".to_string());

            // Create specific configuration for fix command
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

            // Create analyzer for fix command
            let fix_analyzer = CodeQLAnalyzer::new(fix_config)?;

            // Execute code generation
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
            // Original behavior for report analysis
            match &cli.input {
                Some(input_file) => {
                    // Execute analysis
                    analyzer.analyze(&input_file.to_string_lossy()).await?;
                }
                None => {
                    // Show simplified welcome message
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
                    println!(
                        "{}",
                        "   ./codeql-ai -i <file.json> -p <path> --report-level advanced"
                            .bright_white()
                    );
                    println!(
                        "{}",
                        "   ./codeql-ai -i <file.json> -p <path> --include-fixes".bright_white()
                    );
                    println!(
                        "{}",
                        "   ./codeql-ai -i <file.json> -p <path> --model gpt-4".bright_white()
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
                        "   -p <path>     Project root directory (optional, defaults to current dir)".bright_white()
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
                    println!(
                        "{}",
                        "   --model <model>  ChatGPT model (default: gpt-3.5-turbo)".bright_white()
                    );
                    println!(
                        "{}",
                        "   --openai-api-key <key>  OpenAI API key (optional)".bright_white()
                    );
                    println!(
                        "{}",
                        "   --include-fixes  Include code correction suggestions".bright_white()
                    );
                    println!(
                        "{}",
                        "   --report-level <level>  Report level: easy, medium, advanced (default: medium)".bright_white()
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
