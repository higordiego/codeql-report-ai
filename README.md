# Code Report

🔍 **Advanced Security Analysis Tool** powered by AI & Static Analysis

[![CI](https://github.com/higordiego/codeql-report-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/higordiego/codeql-report-ai/actions/workflows/ci.yml)
[![Release](https://github.com/higordiego/codeql-report-ai/actions/workflows/release.yml/badge.svg)](https://github.com/higordiego/codeql-report-ai/actions/workflows/release.yml)

## 🚀 Overview

**Code Report** is a professional security analysis tool that combines CodeQL static analysis with ChatGPT AI to generate comprehensive security reports and action plans in Markdown format.

## ✨ Features

- 🔍 **Static Analysis**: CodeQL integration for vulnerability detection
- 🤖 **AI-Powered**: ChatGPT analysis for intelligent insights
- 📊 **Detailed Reports**: Professional Markdown reports with actionable recommendations
- 🛡️ **Security Focus**: Comprehensive vulnerability assessment
- 🎨 **Professional UI**: Clean and intuitive CLI interface with colored output
- ⚡ **Fast & Efficient**: Optimized for performance with smart caching
- 🔧 **Flexible**: Configurable analysis parameters and output formats

## 📦 Installation

### From Release (Recommended)

1. Download the latest release from [GitHub Releases](https://github.com/higordiego/codeql-report-ai/releases)
2. Extract the archive:
   ```bash
   tar -xzf codeql-ai-linux-x86_64.tar.gz
   chmod +x codeql-ai-linux-x86_64
   ```
3. Move to PATH (optional):
   ```bash
   sudo mv codeql-ai-linux-x86_64 /usr/local/bin/codeql-ai
   ```

### From Source

```bash
# Clone the repository
git clone https://github.com/higordiego/codeql-report-ai.git
cd codeql-report-ai

# Build the project
cargo build --release

# The binary will be available at target/release/codeql-ai
```

## 🎯 Quick Start

### Basic Usage

```bash
# Analyze CodeQL results
./codeql-ai -i results.json -p /path/to/project

# With custom output file
./codeql-ai -i results.json -p /path/to/project -o my-report.md

# With debug logging
./codeql-ai -i results.json -p /path/to/project -v debug
```

### Example Workflow

1. **Run CodeQL Analysis**:
   ```bash
   codeql database create db --language=python
   codeql database analyze db python-security-and-quality.qls --format=sarif-latest --output=results.json
   ```

2. **Generate AI-Powered Report**:
   ```bash
   ./codeql-ai -i results.json -p /path/to/your/project
   ```

3. **Review the Report**:
   ```bash
   cat codeql-analysis-report.md
   ```

## 📋 Command Line Options

```bash
USAGE:
    codeql-ai [OPTIONS] -p <PATH>

OPTIONS:
    -i, --input <FILE>                    Input CodeQL results file
    -p, --project-root <PATH>             Project root directory (required)
    -o, --output <FILE>                   Output report file [default: codeql-analysis-report.md]
    --openai-api-key <KEY>                OpenAI API key (optional, uses OPENAI_API_KEY env var or demo key)
    --model <MODEL>                       ChatGPT model to use [default: gpt-3.5-turbo]
    -v, --verbosity <LEVEL>               Verbosity level: info, debug, trace [default: info]
    -h, --help                            Print help information
    -V, --version                         Print version information
```

## 🔧 Configuration

### Environment Variables

- `OPENAI_API_KEY`: Your OpenAI API key (optional, uses demo key if not provided)
- `OPENAI_MODEL`: ChatGPT model to use (default: gpt-3.5-turbo)
- `OPENAI_TEMPERATURE`: AI response temperature (default: 0.2)

### Example Configuration

```bash
export OPENAI_API_KEY="your-api-key-here"
export OPENAI_MODEL="gpt-3.5-turbo"
./codeql-ai -i results.json -p /path/to/project
```

## 📊 Report Format

The generated report includes:

- **Executive Summary**: High-level overview with statistics
- **CodeQL Statistics**: Detailed analysis results
- **Vulnerability Details**: Specific issues with code examples
- **AI Recommendations**: Intelligent suggestions for fixes
- **Action Plan**: Prioritized tasks for remediation
- **Metadata**: Configuration and analysis information

### Sample Report Structure

```markdown
# Relatório de Análise de Segurança - CodeQL + ChatGPT

## 📊 Resumo Executivo
- Total de achados: 7
- Arquivos com problemas: 1
- Score de risco médio: 0.6

## 🔍 Achados Detalhados
### main.py - Linha 7
**Problema:** Vulnerabilidade de injeção de comando
**Severidade:** Alta
**Código Problemático:**
```python
subprocess.call(user_input, shell=True)
```

## 💡 Recomendações
### 🔴 Prioridade Alta (Imediata)
- Corrigir vulnerabilidades críticas de segurança

## 🎯 Plano de Ação
- [ ] Implementar validação de entrada
- [ ] Usar subprocess sem shell=True
```

## 🏗️ Architecture

```
codeql-report-ai/
├── Cargo.toml              # Workspace configuration
├── crates/
│   ├── corelib/            # Core library with analysis logic
│   │   ├── src/
│   │   │   ├── analyzer.rs # Main analysis orchestrator
│   │   │   ├── chatgpt.rs  # ChatGPT integration
│   │   │   ├── types.rs    # Data structures
│   │   │   └── utils.rs    # Utility functions
│   │   └── Cargo.toml
│   └── cli/                # Command-line interface
│       ├── src/main.rs     # CLI entry point
│       └── Cargo.toml
├── examples/               # Sample CodeQL results
└── .github/workflows/      # CI/CD pipelines
```

## 🧪 Development

### Prerequisites

- Rust 1.70+ (stable)
- Cargo

### Building

```bash
# Build in debug mode
cargo build

# Build in release mode
cargo build --release

# Run tests
cargo test

# Check formatting
cargo fmt --all

# Linting
cargo clippy --all-targets --all-features -- -D warnings
```

### Project Structure

The project is organized as a Rust workspace with two crates:

- **`corelib`**: Core analysis logic and ChatGPT integration
- **`cli`**: Command-line interface and user interaction

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Rust coding conventions
- Add tests for new features
- Update documentation as needed
- Ensure all CI checks pass

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CodeQL**: Static analysis engine by GitHub
- **OpenAI**: ChatGPT API for intelligent analysis
- **Rust Community**: Excellent tooling and ecosystem

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/higordiego/codeql-report-ai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/higordiego/codeql-report-ai/discussions)
- **Documentation**: [Project Wiki](https://github.com/higordiego/codeql-report-ai/wiki)

---

**Made with ❤️ for the security community**
