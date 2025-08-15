# Code Report

🛡️ **Advanced Security Analysis** powered by AI and Static Analysis

[![CI](https://github.com/higordiego/codeql-report-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/higordiego/codeql-report-ai/actions/workflows/ci.yml)
[![Release](https://github.com/higordiego/codeql-report-ai/actions/workflows/release.yml/badge.svg)](https://github.com/higordiego/codeql-report-ai/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)

## 📋 Overview

**Code Report** is a professional security analysis tool that combines CodeQL static analysis with ChatGPT AI to generate comprehensive security reports and **automatically generate corrected code**.

### 🎯 Key Features

- **🔍 Advanced Static Analysis**: CodeQL integration for precise vulnerability detection
- **🤖 Artificial Intelligence**: Deep analysis using ChatGPT
- **📊 Detailed Reports**: Professional documentation with actionable recommendations
- **🔧 Code Generation**: Automatically creates secure code based on found vulnerabilities
- **🛡️ Security Focus**: Comprehensive vulnerability assessment
- **💻 Professional Interface**: Intuitive CLI with visual feedback
- **⚡ High Performance**: Optimized with intelligent caching
- **⚙️ Configurable**: Customizable parameters and output formats

## 🚀 Installation

### Via Release (Recommended)

1. **Download** the latest version from [GitHub Releases](https://github.com/higordiego/codeql-report-ai/releases)
2. **Extract the file**:
   ```bash
   tar -xzf codeql-ai-linux-x86_64.tar.gz
   chmod +x codeql-ai
   ```
3. **Add to PATH** (optional):
   ```bash
   sudo mv codeql-ai /usr/local/bin/codeql-ai
   ```

### Via Source Code

```bash
# Clone the repository
git clone https://github.com/higordiego/codeql-report-ai.git
cd codeql-report-ai

# Build the project
cargo build --release

# Run
./target/release/codeql-ai --help
```

## 📖 Usage

### Main Commands

#### 1. **Security Report Analysis**

```bash
# Basic analysis
./codeql-ai -i results.json -p .

# Analysis with custom report
./codeql-ai -i results.json -p . -o my-report.md

# Advanced analysis with recommendations
./codeql-ai -i results.json -p . --report-level advanced

# Analysis with verbosity
./codeql-ai -i results.json -p . -v debug
```

#### 2. **Code Generation** ⭐ **NEW!**

```bash
# Generate corrected code automatically
./codeql-ai fix -i results.json -p . -o corrected_code.py

# With custom API key
./codeql-ai fix -i results.json -p . --openai-api-key "your-key-here"

# With verbosity for debugging
./codeql-ai fix -i results.json -p . -v debug
```

### Report Levels

- **`easy`**: Basic report with statistics
- **`medium`**: Detailed report with vulnerability analysis
- **`advanced`**: Complete report with correction recommendations

### Configuration Options

```bash
# OpenAI API configuration
export OPENAI_API_KEY="your-key-here"

# Or use via command line
./codeql-ai -i results.json -p . --openai-api-key "your-key-here"

# ChatGPT model
./codeql-ai -i results.json -p . --model "gpt-4"

# Verbosity
./codeql-ai -i results.json -p . -v debug
```

## 🔧 Detailed Features

### 📊 Report Analysis

Code Report analyzes CodeQL results and generates professional reports including:

- **Executive Summary**: Overview of found vulnerabilities
- **Detailed Statistics**: Distribution by severity and type
- **Detailed Findings**: Specific analysis of each vulnerability
- **Affected Code Lines**: Visual context of problematic lines
- **Correction Recommendations**: Practical suggestions to resolve vulnerabilities

### 🔧 Code Generation

The `fix` command automatically generates secure code that:

- **Identifies vulnerabilities** in the CodeQL JSON
- **Analyzes original code** to understand context
- **Generates corrected code** with security best practices
- **Implements input validations** appropriately
- **Adds logging** for audit purposes
- **Handles exceptions** robustly
- **Maintains original functionality** of the code

#### Generated Code Example

```python
# Corrected Code - Security Vulnerabilities Resolved
import subprocess
import shlex
import logging

# Logging configuration for audit
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# List of allowed commands for secure execution
ALLOWED_COMMANDS = ['ls', 'pwd', 'whoami', 'date', 'echo']

def safe_command_execution(user_input: str) -> str:
    """Execute commands securely"""
    try:
        # Input validation
        if not user_input or user_input.strip().is_empty():
            return "Error: Invalid input"
        
        # Split command into parts
        command_parts = shlex.split(user_input)
        
        # Check if command is in allowed list
        if command_parts[0] not in ALLOWED_COMMANDS:
            return f"Error: Command '{command_parts[0]}' not allowed"
        
        # Execute command securely
        result = subprocess.run(
            command_parts,
            shell=False,  # Never use shell=True
            capture_output=True,
            text=True,
            timeout=30  # Timeout for security
        )
        
        return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
            
    except Exception as e:
        return f"Error: {str(e)}"
```

## 📁 Project Structure

```
codeql-report-ai/
├── crates/
│   ├── cli/                 # Command line interface
│   └── corelib/             # Core library
├── test_project/            # Test project
├── .github/workflows/       # CI/CD
├── docs/                    # Documentation
├── examples/                # Usage examples
└── README.md               # This file
```

## ⚙️ Configuration

### Environment Variables

```bash
# OpenAI API key (required for AI features)
OPENAI_API_KEY=your-key-here

# Optional configurations
OPENAI_TEMPERATURE=0.8
TIMEOUT_SECONDS=120
```

### Configuration File

Create a `.env` file based on `env.example`:

```bash
cp env.example .env
# Edit the .env file with your configurations
```

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run tests with verbosity
cargo test -- --nocapture

# Run integration tests
cargo test --test integration_tests
```

## 🔍 Usage Examples

### Example 1: Basic Analysis

```bash
# Run CodeQL on your project
codeql database create db --language=python
codeql database analyze db python-security-and-quality.qls --format=sarif-latest --output=results.json

# Analyze with Code Report
./codeql-ai -i results.json -p .
```

### Example 2: Advanced Analysis

```bash
# Analysis with detailed recommendations
./codeql-ai -i results.json -p . --report-level advanced -o advanced-report.md
```

### Example 3: Code Generation

```bash
# Generate corrected code automatically
./codeql-ai fix -i results.json -p . -o secure_code.py

# Test the generated code
python secure_code.py
```

## 📊 Security Features

### Detected Vulnerabilities

- **Command Injection**: Command injection via `subprocess` and `os.system`
- **SQL Injection**: SQL injection in database queries
- **Path Traversal**: Unauthorized file access
- **XSS**: Cross-Site Scripting
- **Unsafe Deserialization**: Deserialization of untrusted data
- **Hardcoded Secrets**: Hardcoded keys and passwords in code

### Implemented Best Practices

- ✅ **Input Validation**: Rigorous verification of input data
- ✅ **Allowed Commands List**: Restriction of executable commands
- ✅ **Security Timeout**: Execution time limitation
- ✅ **Audit Logging**: Operation logging for audit purposes
- ✅ **Exception Handling**: Robust error handling
- ✅ **Data Sanitization**: Input data cleaning
- ✅ **Principle of Least Privilege**: Execution with minimal privileges

## 🤝 Contributing

1. **Fork** the project
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Contribution Guidelines

- Follow Rust code conventions
- Add tests for new features
- Update documentation as needed
- Maintain high test coverage

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **GitHub** for CodeQL
- **OpenAI** for ChatGPT
- **Rust Community** for tools and libraries
- **Contributors** who helped improve this project

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/higordiego/codeql-report-ai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/higordiego/codeql-report-ai/discussions)
- **Documentation**: [Wiki](https://github.com/higordiego/codeql-report-ai/wiki)

## 🔄 Roadmap

- [ ] Support for more programming languages
- [ ] Integration with more static analysis tools
- [ ] Web interface for report visualization
- [ ] Vulnerable dependency analysis
- [ ] CI/CD system integration
- [ ] Reports in multiple formats (PDF, HTML, JSON)

---

**⭐ If this project helped you, consider giving it a star!**

**🛡️ Code Report - Code Security with Artificial Intelligence**
