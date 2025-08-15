#!/bin/bash

# Code Report - Setup Script
# This script helps set up the development environment for Code Report

set -e  # Exit on any error

echo "🚀 Code Report - Development Environment Setup"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Rust is installed
print_status "Checking Rust installation..."
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    print_success "Rust is installed: $RUST_VERSION"
else
    print_error "Rust is not installed. Please install Rust first:"
    echo "  Visit: https://rustup.rs/"
    echo "  Or run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Check if Cargo is installed
print_status "Checking Cargo installation..."
if command -v cargo &> /dev/null; then
    CARGO_VERSION=$(cargo --version | cut -d' ' -f2)
    print_success "Cargo is installed: $CARGO_VERSION"
else
    print_error "Cargo is not installed. Please install Cargo first."
    exit 1
fi

# Install Rust components if needed
print_status "Installing Rust components..."
rustup component add rustfmt
rustup component add clippy
print_success "Rust components installed"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    print_error "Cargo.toml not found. Please run this script from the project root directory."
    exit 1
fi

# Build the project
print_status "Building the project..."
if cargo build --release; then
    print_success "Project built successfully!"
else
    print_error "Build failed. Please check the error messages above."
    exit 1
fi

# Run tests
print_status "Running tests..."
if cargo test; then
    print_success "All tests passed!"
else
    print_error "Tests failed. Please check the error messages above."
    exit 1
fi

# Create test project directory
print_status "Creating test project..."
if [ ! -d "test_project" ]; then
    mkdir -p test_project
    print_success "Test project directory created"
else
    print_success "Test project directory already exists"
fi

# Create sample CodeQL results file
print_status "Creating sample CodeQL results file..."
cat > test_project/results.json << 'EOF'
{
  "runs": [
    {
      "results": [
        {
          "rule_id": "python/command-injection",
          "level": "error",
          "message": "Command injection vulnerability detected",
          "locations": [
            {
              "physical_location": {
                "artifact_location": {
                  "uri": "main.py"
                },
                "region": {
                  "start_line": 7,
                  "end_line": 7
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
EOF
print_success "Sample CodeQL results file created"

# Create sample Python file with vulnerabilities
print_status "Creating sample Python file with vulnerabilities..."
cat > test_project/main.py << 'EOF'
import subprocess
import os
import sys

def vulnerable_function(user_input):
    # Line 7: Command injection vulnerability
    subprocess.call(user_input, shell=True)

def another_vulnerable_function(command):
    # Line 11: Another vulnerability
    os.system(command)

def safe_function():
    # Line 15: Safe function
    print("This is a safe function")

if __name__ == "__main__":
    user_input = input("Enter a command: ")
    vulnerable_function(user_input)
EOF
print_success "Sample Python file created"

# Create .env file from template
print_status "Creating .env file from template..."
if [ ! -f ".env" ]; then
    if [ -f "env.example" ]; then
        cp env.example .env
        print_success ".env file created from template"
        print_warning "Please edit .env file with your OpenAI API key"
    else
        print_warning "env.example not found, creating basic .env file"
        cat > .env << 'EOF'
# Code Report Configuration
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-3.5-turbo
OPENAI_TEMPERATURE=0.8
REPORT_LEVEL=medium
OUTPUT_FILE=codeql-analysis-report.md
EOF
        print_success "Basic .env file created"
    fi
else
    print_success ".env file already exists"
fi

# Test the binary
print_status "Testing the binary..."
if ./target/release/codeql-ai --help &> /dev/null; then
    print_success "Binary is working correctly!"
else
    print_error "Binary test failed"
    exit 1
fi

# Show usage information
echo ""
echo "🎉 Setup completed successfully!"
echo "================================"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file with your OpenAI API key"
echo "2. Run: ./target/release/codeql-ai -i test_project/results.json -p test_project"
echo "3. Or run: make run-example"
echo ""
echo "📚 Available commands:"
echo "  make build      - Build the project"
echo "  make test       - Run tests"
echo "  make clean      - Clean build artifacts"
echo "  make install    - Install to system"
echo "  make format     - Format code"
echo "  make lint       - Run linter"
echo "  make ci         - Run CI checks"
echo ""
echo "🔧 Development:"
echo "  cargo run -- -i test_project/results.json -p test_project -v debug"
echo "  cargo clippy --all-targets --all-features -- -D warnings"
echo ""
echo "📖 Documentation:"
echo "  See README.md for detailed usage instructions"
echo ""
print_success "Setup completed! Happy coding! 🚀"
