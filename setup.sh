#!/bin/bash

# Code Report - Setup Script
# This script helps set up the development environment

set -e

echo "🚀 Code Report - Setup Script"
echo "=============================="
echo ""

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust first:"
    echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "✅ Rust is installed: $(rustc --version)"

# Check if Cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo is not installed. Please install Cargo first."
    exit 1
fi

echo "✅ Cargo is installed: $(cargo --version)"

# Install Rust components
echo ""
echo "📦 Installing Rust components..."
rustup component add rustfmt
rustup component add clippy

echo "✅ Rust components installed"

# Build the project
echo ""
echo "🔨 Building the project..."
cargo build

echo "✅ Project built successfully"

# Run tests
echo ""
echo "🧪 Running tests..."
cargo test

echo "✅ Tests passed"

# Create test project
echo ""
echo "📁 Creating test project..."
mkdir -p test_project

cat > test_project/main.py << 'EOF'
import subprocess
import os
import sys

def vulnerable_function(user_input):
    # Linha 7: Vulnerabilidade de injeção de comando
    subprocess.call(user_input, shell=True)
    
def another_vulnerable_function(command):
    # Linha 11: Outra vulnerabilidade
    os.system(command)
    
def safe_function():
    # Linha 15: Função segura
    print("Esta é uma função segura")
    
if __name__ == "__main__":
    user_input = input("Digite um comando: ")
    vulnerable_function(user_input)
EOF

echo "✅ Test project created"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo ""
    echo "📝 Creating .env file from template..."
    cp env.example .env
    echo "✅ .env file created (please update with your OpenAI API key)"
else
    echo "✅ .env file already exists"
fi

# Show project info
echo ""
echo "📊 Project Information:"
echo "======================="
echo "Version: $(grep '^version =' Cargo.toml | cut -d'"' -f2)"
echo "Project structure:"
find . -name "*.rs" -o -name "Cargo.toml" | head -10

echo ""
echo "🎯 Next steps:"
echo "=============="
echo "1. Update .env file with your OpenAI API key"
echo "2. Run: make help (to see available commands)"
echo "3. Run: make run-example (to test the tool)"
echo "4. Run: make ci (to run all CI checks)"
echo ""
echo "🚀 Setup complete! Happy coding!"
