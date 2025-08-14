.PHONY: help build test clean release install format lint check

# Default target
help:
	@echo "Code Report - Available commands:"
	@echo ""
	@echo "  build     - Build the project in debug mode"
	@echo "  release   - Build the project in release mode"
	@echo "  test      - Run all tests"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install the binary globally"
	@echo "  format    - Format code with rustfmt"
	@echo "  lint      - Run clippy linter"
	@echo "  check     - Check code without building"
	@echo "  ci        - Run CI checks (format, lint, test, build)"
	@echo ""

# Build in debug mode
build:
	cargo build

# Build in release mode
release:
	cargo build --release

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Install binary globally
install:
	cargo install --path crates/cli

# Format code
format:
	cargo fmt --all

# Run linter
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Check code
check:
	cargo check --workspace

# Run CI checks
ci: format lint test release

# Run with example
run-example:
	cargo run --release -- -i examples/sample-codeql-results.json -p test_project

# Create test project
setup-test:
	mkdir -p test_project
	@echo 'import subprocess' > test_project/main.py
	@echo 'import os' >> test_project/main.py
	@echo 'import sys' >> test_project/main.py
	@echo '' >> test_project/main.py
	@echo 'def vulnerable_function(user_input):' >> test_project/main.py
	@echo '    # Linha 7: Vulnerabilidade de injeção de comando' >> test_project/main.py
	@echo '    subprocess.call(user_input, shell=True)' >> test_project/main.py
	@echo '' >> test_project/main.py
	@echo 'def another_vulnerable_function(command):' >> test_project/main.py
	@echo '    # Linha 11: Outra vulnerabilidade' >> test_project/main.py
	@echo '    os.system(command)' >> test_project/main.py
	@echo '' >> test_project/main.py
	@echo 'def safe_function():' >> test_project/main.py
	@echo '    # Linha 15: Função segura' >> test_project/main.py
	@echo '    print("Esta é uma função segura")' >> test_project/main.py
	@echo '' >> test_project/main.py
	@echo 'if __name__ == "__main__":' >> test_project/main.py
	@echo '    user_input = input("Digite um comando: ")' >> test_project/main.py
	@echo '    vulnerable_function(user_input)' >> test_project/main.py

# Show project info
info:
	@echo "Code Report - Project Information"
	@echo "================================"
	@echo "Version: $(shell grep '^version =' Cargo.toml | cut -d'"' -f2)"
	@echo "Rust version: $(shell rustc --version)"
	@echo "Cargo version: $(shell cargo --version)"
	@echo ""
	@echo "Project structure:"
	@find . -name "*.rs" -o -name "Cargo.toml" | head -10
