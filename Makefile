# Code Report - Advanced Security Analysis Tool
# Makefile for building, testing, and managing the project

# Variables
BINARY_NAME = codeql-ai
CARGO = cargo
RUST_VERSION = 1.70

# Default target
.PHONY: all
all: build

# Build the project in release mode
.PHONY: build
build:
	@echo "🔨 Building Code Report in release mode..."
	$(CARGO) build --release
	@echo "✅ Build completed successfully!"

# Build for release with optimizations
.PHONY: release
release:
	@echo "🚀 Building optimized release..."
	$(CARGO) build --release
	@echo "✅ Release build completed!"

# Run tests
.PHONY: test
test:
	@echo "🧪 Running tests..."
	$(CARGO) test
	@echo "✅ Tests completed!"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "🧹 Cleaning build artifacts..."
	$(CARGO) clean
	@echo "✅ Clean completed!"

# Install the binary to system
.PHONY: install
install: build
	@echo "📦 Installing Code Report..."
	sudo cp target/release/$(BINARY_NAME) /usr/local/bin/
	@echo "✅ Installation completed!"

# Format code using rustfmt
.PHONY: format
format:
	@echo "🎨 Formatting code..."
	$(CARGO) fmt
	@echo "✅ Code formatting completed!"

# Lint code using clippy
.PHONY: lint
lint:
	@echo "🔍 Running clippy linter..."
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	@echo "✅ Linting completed!"

# Check code without building
.PHONY: check
check:
	@echo "✅ Checking code..."
	$(CARGO) check
	@echo "✅ Code check completed!"

# Run continuous integration checks
.PHONY: ci
ci: format lint test
	@echo "🔄 CI checks completed successfully!"

# Run example analysis
.PHONY: run-example
run-example: build
	@echo "📊 Running example analysis..."
	./target/release/$(BINARY_NAME) -i test_project/results.json -p test_project --report-level advanced
	@echo "✅ Example analysis completed!"

# Setup test environment
.PHONY: setup-test
setup-test:
	@echo "🧪 Setting up test environment..."
	@if [ ! -d "test_project" ]; then \
		mkdir -p test_project; \
		echo '{"runs":[{"results":[]}]}' > test_project/results.json; \
		echo "print('Hello, World!')" > test_project/main.py; \
		echo "✅ Test environment created!"; \
	else \
		echo "✅ Test environment already exists!"; \
	fi

# Show project information
.PHONY: info
info:
	@echo "📋 Code Report Project Information:"
	@echo "  Binary Name: $(BINARY_NAME)"
	@echo "  Rust Version: $(RUST_VERSION)"
	@echo "  Build Target: target/release/$(BINARY_NAME)"
	@echo ""
	@echo "📚 Available Commands:"
	@echo "  make build      - Build the project"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make install    - Install to system"
	@echo "  make format     - Format code"
	@echo "  make lint       - Run linter"
	@echo "  make ci         - Run CI checks"
	@echo "  make run-example - Run example analysis"

# Help target
.PHONY: help
help: info

# Development helpers
.PHONY: dev
dev:
	@echo "🛠️  Starting development mode..."
	$(CARGO) run -- -i test_project/results.json -p test_project -v debug

# Quick build and test
.PHONY: quick
quick: build test
	@echo "⚡ Quick build and test completed!"

# Documentation
.PHONY: docs
docs:
	@echo "📚 Generating documentation..."
	$(CARGO) doc --no-deps --open
	@echo "✅ Documentation generated!"

# Security audit
.PHONY: audit
audit:
	@echo "🔒 Running security audit..."
	$(CARGO) audit
	@echo "✅ Security audit completed!"

# Update dependencies
.PHONY: update
update:
	@echo "🔄 Updating dependencies..."
	$(CARGO) update
	@echo "✅ Dependencies updated!"

# Show dependency tree
.PHONY: tree
tree:
	@echo "🌳 Dependency tree:"
	$(CARGO) tree

# Benchmark (if available)
.PHONY: bench
bench:
	@echo "⚡ Running benchmarks..."
	$(CARGO) bench
	@echo "✅ Benchmarks completed!"
