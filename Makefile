# Makefile for graftcp-rust

.PHONY: all build clean install test check fmt clippy

# Default target
all: build

# Build the mgraftcp binary
build:
	cargo build --release --bin mgraftcp

# Development build (debug mode)
dev:
	cargo build

# Clean build artifacts
clean:
	cargo clean

# Install binary to system
install: build
	install -D target/release/mgraftcp $(DESTDIR)$(PREFIX)/bin/mgraftcp

# Run tests
test:
	cargo test

# Check code without building
check:
	cargo check

# Format code
fmt:
	cargo fmt

# Run clippy lints
clippy:
	cargo clippy -- -D warnings

# Development workflow
dev-check: fmt clippy test

# Set default installation prefix
PREFIX ?= /usr/local