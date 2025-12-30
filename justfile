# List available recipes
default:
    @just --list

# Run all tests
test:
    cargo test

# Run tests with all features
test-all:
    cargo test --all-features

# Run clippy with warnings as errors
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Check code formatting
fmt-check:
    cargo fmt -- --check

# Format code
fmt:
    cargo fmt

# Build documentation
doc:
    cargo doc --no-deps

# Open documentation in browser
doc-open:
    cargo doc --no-deps --open

# Build the project
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Run all checks (test, clippy, fmt)
check: test clippy fmt-check

# Run a specific example
example name:
    cargo run --example {{name}}

# List available examples
examples:
    @ls -1 examples/*.rs | xargs -I {} basename {} .rs

# Clean build artifacts
clean:
    cargo clean

# Update dependencies
update:
    cargo update

# Check for outdated dependencies
outdated:
    cargo outdated
