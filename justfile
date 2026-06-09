# AuthKit — task runner (https://just.systems)
# Parallel to Taskfile.yml; use either, justfile is the canonical entrypoint.

set shell := ["bash", "-uc"]

default:
    @just --list

# Start dev server / watch mode
dev:
    cargo watch -x check -x test

# Produce release artifacts
build:
    cargo build --workspace --all-features --release

# Run the test suite
test:
    cargo test --workspace --all-features

# Run the linter
lint:
    cargo clippy --workspace --all-features --all-targets -- -D warnings

# Apply formatter
fmt:
    cargo fmt --all

# Remove build artifacts
clean:
    cargo clean
    rm -rf target
