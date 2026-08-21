# AuthKit Justfile — single command entry point for the local quality gate.
#
# `just ci` mirrors what `.github/workflows/ci.yml` runs, so contributors and
# autonomous agents can verify a change locally before pushing.

set shell := ["bash", "-uc"]

default:
    @just --list

# Run every check the CI workflow runs (fmt + clippy + test + doc + deny).
ci: fmt-check clippy test doc deny

# `cargo +nightly fmt -- --check`
fmt-check:
    cargo +nightly fmt -- --check

# `cargo +nightly clippy --all-targets -- -D warnings`
clippy:
    cargo +nightly clippy --all-targets -- -D warnings

# `cargo +nightly test --locked --all-features`
test:
    cargo +nightly test --locked --all-features

# `cargo +nightly doc --no-deps --all-features`
doc:
    cargo +nightly doc --no-deps --all-features

# `cargo deny check` (requires `deny.toml`)
deny:
    cargo deny check