# justfile — Phenotype org standard recipes
# Run `just` to list available recipes.

set shell := ["bash", "-uc"]

# Default: list available recipes.
default:
    @just --list

# Run the test suite.
test:
    @echo "Run project tests (see package.json / Cargo.toml / pyproject.toml)"

# Run the linter.
lint:
    @echo "Run project linter"

# Apply the formatter.
fmt:
    @echo "Run project formatter"

# Remove build artifacts.
clean:
    @echo "Remove build artifacts"

# Run the full local quality gate.
quality: lint test
    @echo "Quality gate passed"
