# ARCHIVED — phenotype-cipher

**Status:** This repository has been archived.

## What happened

The crate has been extracted and productized under a neutral name.

## Canonical location

```
https://github.com/phenotype-dev/cipher
```

Package name: `cipher`

## Migration

Replace in `Cargo.toml`:

```toml
# Old
phenotype-cipher = { path = "path/to/phenotype-cipher" }

# New
cipher = { git = "https://github.com/phenotype-dev/cipher" }
```

Replace in source code:

```rust
// Old
use phenotype_cipher::core;

// New
use cipher::core;
```

## Timeline

- Archived: 2026-03-26
- Phase 6 productization
