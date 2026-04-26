# CLAUDE.md — AuthKit

Extends parent governance. See the following for canonical definitions:
- **Global baseline:** `~/.claude/CLAUDE.md`
- **Phenotype root:** `/Users/kooshapari/CodeProjects/Phenotype/repos/CLAUDE.md`
- **AgilePlus mandate:** `/Users/kooshapari/CodeProjects/Phenotype/repos/AgilePlus`
- **Governance reference:** `AGENTS.md` (local, this repository)

## Project Overview

- **Name:** AuthKit (formerly AuthVault)
- **Description:** Pre-extraction staging repo for shared Phenotype infrastructure crates destined for `phenoShared`. Despite the name, no authentication SDK code currently lives here — the crates checked in are general-purpose infrastructure (bid, content-hash, contracts, policy-engine, security-aggregator).
- **Location:** repos/AuthKit
- **Language Stack:** Rust (edition 2021)
- **Status:** Experimental / pre-extraction staging

## Current Crates (`rust/`)

- `phenotype-bid`
- `phenotype-content-hash`
- `phenotype-contracts`
- `phenotype-policy-engine`
- `phenotype-security-aggregator`

These are slated for migration to `phenoShared` once their APIs stabilize. Do **not** treat this repo as a published auth SDK — any older references to `authkit-core` / `authkit-provider-*` / multi-language bindings are aspirational and not implemented.

## AgilePlus Mandate

All work MUST be tracked in AgilePlus:
- CLI: `cd /Users/kooshapari/CodeProjects/Phenotype/repos/AgilePlus && agileplus <command>`
- Check for existing specs before implementing
- Create spec for new work: `agileplus specify --title "<feature>" --description "<desc>"`
- No code without corresponding AgilePlus spec

## Quality Checks

From this repository root:
```bash
cd rust
cargo clippy --workspace -- -D warnings
cargo fmt --check
cargo test --workspace
```

## Worktree & Git Discipline

- Feature work uses repo-specific worktrees: `repos/AuthKit-wtrees/<topic>/`
- Canonical repo stays on `main` except during explicit merge operations
- All feature branches are temporary; integrate via pull request or squash commit
- See parent governance for non-destructive change protocol

## Cross-Project Reuse

The crates here are explicitly staged for cross-project reuse via `phenoShared`. When touching them, prefer changes that ease extraction (clean public API, no Phenotype-specific coupling, documented invariants).

## Related Documents

- `AGENTS.md` — Local agent contract and operating loop
- `FUNCTIONAL_REQUIREMENTS.md` — Functional requirements and test traceability (if present)
- `docs/worklogs/README.md` — Work audit and decision log
- Parent `README.md` — Project-specific documentation

---

For CI, scripting language hierarchy, and other policies, see the canonical sources listed above.
