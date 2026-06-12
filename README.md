<!-- AI-DD-META:START -->
<!-- This repository is planned, maintained, and managed by AI Agents only. -->
<!-- Slop issues are expected and intentionally present as part of an HITL-less -->
<!-- /minimized AI-DD metaproject of learning, refining, and building brute-force -->
<!-- training for both agents and the human operator. -->
![Downloads](https://img.shields.io/github/downloads/KooshaPari/AuthKit/total?style=flat-square&label=downloads&color=blue)
![GitHub release](https://img.shields.io/github/v/release/KooshaPari/AuthKit?style=flat-square&label=release)
![License](https://img.shields.io/github/license/KooshaPari/AuthKit?style=flat-square)
![AI-Slop](https://img.shields.io/badge/AI--DD-Slop%20Expected-orange?style=flat-square)
![AI-Only-Maintained](https://img.shields.io/badge/Planned%20%26%20Maintained%20by-AI%20Agents%20Only-red?style=flat-square)
![HITL-less](https://img.shields.io/badge/HITL--less%20AI--DD-metaproject-yellow?style=flat-square)

> ⚠️ **AI-Agent-Only Repository**
>
> This repo is **planned, maintained, and managed exclusively by AI Agents**.
> Slop issues, rough edges, and AI artifacts are **expected and intentionally
> present** as part of an **HITL-less / minimized AI-DD** metaproject focused
> on learning, refining, and brute-force training both the agents and the
> human operator. Bug reports and contributions are still welcome, but please
> expect AI-generated code, comments, and documentation throughout.
<!-- AI-DD-META:END -->
## Work State

| Field | Value |
|---|---|
| Last commit | 2026-05-04 |
| Open issues | 4 |
| Open PRs | 4 |
| Focus | Auth & identity infrastructure (pre-extraction staging) |

Progress: ██████░░░░ 65%

# AuthKit

[![Build](https://img.shields.io/github/actions/workflow/status/KooshaPari/AuthKit/ci.yml?branch=main&label=build)](https://github.com/KooshaPari/AuthKit/actions)
[![Release](https://img.shields.io/github/v/release/KooshaPari/AuthKit?include_prereleases&sort=semver)](https://github.com/KooshaPari/AuthKit/releases)
[![License](https://img.shields.io/github/license/KooshaPari/AuthKit)](LICENSE)
[![Phenotype](https://img.shields.io/badge/Phenotype-org-blueviolet)](https://github.com/KooshaPari)

> **Status:** Pre-extraction staging repo. Not a published SDK.

AuthKit (formerly AuthVault) is a pre-extraction staging repository for shared infrastructure crates that will eventually move to **phenoShared**. Despite the name, this repository does **not** currently contain authentication SDK code — that work is planned but not started. The crates currently checked in here are general-purpose Phenotype-org infrastructure being staged for extraction.

If you arrived here looking for a unified OAuth/OIDC/SAML/WebAuthn SDK: that does not exist yet in this repo.

## Current Contents

The `rust/` workspace currently contains five infrastructure crates:

| Crate | Purpose |
|-------|---------|
| `phenotype-bid` | Bid / auction primitives shared across Phenotype services |
| `phenotype-content-hash` | Content-addressable hashing utilities |
| `phenotype-contracts` | Cross-service contract / interface definitions |
| `phenotype-policy-engine` | Rule-based policy evaluation (TOML-configured) |
| `phenotype-security-aggregator` | Security signal aggregation across sources |

Build:

```bash
cd rust && cargo build --workspace && cargo test --workspace
```

## Roadmap

1. **Now:** Stage and stabilize the five infrastructure crates above.
2. **Next:** Extract them into `phenoShared` once their APIs are stable.
3. **Later:** Reuse this repo (or a successor) for actual auth SDK work — at which point the README and crate layout will be rewritten to match.

Until step 3 happens, treat any reference to `authkit-core`, `authkit-provider-*`, or multi-language (TypeScript/Python/Go) auth bindings in older docs as aspirational — none of that code exists here.

## Related Phenotype Projects

- **phenoShared** — destination for the staged crates above
- **bifrost-extensions** — API gateway (separate auth concerns)
- **PhenoPlugins** — plugin system

## License

MIT — see [LICENSE](./LICENSE).
