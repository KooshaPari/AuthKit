# Package Surfaces

AuthKit is organized by language so each ecosystem can expose native ergonomics
while preserving shared protocol concepts.

| Package Area | Purpose |
| --- | --- |
| `python/pheno-auth` | Python authentication package surface |
| `python/pheno-credentials` | Python credential handling |
| `python/pheno-security` | Shared Python security helpers |
| `typescript/` | TypeScript package workspace |
| `go` | Go module surface |

## Package Guidance

- Keep provider-specific behavior behind adapters.
- Keep token, credential, and session concepts aligned across languages.
- Reference functional requirements from tests and implementation notes.
- Avoid copying protocol logic between languages when a shared contract can
  describe the expected behavior.
