# Ports of sbomgate

The same **SBOM diff + gate** logic, ported across languages so you can drop
sbomgate into any stack or ship a single static binary. Every port mirrors the
Python reference (`sbomgate/core.py`): it parses CycloneDX / SPDX / native SBOM
JSON, computes the structural diff (added / removed / version-change /
maintainer-change), and exits non-zero when a finding meets/exceeds the gate
severity — exactly like `sbomgate diff`. The maintainer-change → `high` rule
(supply-chain takeover signal) is preserved everywhere.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../sbomgate/` | `sbomgate diff old.json new.json` | `pytest` (repo root) |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js diff ports/fixtures/sbom-old.json ports/fixtures/sbom-new.json` | `node ports/javascript/test.mjs` |
| Go | `go/` | `cd ports/go && go run . diff ../fixtures/sbom-old.json ../fixtures/sbom-new.json` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- diff ../fixtures/sbom-old.json ../fixtures/sbom-new.json` | `cd ports/rust && cargo test` |

All three ports share the fixtures in [`fixtures/`](fixtures/) and are built +
tested on every push by [`.github/workflows/ports.yml`](../.github/workflows/ports.yml),
so they are real and verifiable — not vaporware. Each port emits the same JSON
shape:

```json
{ "tool": "sbomgate", "old_count": 4, "new_count": 4, "gate": "fail",
  "findings": [ { "kind": "maintainer-change", "component": "leftpad-utils",
                  "severity": "high", "old": "acme-security", "new": "unknown-dev-9981" } ] }
```

The Rust port carries a tiny hand-rolled JSON parser (`src/json.rs`) so it stays
**zero-dependency**; the Go and JS ports use only their standard libraries.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
