# Demo 10 — Version-constraint operators and gate-threshold tuning

A focused reference demo that shows exactly how `sbomgate` evaluates each
version-constraint operator and how `--fail-on` changes what blocks a build.

> The package names (`alpha`…`echo`) and advisory ids (`SBOMGATE-EXAMPLE-*`)
> are **deliberately synthetic** — this demo documents matcher *semantics*, so
> it intentionally uses no real CVE/GHSA identifiers.

## What each entry proves

| Component | Constraint | Matches? | Why |
|---|---|---|---|
| `alpha 2.5.0`   | `==2.5.0`        | ✅ | exact pin |
| `bravo 1.4.2`   | `>=1.0.0,<1.5.0` | ✅ | AND-joined range, both clauses hold |
| `charlie 3.0.0` | `>=3.0.0`        | ✅ | lower bound is inclusive |
| `delta 0.9.9`   | `<1.0.0`         | ✅ | upper bound is exclusive |
| `echo 5.0.0`    | `<5.0.0`         | ❌ | `5.0.0` is **not** `< 5.0.0` (boundary) |

## Run it

```bash
# default gate (--fail-on high): blocks on alpha (critical) + bravo (high)
python -m sbomgate vulns demos/10-version-range-and-gate/sbom.json \
    demos/10-version-range-and-gate/advisories.json

# widen the gate to see every severity counted:
python -m sbomgate vulns demos/10-version-range-and-gate/sbom.json \
    demos/10-version-range-and-gate/advisories.json --fail-on low --format json
```

## How to act

Use this as the contract for writing your own advisory feed: a comma inside one
string is **AND** (`>=2.0,<2.31`), and a list of strings is **OR** (any entry
matching is a hit). Boundaries on `<` / `>` are exclusive.
