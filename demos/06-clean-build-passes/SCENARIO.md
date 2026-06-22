# Demo 06 — A clean upgrade build that the gate lets through (exit 0)

Most builds are *boring* — routine patch bumps that move every dependency
**forward** past its known-fixed version. A good gate must let these through
silently so it stays trusted. This demo is the negative control.

## Where the data came from

Two CycloneDX SBOMs of a billing service across a routine maintenance release
(`1.8.0` -> `1.9.0`). The advisory feed contains two *real* medium advisories,
but every component is already at or above the fixed version.

## What to expect

- `requests 2.32.2 -> 2.32.4`, `urllib3 2.2.2 -> 2.2.3`,
  `certifi 2024.7.4 -> 2024.8.30` — three benign `version-change` (low)
  findings.
- **No** vulnerability matches: the build is already past
  CVE-2024-35195 (requests `<2.32.0`) and CVE-2024-37891 (urllib3 `<2.2.2`).
- No maintainer changes.

Gate **PASSES** (exit 0) at the default `--fail-on high`.

## Run it

```bash
python -m sbomgate scan demos/06-clean-build-passes/sbom-new.json \
    --old demos/06-clean-build-passes/sbom-old.json \
    --advisories demos/06-clean-build-passes/advisories.json
echo "exit code: $?"   # 0
```

## How to act

Nothing to do — this is the desired steady state. Use it as a smoke test that
your CI wiring reports exit 0 (green) when there is genuinely nothing to block.
