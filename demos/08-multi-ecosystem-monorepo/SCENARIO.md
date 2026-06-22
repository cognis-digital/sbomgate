# Demo 08 — Multi-ecosystem monorepo (Python + npm + Maven + Go)

A single SBOM spanning four package ecosystems, the way a real monorepo or a
container image SBOM looks. It exercises ecosystem-scoped matching, an
AND-joined version range, a maintainer takeover, and `--fail-on` tuning all at
once.

## Where the data came from

Two CycloneDX SBOMs of `platform-monorepo` across a month (`2026.05` ->
`2026.06`). The advisory feed carries two **real** advisories scoped by
ecosystem.

## What to expect

- `org.apache.commons:commons-text 1.10.0 -> 1.9.0` — the downgrade lands
  inside `>=1.5,<1.10.0`, re-introducing **Text4Shell** (CVE-2022-42889 /
  GHSA-599f-7c49-w659, **critical**).
- `axios 1.7.4 -> 1.6.0` — matches **CVE-2024-39338 / GHSA-8hc4-vh64-cxmj**
  (high SSRF, range `>=1.3.2,<1.7.4`).
- `internal-auth` maintainer flips `platform-security -> drifter-9921`
  (**high** maintainer-change — possible takeover of an internal package).
- `Flask` and `gin` are unchanged and clean.

Gate **FAILS** (exit 1) at default `--fail-on high`, and still fails at
`--fail-on critical` because of Text4Shell.

## Run it

```bash
python -m sbomgate scan demos/08-multi-ecosystem-monorepo/sbom-new.json \
    --old demos/08-multi-ecosystem-monorepo/sbom-old.json \
    --advisories demos/08-multi-ecosystem-monorepo/advisories.json

# triage the highest-priority items only:
python -m sbomgate scan demos/08-multi-ecosystem-monorepo/sbom-new.json \
    --old demos/08-multi-ecosystem-monorepo/sbom-old.json \
    --advisories demos/08-multi-ecosystem-monorepo/advisories.json \
    --fail-on critical
```

## How to act

Restore `commons-text>=1.10.0` and `axios>=1.7.4` immediately. Treat the
`internal-auth` maintainer change as an account-compromise investigation before
the next release ships.
