# Demo 07 — Same package name, different ecosystem (no false positive)

Package names are **not** unique across ecosystems. `requests` exists on both
PyPI and npm. A naive name-only matcher would flag both when an advisory only
applies to one. `sbomgate` scopes matches by `ecosystem` (derived from the
purl), so the wrong-ecosystem package is left alone.

## Where the data came from

One CycloneDX SBOM for a polyglot service that vendors **two** different
packages that happen to share the name `requests`:

- `pkg:pypi/requests@2.19.0` — the Python HTTP library, on an old version.
- `pkg:npm/requests@2.88.2` — an unrelated npm package of the same name.

## What to expect

- Exactly **one** finding: the PyPI `requests@2.19.0` matches
  **CVE-2018-18074 / GHSA-x84v-xcm2-53pg** (high, credential leak on redirect,
  fixed in 2.20.0). The advisory's `ecosystem: pypi` constrains it.
- The npm `requests@2.88.2` is **not** flagged — different ecosystem.

Gate **FAILS** (exit 1) on the single high finding.

## Run it

```bash
python -m sbomgate vulns demos/07-ecosystem-mismatch/sbom.json \
    demos/07-ecosystem-mismatch/advisories.json
```

## How to act

This demo is here so you can trust that `sbomgate`'s alerts are ecosystem-aware
and won't drown a polyglot monorepo in cross-ecosystem false positives. Fix the
real one: bump PyPI `requests` to `>=2.20.0`.
