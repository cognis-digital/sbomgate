# Demo 05 — A dependency downgrade re-introduces a fixed critical CVE

A common, dangerous regression: a lockfile resolution (or a careless pin)
pulls a transitive dependency **backwards** past the version that fixed a
known critical. The diff alone looks harmless ("just a version change") — the
vuln match is what makes it actionable.

## Where the data came from

Two CycloneDX SBOMs from consecutive builds of a Python data pipeline
(`cyclonedx-py` / `syft` style). Between `3.2.0` and `3.3.0`, two libraries
were pinned to *older* versions.

## What to expect

- `PyYAML 5.4.1 -> 5.3.1` — the downgrade crosses back below 5.4, so
  **CVE-2020-14343 / GHSA-8q59-q68h-6hv4** (critical RCE via `full_load`)
  re-appears.
- `Jinja2 3.1.4 -> 2.11.2` — re-introduces **CVE-2020-28493 /
  GHSA-g3rq-g295-4j3m** (medium ReDoS in `urlize`).
- `requests` is unchanged and clean.

Gate **FAILS** (exit 1) on the PyYAML critical.

## Run it

```bash
python -m sbomgate scan demos/05-transitive-critical/sbom-new.json \
    --old demos/05-transitive-critical/sbom-old.json \
    --advisories demos/05-transitive-critical/advisories.json
```

## How to act

Treat downgrades of security-fixed packages as build-breaking. Restore
`PyYAML>=5.4` and `Jinja2>=2.11.3`, and add a floor pin so resolution cannot
walk back across a fixed CVE again.
