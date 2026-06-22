# Demo 04 — SPDX-format SBOM from a Node.js build

`sbomgate` auto-detects SBOM format. This demo proves the **SPDX 2.3** path
(top-level `packages[]`, `versionInfo`, `supplier`, purl in `externalRefs`)
works just as well as CycloneDX.

## Where the data came from

`sbom.json` is a trimmed SPDX document of the kind `syft` emits when scanning
a JavaScript front-end (`syft <dir> -o spdx-json`). It pins three popular npm
packages, two of them at versions covered by **real, published** advisories.

## What to expect

- `lodash@4.17.20` → **high** — CVE-2021-23337 / GHSA-35jh-r3h4-6jhm
  (command injection, fixed in 4.17.21).
- `minimist@1.2.5` → **critical** — CVE-2021-44906 / GHSA-xvch-5gv4-984h
  (prototype pollution, fixed in 1.2.6).
- `express@4.19.2` → clean (no matching advisory).

The gate **FAILS** (exit 1) at the default `--fail-on high`.

## Run it

```bash
python -m sbomgate vulns demos/04-spdx-format-nodejs/sbom.json \
    demos/04-spdx-format-nodejs/advisories.json
```

## How to act

Bump `lodash` to `>=4.17.21` and `minimist` to `>=1.2.6`, regenerate the SBOM,
and re-run — the gate should pass.
