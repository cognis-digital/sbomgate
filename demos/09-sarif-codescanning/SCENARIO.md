# Demo 09 — SARIF 2.1.0 export for GitHub code-scanning

`sbomgate` can emit **SARIF 2.1.0** so its findings show up in the GitHub
Security tab (or any SARIF-aware viewer / SIEM). Each finding kind becomes a
SARIF rule; each finding carries a `level` and a `security-severity` band that
GitHub uses to color and rank alerts.

## Where the data came from

One CycloneDX SBOM for an API gateway pinning three Python libraries at
versions covered by **real, published** advisories.

## What to expect

Three SARIF results under the `SBOMGATE-VULN` rule:

| Component | Advisory | SARIF level | security-severity |
|---|---|---|---|
| `cryptography 41.0.0` | CVE-2023-50782 / GHSA-3ww4-gg4f-jr7f | error | 8.0 |
| `Werkzeug 2.2.3` | CVE-2023-46136 / GHSA-hrfv-mqp8-q5rw | error | 8.0 |
| `idna 3.6` | CVE-2024-3651 / GHSA-jjg7-2v4v-x38h | warning | 5.5 |

## Run it

```bash
python -m sbomgate vulns demos/09-sarif-codescanning/sbom.json \
    demos/09-sarif-codescanning/advisories.json \
    --format sarif > sbomgate.sarif
```

In CI (GitHub Actions):

```yaml
- run: python -m sbomgate vulns sbom.json advisories.json --format sarif > sbomgate.sarif
  continue-on-error: true            # let upload run even on a failing gate
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sbomgate.sarif
```

## How to act

Bump `cryptography>=42.0.0`, `Werkzeug>=2.3.8`, and `idna>=3.7`. The alerts
will auto-close on the next scan once the SBOM no longer matches.
