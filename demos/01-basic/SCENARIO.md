# Demo 01 - Basic: catching a risky build

This demo simulates a CI/CD pipeline running SBOMGATE between two builds of a
Python service. Between the old build and the new build, three things happened:

1. **`requests` was downgraded** from `2.32.0` to `2.5.0` (someone pinned an
   old version) - and that old version is covered by an advisory.
2. **`leftpad-utils` had its maintainer change** from `acme-security` to
   `unknown-dev-9981` - a classic supply-chain takeover signal.
3. **A brand-new dependency `shady-logger` was added**, which also matches a
   critical advisory in the local feed.
4. `colorama` was removed and `urllib3` got a routine patch bump.

## Files

- `sbom-old.json` - CycloneDX-style SBOM from the previous build.
- `sbom-new.json` - CycloneDX-style SBOM from the current build.
- `advisories.json` - a local advisory feed (no network needed).

## Run it

Full scan (diff + vulnerability match + gate), human-readable:

```
python -m sbomgate scan demos/01-basic/sbom-new.json \
    --old demos/01-basic/sbom-old.json \
    --advisories demos/01-basic/advisories.json
```

Machine-readable for pipelines:

```
python -m sbomgate scan demos/01-basic/sbom-new.json \
    --old demos/01-basic/sbom-old.json \
    --advisories demos/01-basic/advisories.json \
    --format json
```

## Expected outcome

The gate **FAILS** (exit code `1`) because there are `high`/`critical`
findings: the `shady-logger` critical vulnerability, the `requests` high
vulnerability, and the `leftpad-utils` maintainer change. You will also see
the added/removed/version-change diff findings.

Lower the bar to see it pass nothing dangerous, or raise `--fail-on critical`
to only block on critical issues.
