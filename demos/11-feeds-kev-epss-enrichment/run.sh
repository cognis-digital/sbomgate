#!/usr/bin/env sh
# Demo 11: enrich SBOM vuln findings with CISA-KEV + EPSS, fully offline.
# Points the feed cache at the committed trimmed fixtures so this runs with
# zero network on an air-gapped box.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

export COGNIS_FEEDS_CACHE="${COGNIS_FEEDS_CACHE:-$ROOT/tests/fixtures/feeds-cache}"
cd "$ROOT"

echo "== feeds available (offline) =="
python -m sbomgate feeds list

echo
echo "== vulns WITHOUT enrichment (all high) =="
python -m sbomgate vulns "$HERE/sbom.json" "$HERE/advisories.json" --format table || true

echo
echo "== vulns WITH CISA-KEV + EPSS enrichment (offline) =="
python -m sbomgate vulns "$HERE/sbom.json" "$HERE/advisories.json" \
  --enrich --offline --format table || true
