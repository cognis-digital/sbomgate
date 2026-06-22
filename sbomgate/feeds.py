"""feeds — real, edge/air-gap-deployable threat-intel ingestion for SBOMGATE.

Wraps the bundled :mod:`sbomgate.datafeeds` engine (keyless HTTPS fetch -> disk
cache -> offline re-serve -> air-gap snapshot) and restricts the 17-feed Cognis
catalog to the three feeds that genuinely improve SBOMGATE's vulnerability
output:

  * ``cisa-kev``  CISA Known Exploited Vulnerabilities
        https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
        -> the authoritative list of CVEs observed *actively exploited in the
           wild*. A dependency vuln that is on this list is a drop-everything,
           patch-now item, so we escalate it to ``critical`` and tag it KEV.
  * ``epss``      FIRST EPSS exploit-probability scores
        https://api.first.org/data/v1/epss
        -> a 0..1 probability that a given CVE will be exploited in the next 30
           days. We attach the score so triage can rank a wall of "high"
           findings by real-world exploitation likelihood.
  * ``osv``       OSV.dev package->vulnerability query
        https://api.osv.dev/v1/query
        -> resolve known vulnerabilities for a package@version across
           ecosystems, so the gate works even without a hand-maintained
           advisory feed.

Everything here is defensive / authorized-use only. No feed endpoints are
invented — every URL comes from the bundled ``data_feeds_2026.json`` catalog.

Edge / air-gap:
  * ``--offline`` serves only the on-disk cache (``COGNIS_FEEDS_CACHE``,
    default ~/.cache/cognis-feeds); it never touches the network.
  * ``datafeeds snapshot-export feeds.tar.gz`` tars the cache for sneakernet
    into a disconnected enclave, where ``snapshot-import`` rehydrates it.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from . import datafeeds

# Only these catalog feeds are relevant to an SBOM vulnerability gate.
RELEVANT_FEEDS = ["cisa-kev", "epss", "osv"]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# catalog (filtered to this tool's domain)
# --------------------------------------------------------------------------- #
def catalog() -> List[Dict[str, Any]]:
    """Return the catalog entries for this tool's relevant feeds only."""
    by_id = {f["id"]: f for f in datafeeds.load_catalog().get("feeds", [])}
    return [by_id[fid] for fid in RELEVANT_FEEDS if fid in by_id]


def is_relevant(feed_id: str) -> bool:
    return feed_id in RELEVANT_FEEDS


def _require_relevant(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEEDS:
        raise KeyError(
            f"{feed_id!r} is not a SBOMGATE feed; choose one of {RELEVANT_FEEDS}"
        )


# --------------------------------------------------------------------------- #
# CISA-KEV: set of actively-exploited CVE ids
# --------------------------------------------------------------------------- #
def kev_cve_set(*, offline: bool = False) -> set[str]:
    """Return the uppercase CVE ids on the CISA Known-Exploited list."""
    data = datafeeds.get("cisa-kev", offline=offline)
    out: set[str] = set()
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    for v in vulns:
        cve = (v.get("cveID") or v.get("cveId") or "").strip().upper()
        if cve:
            out.add(cve)
    return out


# --------------------------------------------------------------------------- #
# EPSS: CVE -> exploitation probability (0..1)
# --------------------------------------------------------------------------- #
def epss_scores(cves: Iterable[str], *, offline: bool = False) -> Dict[str, float]:
    """Return {CVE: epss_probability} for the requested CVEs.

    Online, EPSS is queried in a single batched ``?cve=A,B,C`` request. Offline,
    we read whatever EPSS rows are already cached and filter to the request.
    """
    wanted = {c.strip().upper() for c in cves if c and _CVE_RE.fullmatch(c.strip())}
    if not wanted:
        return {}

    if offline:
        # Air-gap: read whatever EPSS rows were cached/snapshotted.
        data = datafeeds.get("epss", offline=True)
    else:
        # The EPSS endpoint is a GET that filters on ?cve=A,B,C. The generic
        # engine only bodies POSTs, so build the filtered URL here and fetch it
        # directly (single batched call) rather than pulling the unfiltered top-N.
        import json as _json
        by_id = {f["id"]: f for f in datafeeds.load_catalog().get("feeds", [])}
        base = by_id["epss"]["url"]
        url = f"{base}?cve={','.join(sorted(wanted))}"
        data = _json.loads(datafeeds.fetch(url).decode("utf-8", "replace"))

    out: Dict[str, float] = {}
    rows = data.get("data", []) if isinstance(data, dict) else []
    for row in rows:
        cve = (row.get("cve") or "").strip().upper()
        if cve in wanted:
            try:
                out[cve] = float(row.get("epss", 0.0))
            except (TypeError, ValueError):
                continue
    return out


# --------------------------------------------------------------------------- #
# OSV: package@version -> known vulnerabilities
# --------------------------------------------------------------------------- #
_OSV_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "crates": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "packagist": "Packagist",
}


def osv_query(name: str, version: str, ecosystem: str, *, offline: bool = False) -> List[Dict[str, Any]]:
    """Query OSV.dev for vulnerabilities affecting name@version in ecosystem.

    Offline this is a no-op (returns []) — OSV is a per-package POST that we do
    not pre-cache; KEV+EPSS are the cached enrichment that works air-gapped.
    """
    if offline:
        return []
    eco = _OSV_ECOSYSTEM.get((ecosystem or "").strip().lower())
    if not eco or not name:
        return []
    query = {"version": version, "package": {"name": name, "ecosystem": eco}}
    try:
        data = datafeeds.get("osv", offline=False, query=query)
    except Exception:  # network/transient; OSV is best-effort enrichment
        return []
    return data.get("vulns", []) if isinstance(data, dict) else []


# --------------------------------------------------------------------------- #
# enrichment: fold KEV + EPSS into vulnerability findings
# --------------------------------------------------------------------------- #
def _finding_cve(f: Any) -> Optional[str]:
    """Pull a CVE id out of a finding's advisory_id (or its detail text)."""
    aid = (getattr(f, "advisory_id", "") or "").strip()
    m = _CVE_RE.search(aid) or _CVE_RE.search(getattr(f, "detail", "") or "")
    return m.group(0).upper() if m else None


def enrich_findings(findings: List[Any], *, offline: bool = False) -> Dict[str, Any]:
    """Annotate vulnerability findings in place with CISA-KEV + EPSS context.

    For every finding whose advisory id resolves to a CVE:
      * if the CVE is on the CISA-KEV list, prepend ``[KEV]`` to the detail and
        escalate the finding to ``critical`` (actively exploited == patch now);
      * attach the EPSS probability to the detail (``EPSS=0.97``) so a triage
        queue can be ranked by real exploitation likelihood.

    Returns a small summary dict (counts + the KEV/EPSS data used) for reports.
    """
    cve_by_finding: Dict[int, str] = {}
    for i, f in enumerate(findings):
        if getattr(f, "kind", "") != "vulnerability":
            continue
        cve = _finding_cve(f)
        if cve:
            cve_by_finding[i] = cve

    cves = set(cve_by_finding.values())
    if not cves:
        return {"enriched": 0, "kev": 0, "epss_scored": 0, "epss": {}, "kev_cves": []}

    kev = kev_cve_set(offline=offline)
    scores = epss_scores(cves, offline=offline)

    enriched = kev_hits = 0
    for i, cve in cve_by_finding.items():
        f = findings[i]
        tags: List[str] = []
        on_kev = cve in kev
        if on_kev:
            kev_hits += 1
            tags.append("KEV")
            # Actively exploited in the wild — strongest possible signal.
            f.severity = "critical"
        if cve in scores:
            tags.append(f"EPSS={scores[cve]:.4f}")
        if tags:
            enriched += 1
            f.detail = f"[{' '.join(tags)}] {f.detail}".strip()
            # record the score on the finding object for JSON consumers
            try:
                setattr(f, "epss", scores.get(cve))
                setattr(f, "known_exploited", on_kev)
            except Exception:  # dataclass without slots tolerates this
                pass

    return {
        "enriched": enriched,
        "kev": kev_hits,
        "epss_scored": sum(1 for c in cves if c in scores),
        "epss": {c: scores[c] for c in sorted(scores)},
        "kev_cves": sorted(c for c in cves if c in kev),
    }


# --------------------------------------------------------------------------- #
# thin CLI passthroughs used by `sbomgate feeds ...`
# --------------------------------------------------------------------------- #
def cli_list() -> int:
    for f in catalog():
        age = datafeeds.cached_age_hours(f["id"])
        fresh = "uncached" if age is None else f"{age:.1f}h old"
        print(f"  {f['id']:10} {f.get('domain',''):6} [{fresh:>10}]  {f['name']}")
        print(f"             {f.get('url','')}")
    return 0


def cli_update(feed_ids: List[str]) -> int:
    targets = feed_ids or list(RELEVANT_FEEDS)
    rc = 0
    for fid in targets:
        try:
            _require_relevant(fid)
            pth = datafeeds.update(fid)
            print(f"  updated {fid} -> {pth.stat().st_size} bytes")
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"  {fid}: {e}")
            rc = 1
    return rc


def cli_get(feed_id: str, *, offline: bool = False) -> int:
    import json as _json
    try:
        _require_relevant(feed_id)
        data = datafeeds.get(feed_id, offline=offline)
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}")
        return 1
    text = _json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
    print(text[:4000])
    return 0
