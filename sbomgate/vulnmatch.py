"""vulnmatch — match SBOM components against the bundled offline OSV vuln DB.

This is the offline counterpart to :mod:`sbomgate.core.match_vulnerabilities`
(which needs a hand-maintained advisory feed) and to :mod:`sbomgate.feeds`
(which needs the network for live OSV/EPSS). Here we resolve a component set
against ``sbomgate/cognis_vulndb.jsonl.gz`` — ~262k real OSV vulnerabilities —
**fully offline, no network, no key**.

The DB packages are stored with their full coordinates, e.g.

    Maven    -> "org.apache.logging.log4j:log4j-core"
    npm      -> "lodash"
    PyPI     -> "django"
    Go       -> "github.com/gin-gonic/gin"

SBOM component names rarely carry the Maven group id, so we index every DB
package both under its full name and under the short artifact id (the part
after the last ``:`` or ``/``) and match an SBOM component on either form,
scoped by ecosystem when both sides declare one.

Everything here is passive: it reads a local gzip and the in-memory component
list. It never opens a socket.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from .core import Component, Finding, _sev_rank
from .vulndb_local import VulnDB

# Map common SBOM/purl ecosystem tokens onto the OSV ecosystem spelling used in
# the bundled DB so an ecosystem-scoped match doesn't drop true positives.
_ECO_ALIAS = {
    "pypi": "pypi",
    "pip": "pypi",
    "python": "pypi",
    "npm": "npm",
    "node": "npm",
    "go": "go",
    "golang": "go",
    "maven": "maven",
    "java": "maven",
    "cargo": "crates.io",
    "crates": "crates.io",
    "crates.io": "crates.io",
    "rust": "crates.io",
    "nuget": "nuget",
    "dotnet": "nuget",
    "gem": "rubygems",
    "rubygems": "rubygems",
    "ruby": "rubygems",
    "composer": "packagist",
    "packagist": "packagist",
    "php": "packagist",
}


def _norm_eco(eco: str) -> str:
    return _ECO_ALIAS.get((eco or "").strip().lower(), (eco or "").strip().lower())


def _short_names(pkg: str) -> List[str]:
    """Return candidate match keys for a DB package coordinate.

    e.g. "org.apache.logging.log4j:log4j-core" ->
         ["org.apache.logging.log4j:log4j-core", "log4j-core"]
         "github.com/gin-gonic/gin" -> [full, "gin"]
    """
    pkg = (pkg or "").strip()
    if not pkg:
        return []
    out = [pkg]
    if ":" in pkg:
        out.append(pkg.rsplit(":", 1)[1])
    if "/" in pkg:
        out.append(pkg.rsplit("/", 1)[1])
    return out


def _cvss_band(severity: str) -> str:
    """Coerce a raw OSV severity (often a CVSS vector or numeric score) into our
    severity vocabulary so it slots into the existing gate / SARIF pipeline."""
    s = (severity or "").strip()
    if not s:
        return "unknown"
    # numeric base score?
    try:
        score = float(s)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "none"
    except ValueError:
        pass
    up = s.upper()
    # CVSS:3.x vector — read the area-impact letters as a coarse proxy.
    if up.startswith("CVSS"):
        # A vector with three High impacts + Network attack vector is critical-ish;
        # we keep this conservative and lean on KEV/EPSS for true escalation.
        highs = up.count(":H")
        if "/AV:N" in up and highs >= 3:
            return "critical"
        if highs >= 2:
            return "high"
        if highs >= 1:
            return "medium"
        return "low"
    # textual
    low = s.lower()
    for band in ("critical", "high", "medium", "moderate", "low"):
        if band in low:
            return "high" if band == "moderate" else band
    return "unknown"


def _primary_cve(record: Dict[str, Any]) -> str:
    """Prefer a CVE alias for the advisory id; fall back to the OSV/GHSA id."""
    for alias in record.get("aliases") or []:
        if str(alias).upper().startswith("CVE-"):
            return str(alias)
    return str(record.get("id") or "")


class DBMatcher:
    """Index the bundled DB by short artifact name for fast offline matching."""

    def __init__(self, db: Optional[VulnDB] = None) -> None:
        self.db = db or VulnDB()
        self._by_name: Optional[Dict[str, List[Tuple[Dict[str, Any], str]]]] = None

    def _build(self) -> None:
        if self._by_name is not None:
            return
        idx: Dict[str, List[Tuple[Dict[str, Any], str]]] = {}
        for rec in self.db:
            eco = _norm_eco(rec.get("ecosystem", ""))
            for pkg in rec.get("packages") or []:
                for key in _short_names(pkg):
                    idx.setdefault(key.lower(), []).append((rec, eco))
        self._by_name = idx

    def match_component(self, comp: Component) -> List[Finding]:
        self._build()
        assert self._by_name is not None
        name = (comp.name or "").strip().lower()
        ceco = _norm_eco(comp.ecosystem)
        seen: set = set()
        out: List[Finding] = []
        for rec, reco in self._by_name.get(name, []):
            # ecosystem scope when both sides declare one
            if ceco and reco and ceco != reco:
                continue
            rid = str(rec.get("id") or "")
            if rid in seen:
                continue
            seen.add(rid)
            cve = _primary_cve(rec)
            out.append(Finding(
                kind="vulnerability",
                component=comp.name,
                severity=_cvss_band(rec.get("severity", "")),
                detail=(rec.get("summary") or "vulnerable dependency").strip(),
                new=comp.version,
                advisory_id=cve or rid,
            ))
        return out

    def match(self, components: Iterable[Component]) -> List[Finding]:
        findings: List[Finding] = []
        for c in components:
            findings.extend(self.match_component(c))
        findings.sort(key=lambda f: (_sev_rank(f.severity), f.component, f.advisory_id))
        return findings


def match_against_db(
    components: Iterable[Component],
    db: Optional[VulnDB] = None,
) -> List[Finding]:
    """Convenience: match a component list against the bundled offline DB."""
    return DBMatcher(db).match(components)
