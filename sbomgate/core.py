"""Core engine for SBOMGATE.

No third-party imports. Pure standard library.

Supported SBOM input shapes (auto-detected):
  * CycloneDX JSON      -> top-level key "components": [{name, version, ...}]
  * SPDX JSON           -> top-level key "packages": [{name, versionInfo, ...}]
  * Native SBOMGATE     -> top-level key "components" with our own field names,
                           or a bare JSON list of component objects.

A Component is keyed by (name) within an ecosystem; version + maintainer +
purl are tracked so we can detect version bumps and maintainer takeovers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# Highest severity first. Lower index == more severe.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "none", "unknown"]


def _sev_rank(sev: str) -> int:
    s = (sev or "unknown").strip().lower()
    try:
        return SEVERITY_ORDER.index(s)
    except ValueError:
        return SEVERITY_ORDER.index("unknown")


@dataclass
class Component:
    name: str
    version: str = ""
    purl: str = ""
    maintainer: str = ""
    ecosystem: str = ""

    def key(self) -> str:
        # Identity for diffing: ecosystem + name (version-independent).
        eco = self.ecosystem.strip().lower()
        return f"{eco}:{self.name.strip().lower()}" if eco else self.name.strip().lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    kind: str            # added | removed | version-change | maintainer-change | vulnerability
    component: str
    severity: str = "none"
    detail: str = ""
    old: str = ""
    new: str = ""
    advisory_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiffResult:
    findings: List[Finding] = field(default_factory=list)
    old_count: int = 0
    new_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "old_count": self.old_count,
            "new_count": self.new_count,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
        }

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.kind] = out.get(f.kind, 0) + 1
        return out

    def max_severity(self) -> str:
        worst = "none"
        for f in self.findings:
            if _sev_rank(f.severity) < _sev_rank(worst):
                worst = f.severity.strip().lower()
        return worst


def _first(d: Dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        v = d.get(k)
        if v is None:
            continue
        if isinstance(v, (str, int, float)):
            s = str(v).strip()
            if s:
                return s
    return default


def _extract_maintainer(raw: Dict[str, Any]) -> str:
    # CycloneDX uses "publisher" or "author"; SPDX uses "supplier"/"originator";
    # ours uses "maintainer". supplier/originator are often "Organization: Foo".
    val = _first(raw, "maintainer", "publisher", "author", "supplier", "originator")
    if ":" in val and val.split(":", 1)[0].strip().lower() in ("organization", "person", "noassertion"):
        val = val.split(":", 1)[1].strip()
    return val


def _ecosystem_from_purl(purl: str) -> str:
    # pkg:pypi/requests@2.0 -> pypi
    if purl.startswith("pkg:"):
        rest = purl[4:]
        return rest.split("/", 1)[0].strip().lower()
    return ""


def _component_from_raw(raw: Dict[str, Any]) -> Optional[Component]:
    name = _first(raw, "name", "packageName")
    if not name:
        return None
    purl = _first(raw, "purl", "packageUrl")
    eco = _first(raw, "ecosystem", "type") or _ecosystem_from_purl(purl)
    # CycloneDX "type" can be application/library; don't treat those as ecosystems.
    if eco in ("application", "library", "framework", "container", "file"):
        eco = _ecosystem_from_purl(purl)
    return Component(
        name=name,
        version=_first(raw, "version", "versionInfo"),
        purl=purl,
        maintainer=_extract_maintainer(raw),
        ecosystem=eco,
    )


def parse_sbom(data: Any) -> List[Component]:
    """Parse an already-loaded JSON object into a list of Components.

    Accepts CycloneDX, SPDX, native dict, or a bare list of component dicts.
    """
    raw_list: List[Dict[str, Any]] = []
    if isinstance(data, list):
        raw_list = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        if isinstance(data.get("components"), list):       # CycloneDX / native
            raw_list = [x for x in data["components"] if isinstance(x, dict)]
        elif isinstance(data.get("packages"), list):       # SPDX
            raw_list = [x for x in data["packages"] if isinstance(x, dict)]
        else:
            raise ValueError("unrecognized SBOM: no 'components' or 'packages' array")
    else:
        raise ValueError("unrecognized SBOM: expected JSON object or array")

    comps: List[Component] = []
    for raw in raw_list:
        c = _component_from_raw(raw)
        if c is not None:
            comps.append(c)
    return comps


def load_sbom(path: str) -> List[Component]:
    """Read a JSON SBOM file from disk and parse it."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return parse_sbom(data)


def _index(components: List[Component]) -> Dict[str, Component]:
    out: Dict[str, Component] = {}
    for c in components:
        out[c.key()] = c
    return out


def diff_sboms(old: List[Component], new: List[Component]) -> DiffResult:
    """Compute the structural diff between two component lists.

    Emits findings of kind: added, removed, version-change, maintainer-change.
    Maintainer changes are flagged 'high' severity (supply-chain takeover risk).
    """
    oidx = _index(old)
    nidx = _index(new)
    result = DiffResult(old_count=len(oidx), new_count=len(nidx))

    for key in sorted(nidx.keys()):
        if key not in oidx:
            c = nidx[key]
            result.findings.append(Finding(
                kind="added",
                component=c.name,
                severity="low",
                detail=f"new dependency {c.name} {c.version}".strip(),
                new=c.version,
            ))

    for key in sorted(oidx.keys()):
        if key not in nidx:
            c = oidx[key]
            result.findings.append(Finding(
                kind="removed",
                component=c.name,
                severity="none",
                detail=f"dependency {c.name} {c.version} removed".strip(),
                old=c.version,
            ))

    for key in sorted(set(oidx) & set(nidx)):
        oc, nc = oidx[key], nidx[key]
        if oc.version != nc.version:
            result.findings.append(Finding(
                kind="version-change",
                component=nc.name,
                severity="low",
                detail=f"{nc.name} {oc.version} -> {nc.version}",
                old=oc.version,
                new=nc.version,
            ))
        # Maintainer takeover: only flag when both sides actually declare one
        # and they differ. A blank-on-one-side is treated as metadata noise.
        if oc.maintainer and nc.maintainer and oc.maintainer != nc.maintainer:
            result.findings.append(Finding(
                kind="maintainer-change",
                component=nc.name,
                severity="high",
                detail=f"maintainer of {nc.name} changed (possible takeover)",
                old=oc.maintainer,
                new=nc.maintainer,
            ))
    return result


def load_advisories(path: str) -> List[Dict[str, Any]]:
    """Load a local advisory feed.

    Feed format: JSON list (or {"advisories": [...]}) of objects:
      {"id": "GHSA-xxxx", "name": "requests", "ecosystem": "pypi",
       "severity": "high", "affected": ["<2.31.0", "==2.5.0"],
       "summary": "..."}
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("advisories"), list):
        data = data["advisories"]
    if not isinstance(data, list):
        raise ValueError("advisory feed must be a JSON list or {'advisories': [...]}")
    return [a for a in data if isinstance(a, dict)]


def _split_version(v: str) -> Tuple[Any, ...]:
    parts: List[Any] = []
    for chunk in v.replace("-", ".").split("."):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk.isdigit():
            parts.append((0, int(chunk)))
        else:
            parts.append((1, chunk))  # non-numeric sorts after numeric
    return tuple(parts)


def _cmp_version(a: str, b: str) -> int:
    va, vb = _split_version(a), _split_version(b)
    if va < vb:
        return -1
    if va > vb:
        return 1
    return 0


def _version_matches(version: str, constraint: str) -> bool:
    """Evaluate a single constraint like '<2.31.0', '>=1.0', '==2.5.0', '2.5.0'."""
    constraint = constraint.strip()
    if not constraint:
        return False
    if not version:
        return False
    op = "=="
    rest = constraint
    for candidate in ("<=", ">=", "==", "<", ">", "="):
        if constraint.startswith(candidate):
            op = "==" if candidate == "=" else candidate
            rest = constraint[len(candidate):].strip()
            break
    else:
        # bare version means exact match
        op = "=="
        rest = constraint
    c = _cmp_version(version, rest)
    if op == "==":
        return c == 0
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    return False


def _affected(version: str, affected: Any) -> bool:
    """affected may be a string of comma-joined constraints, or a list.

    A list of constraints is OR-ed (any matching range hits). A single
    string with commas is AND-ed (all must hold) so you can express
    '>=2.0,<2.31.0'.
    """
    if isinstance(affected, str):
        clauses = [c for c in affected.split(",") if c.strip()]
        return bool(clauses) and all(_version_matches(version, c) for c in clauses)
    if isinstance(affected, list):
        for entry in affected:
            if isinstance(entry, str):
                clauses = [c for c in entry.split(",") if c.strip()]
                if clauses and all(_version_matches(version, c) for c in clauses):
                    return True
        return False
    return False


def match_vulnerabilities(
    components: List[Component],
    advisories: List[Dict[str, Any]],
) -> List[Finding]:
    """Match the component set against the advisory feed."""
    findings: List[Finding] = []
    for c in components:
        cname = c.name.strip().lower()
        ceco = c.ecosystem.strip().lower()
        for adv in advisories:
            aname = _first(adv, "name", "package", "component").strip().lower()
            if aname != cname:
                continue
            aeco = _first(adv, "ecosystem").strip().lower()
            if aeco and ceco and aeco != ceco:
                continue
            if not _affected(c.version, adv.get("affected", [])):
                continue
            findings.append(Finding(
                kind="vulnerability",
                component=c.name,
                severity=_first(adv, "severity", default="unknown").lower(),
                detail=_first(adv, "summary", "description", default="vulnerable dependency"),
                new=c.version,
                advisory_id=_first(adv, "id", "ghsa", "cve"),
            ))
    findings.sort(key=lambda f: (_sev_rank(f.severity), f.component))
    return findings


def gate(findings: List[Finding], fail_on: str = "high") -> bool:
    """Return True if the pipeline should FAIL.

    Fails when any finding's severity is at or above `fail_on`.
    """
    threshold = _sev_rank(fail_on)
    for f in findings:
        if _sev_rank(f.severity) <= threshold:
            return True
    return False
