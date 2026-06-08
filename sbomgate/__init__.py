"""SBOMGATE - Continuous SBOM diff & vulnerability watch with maintainer-change tracking.

A zero-install, standard-library-only tool that compares two Software Bill of
Materials (SBOM) snapshots (CycloneDX or SPDX-tag-value style JSON, or its own
simple component list), reports added/removed/version-changed components,
tracks maintainer/supplier changes (a supply-chain red flag), and matches
components against a local vulnerability advisory feed.

The goal is CI/CD gating: run on every build, fail the pipeline when new
critical vulnerabilities appear or when a dependency's maintainer silently
changes.
"""
from .core import (
    Component,
    Finding,
    DiffResult,
    load_sbom,
    parse_sbom,
    diff_sboms,
    match_vulnerabilities,
    load_advisories,
    gate,
    SEVERITY_ORDER,
)

TOOL_NAME = "sbomgate"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Component",
    "Finding",
    "DiffResult",
    "load_sbom",
    "parse_sbom",
    "diff_sboms",
    "match_vulnerabilities",
    "load_advisories",
    "gate",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "TOOL_VERSION",
]
