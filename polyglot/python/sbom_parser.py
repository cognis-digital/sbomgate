"""
sbom_parser.py - SPDX 2.3 SBOM Parser for sbomgate

Parses SPDX-formatted Software Bill of Materials and extracts structured
package metadata ready for vulnerability scanning and diff analysis.

Supports:
    - SPDX 2.3 JSON format (primary)
    - Nested dependencies via "dependsOn" relationships
    - Package prefixes: pkg:, npm:, maven:, pypi:, etc.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedPackage:
    """Normalized package representation."""
    name: str
    version: str = ""
    pypi_name: str | None = None
    source: str | None = None
    license: str | None = None
    description: str | None = None
    checksums: dict[str, str] = field(default_factory=dict)
    depends_on: list["ParsedPackage"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class ParsedSBOM:
    """Top-level SBOM structure."""
    spdx_version: str = ""
    name: str | None = None
    data_license: str | None = None
    document_namespace: str | None = None
    packages: list[ParsedPackage] = field(default_factory=list)
    metadata_packages: list[ParsedPackage] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spdx_version": self.spdx_version,
            "name": self.name,
            "data_license": self.data_license,
            "document_namespace": self.document_namespace,
            "packages": [p.to_dict() for p in self.packages],
            "metadata_packages": [p.to_dict() for p in self.metadata_packages],
        }


class SBOMParser:
    """SPDX 2.3 parser with normalization and validation."""

    # SPDX 2.3 context mappings
    CONTEXT_MAP = {
        "https://spdx.org/rdf/terms#package": "pkg:",
        "https://spdx.org/rdf/terms#metadataPackage": "meta:",
        "https://spdx.org/rdf/terms#checksum256": "sha256:",
        "https://spdx.org/rdf/terms#checksum160": "sha1:",
        "https://spdx.org/rdf/terms#checksum512": "sha384:",
        "https://spdx.org/rdf/terms#checksum128": "md5:",
    }

    # Common prefix patterns for package names
    PREFIX_PATTERNS = [
        (r"^pkg:(.+)$", 1, "pkg"),
        (r"^npm:(.+)$", 1, "npm"),
        (r"^maven:(.+)$", 1, "maven"),
        (r"^pypi:(.+)$", 1, "pypi"),
    ]

    def __init__(self):
        self._context_map: dict[str, str] = {}

    def _load_context(self, context: Any) -> None:
        """Extract prefix mappings from @context."""
        if isinstance(context, list):
            for item in context:
                if isinstance(item, dict) and "@id" in item:
                    self._context_map[item["@id"]] = item.get("@type", "")

    def _resolve_prefix(self, name: str) -> tuple[str, str | None]:
        """Resolve package prefix to canonical form."""
        for pattern, group, prefix in self.PREFIX_PATTERNS:
            match = re.match(pattern, name)
            if match:
                return (prefix, match.group(group))

        # Check context map
        for url, prefix in self._context_map.items():
            if url in name:
                return (prefix, name.replace(url, ""))

        return ("pkg", name)

    def _parse_checksum(self, checksum: Any) -> dict[str, str]:
        """Extract and normalize checksum data."""
        result = {}
        if isinstance(checksum, list):
            for item in checksum:
                if isinstance(item, dict) and "checksumMethod" in item:
                    method = item["checksumMethod"]
                    value = item.get("checksumValue", "")
                    # Normalize method name
                    normalized = method.lower()
                    result[normalized] = value

        return result

    def _parse_package(self, pkg: dict[str, Any], parent: "ParsedPackage" | None = None) -> ParsedPackage:
        """Parse a single SPDX package entry."""
        # Extract basic fields
        name = pkg.get("name", "") or ""
        version = pkg.get("versionInfo", "") or ""

        # Resolve prefix
        prefix, clean_name = self._resolve_prefix(name)

        # Build pypi_name (canonical identifier)
        pypi_name = f"{prefix}:{clean_name}" if clean_name else None

        # Parse checksums
        checksums = {}
        if "checksum" in pkg:
            checksums = self._parse_checksum(pkg["checksum"])

        # Extract license
        license_field = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        license_str = license_field.strip() if license_field else None

        # Build depends_on list
        depends_on: list[ParsedPackage] = []
        if "dependsOn" in pkg:
            for dep_ref in pkg["dependsOn"]:
                if isinstance(dep_ref, dict):
                    dep_name = dep_ref.get("ref", "") or ""
                    dep_version = dep_ref.get("versionInfo", "") or ""

                    # Resolve prefix for dependency
                    dep_prefix, dep_clean = self._resolve_prefix(dep_name)
                    dep_pypi = f"{dep_prefix}:{dep_clean}" if dep_clean else None

                    dep_pkg = ParsedPackage(
                        name=dep_name,
                        version=dep_version,
                        pypi_name=dep_pypi,
                        source=None,  # Would need to resolve from ref
                        license=None,
                        description=None,
                        checksums={},
                        depends_on=[],
                    )

                    if parent:
                        dep_pkg.source = f"{parent.name}@{parent.version}"

                    depends_on.append(dep_pkg)

        return ParsedPackage(
            name=name,
            version=version,
            pypi_name=pypi_name,
            source=None,  # Could extract from @ref if needed
            license=license_str,
            description=pkg.get("description") or None,
            checksums=checksums,
            depends_on=depends_on,
        )

    def parse(self, data: str | dict[str, Any]) -> ParsedSBOM:
        """Parse SPDX 2.3 SBOM from JSON string or object."""
        # Normalize input
        if isinstance(data, str):
            try:
                sbom = json.loads(data)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in SBOM: {e}")

            # Extract @context
            context = sbom.get("@context")
            if context:
                self._load_context(context)

        else:
            sbom = data

        # Extract top-level metadata
        spdx_version = sbom.get("spdxVersion", "2.3")
        name = sbom.get("name") or sbom.get("dataLicense")
        document_namespace = sbom.get("documentNamespace")

        # Parse packages
        packages: list[ParsedPackage] = []
        metadata_packages: list[ParsedPackage] = []

        if "packages" in sbom:
            for pkg_data in sbom["packages"]:
                try:
                    parsed = self._parse_package(pkg_data)
                    packages.append(parsed)
                except Exception as e:
                    # Log but continue parsing
                    print(f"Warning: Failed to parse package {pkg_data.get('name', 'unknown')}: {e}")

        if "metadataPackages" in sbom:
            for pkg_data in sbom["metadataPackages"]:
                try:
                    parsed = self._parse_package(pkg_data)
                    metadata_packages.append(parsed)
                except Exception as e:
                    print(f"Warning: Failed to parse metadata package {pkg_data.get('name', 'unknown')}: {e}")

        return ParsedSBOM(
            spdx_version=spdx_version,
            name=name,
            data_license=sbom.get("dataLicense"),
            document_namespace=document_namespace,
            packages=packages,
            metadata_packages=metadata_packages,
        )


def main():
    """Demo/test harness for SBOMParser."""

    # Sample SPDX 2.3 SBOM (minimal valid example)
    SAMPLE_SBOM = {
        "@context": [
            "https://spdx.org/rdf/terms#package",
            "https://spdx.org/rdf/terms#checksum256",
        ],
        "spdxVersion": "2.3",
        "name": "Demo Application SBOM",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/demo-sbom",
        "packages": [
            {
                "name": "pkg:py/numpy@1.24.3",
                "versionInfo": "1.24.3",
                "checksum": [
                    {"checksumMethod": "SHA256", "checksumValue": "abc123..."}
                ],
                "licenseConcluded": "BSD-3-Clause",
                "description": "NumPy array library",
            },
            {
                "name": "pkg:py/pandas@2.0.3",
                "versionInfo": "2.0.3",
                "checksum": [
                    {"checksumMethod": "SHA1", "checksumValue": "def456..."}
                ],
                "licenseConcluded": "BSD-3-Clause",
            },
        ],
    }

    parser = SBOMParser()
    sbom = parser.parse(json.dumps(SAMPLE_SBOM))

    print("=== Parsed SBOM ===")
    print(f"Version: {sbom.spdx_version}")
    print(f"Name: {sbom.name}")
    print(f"License: {sbom.data_license}")
    print(f"Namespace: {sbom.document_namespace}")
    print(f"\nPackages found: {len(sbom.packages)}")

    for pkg in sbom.packages:
        print(f"\n  Package: {pkg.name} v{pkg.version}")
        print(f"    PyPI name: {pkg.pypi_name}")
        print(f"    License: {pkg.license}")
        print(f"    Checksums: {pkg.checksums}")

    # Output as JSON for downstream processing
    print("\n=== JSON Output ===")
    print(json.dumps(sbom.to_dict(), indent=2))


if __name__ == "__main__":
    main()