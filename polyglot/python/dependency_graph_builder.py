"""
polyglot/python/dependency_graph_builder.py

Continuous SBOM diff & vulnerability watch with maintainer-change tracking.
Core module: dependency graph builder.

Provides parsing for pip, npm, maven, cargo, go modules, and more. Builds a
directed graph of dependencies, tracks maintainer changes, detects transitive
vulnerabilities, and provides diff capabilities between SBOM versions.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, TypeVar, Union
)

import networkx as nx


# =============================================================================
# ENUMS & CONSTANTS
# =============================================================================

class Ecosystem(Enum):
    """Supported package ecosystems."""
    PIP = auto()      # Python pip
    NPM = auto()      # Node.js npm/yarn
    MAVEN = auto()   # Java Maven
    CARGO = auto()    # Rust cargo
    GO_MOD = auto()  # Go modules
    GEM = auto()     # Ruby gems
    COMPOUND = auto() # Compound/mixed


class DependencyType(Enum):
    """Types of dependency relationships."""
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    DEV = "dev"
    OPTIONAL = "optional"
    PEER = "peer"
    RUNTIME = "runtime"
    BUILD_TOOL = "build_tool"


class ResolutionStatus(Enum):
    """Dependency resolution states."""
    PENDING = "pending"
    RESOLVING = "resolving"
    RESOLVED = "resolved"
    FAILED = "failed"
    PARTIAL = "partial"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass(frozen=True)
class PackageRef:
    """Unique identifier for a package across ecosystems."""
    ecosystem: Ecosystem
    name: str
    version: Optional[str] = None
    
    def __hash__(self):
        return hash((self.ecosystem, self.name, self.version or ""))
    
    def __eq__(self, other):
        if isinstance(other, PackageRef):
            return (self.ecosystem == other.ecosystem and 
                    self.name == other.name and 
                    self.version == other.version)
        return False
    
    @property
    def canonical(self) -> str:
        """Returns a stable string representation."""
        v = f"{self.version}" if self.version else "latest"
        return f"{self.ecosystem.value}:{self.name}@{v}"


@dataclass
class PackageInfo:
    """Metadata for a single package."""
    ref: PackageRef
    name: str
    version: Optional[str] = None
    ecosystem: Ecosystem = Ecosystem.COMPOUND
    source: Optional[Path] = None  # Original SBOM source file
    resolved_at: Optional[datetime] = None
    
    def __hash__(self):
        return hash(self.ref)


@dataclass
class DependencyEdge:
    """Relationship between two packages."""
    from_ref: PackageRef
    to_ref: PackageRef
    dep_type: DependencyType = DependencyType.DIRECT
    constraints: List[str] = field(default_factory=list)  # Version constraints
    
    def __hash__(self):
        return hash((self.from_ref, self.to_ref, self.dep_type))


@dataclass
class MaintainerRecord:
    """Track maintainer changes over time."""
    package_ref: PackageRef
    name: str
    email: Optional[str] = None
    github_id: Optional[str] = None
    role: str = "contributor"  # contributor, committer, owner, admin
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    commits_count: int = 0
    
    def __hash__(self):
        return hash((self.package_ref, self.name))


@dataclass
class VulnerabilityRecord:
    """Vulnerability information for a package."""
    ref: PackageRef
    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    published_date: datetime = field(default_factory=datetime.now)
    description: str = ""
    affected_versions: List[str] = field(default_factory=list)
    fixed_version: Optional[str] = None
    
    def __hash__(self):
        return hash((self.ref, self.cve_id))


# =============================================================================
# GRAPH DATA STRUCTURE
# =============================================================================

class DependencyGraph:
    """
    Production-grade dependency graph with metadata tracking.
    
    Supports:
    - Multi-ecosystem packages (via canonical names)
    - Time-travel queries for maintainer history
    - Vulnerability correlation across versions
    - Fast diff operations between SBOM snapshots
    """
    
    def __init__(self, name: str = "default"):
        self.name = name
        self._graph: nx.DiGraph = nx.DiGraph()
        self._packages: Dict[PackageRef, PackageInfo] = {}
        self._edges: Set[DependencyEdge] = set()
        self._maintainers: Dict[Tuple[str, str], List[MaintainerRecord]] = defaultdict(list)
        self._vulnerabilities: Dict[PackageRef, List[VulnerabilityRecord]] = defaultdict(list)
        self._resolution_status: ResolutionStatus = ResolutionStatus.PENDING
        
    @property
    def graph(self) -> nx.DiGraph:
        """Returns the underlying NetworkX graph."""
        return self._graph
    
    @property
    def packages(self) -> Dict[PackageRef, PackageInfo]:
        """All known packages."""
        return self._packages.copy()
    
    @property
    def edges(self) -> Set[DependencyEdge]:
        """All dependency relationships."""
        return self._edges.copy()
    
    @property
    def vulnerabilities(self) -> Dict[PackageRef, List[VulnerabilityRecord]]:
        """Vulnerabilities grouped by package."""
        return dict(self._vulnerabilities)
    
    def add_package(
        self, 
        info: PackageInfo,
        force: bool = False
    ) -> None:
        """Add or update a package in the graph."""
        ref = info.ref
        
        if ref in self._packages and not force:
            existing = self._packages[ref]
            # Merge metadata
            if info.resolved_at:
                existing.resolved_at = max(existing.resolved_at, info.resolved_at)
        
        else:
            self._packages[ref] = info
        
    def add_edge(
        self, 
        from_ref: PackageRef, 
        to_ref: PackageRef, 
        dep_type: DependencyType = DependencyType.DIRECT,
        constraints: Optional[List[str]] = None
    ) -> bool:
        """Add a dependency edge. Returns True if added."""
        existing_edge = self._find_existing_edge(from_ref, to_ref)
        
        if existing_edge and not (existing_edge.dep_type == dep_type):
            # Update existing edge type
            existing_edge.dep_type = dep_type
        
        elif not existing_edge:
            new_edge = DependencyEdge(
                from_ref=from_ref, 
                to_ref=to_ref, 
                dep_type=dep_type,
                constraints=constraints or []
            )
            self._graph.add_edge(from_ref, to_ref, edge_data=new_edge)
            self._edges.add(new_edge)
        
        return True
    
    def _find_existing_edge(
        self, 
        from_ref: PackageRef, 
        to_ref: PackageRef
    ) -> Optional[DependencyEdge]:
        """Find existing edge between two packages."""
        if from_ref in self._graph and to_ref in self._graph:
            for data in self._graph.get_edge_data(from_ref, to_ref).values():
                if isinstance(data, DependencyEdge):
                    return data
        
        # Check reverse (for undirected relationships)
        if from_ref in self._graph and to_ref in self._graph:
            for data in self._graph.get_edge_data(to_ref, from_ref).values():
                if isinstance(data, DependencyEdge):
                    return data
        
        return None
    
    def get_neighbors(self, ref: PackageRef) -> List[PackageRef]:
        """Get all neighbors (dependencies and dependents) of a package."""
        result = []
        
        # Direct dependencies (packages this one depends on)
        if ref in self._graph:
            for neighbor in self._graph.successors(ref):
                result.append(neighbor)
        
        # Packages that depend on this one
        for neighbor in self._graph.predecessors(ref):
            result.append(neighbor)
        
        return list(set(result))
    
    def get_transitive_dependencies(
        self, 
        start_ref: PackageRef, 
        max_depth: int = 10,
        visited: Optional[Set[PackageRef]] = None
    ) -> List[Tuple[PackageRef, int]]:
        """
        Get all transitive dependencies with depth.
        
        Returns list of (package_ref, depth) tuples.
        """
        if visited is None:
            visited = set()
        
        result = []
        queue = [(start_ref, 0)]
        
        while queue:
            current, depth = queue.pop(0)
            
            if depth > max_depth or current in visited:
                continue
            
            visited.add(current)
            
            # Add direct dependencies
            for neighbor in self._graph.successors(current):
                new_depth = depth + 1
                result.append((neighbor, new_depth))
                
                if new_depth < max_depth:
                    queue.append((neighbor, new_depth))
        
        return result
    
    def get_transitive_dependents(
        self, 
        start_ref: PackageRef, 
        max_depth: int = 10,
        visited: Optional[Set[PackageRef]] = None
    ) -> List[Tuple[PackageRef, int]]:
        """Get all packages that depend on this one transitively."""
        if visited is None:
            visited = set()
        
        result = []
        queue = [(start_ref, 0)]
        
        while queue:
            current, depth = queue.pop(0)
            
            if depth > max_depth or current in visited:
                continue
            
            visited.add(current)
            
            # Add packages that depend on this one
            for neighbor in self._graph.predecessors(current):
                new_depth = depth + 1
                result.append((neighbor, new_depth))
                
                if new_depth < max_depth:
                    queue.append((neighbor, new_depth))
        
        return result
    
    def get_affected_packages(
        self, 
        vulnerability: VulnerabilityRecord
    ) -> List[PackageRef]:
        """Find all packages affected by a specific vulnerability."""
        # Direct matches
        if vulnerability.ref == vulnerability.ref:
            direct = [vulnerability.ref]
        else:
            direct = []
        
        # Transitive matches - find any package in the dependency tree
        affected = set()
        
        def traverse(node, depth):
            for neighbor in self._graph.successors(node):
                if neighbor not in affected and depth < 10:
                    affected.add(neighbor)
                    traverse(neighbor, depth + 1)
        
        # Start from the vulnerable package
        if vulnerability.ref in self._packages:
            traverse(vulnerability.ref, 0)
        
        return list(affected)
    
    def get_maintainer_history(
        self, 
        package_ref: PackageRef,
        since_date: Optional[datetime] = None
    ) -> List[MaintainerRecord]:
        """Get maintainer history for a package."""
        key = (package_ref.name, package_ref.ecosystem.value)
        
        records = []
        for record in self._maintainers.get(key, []):
            if since_date is None or record.last_seen >= since_date:
                records.append(record)
        
        return sorted(records, key=lambda r: r.first_seen)
    
    def get_vulnerabilities_for_package(
        self, 
        ref: PackageRef
    ) -> List[VulnerabilityRecord]:
        """Get all vulnerabilities for a specific package."""
        return list(self._vulnerabilities.get(ref, []))
    
    def add_maintainer_record(
        self, 
        record: MaintainerRecord
    ) -> None:
        """Add or update a maintainer record."""
        key = (record.package_ref.name, record.package_ref.ecosystem.value)
        
        existing = [r for r in self._maintainers.get(key, []) 
                   if r.name == record.name]
        
        if not existing:
            # New maintainer - add to list
            self._maintainers[key].append(record)
        else:
            # Update existing records
            for ex_record in existing:
                ex_record.last_seen = max(ex_record.last_seen, record.last_seen)
                ex_record.commits_count += record.commits_count
    
    def add_vulnerability(
        self, 
        vuln: VulnerabilityRecord
    ) -> None:
        """Add a vulnerability record."""
        if vuln.ref not in self._vulnerabilities:
            self._vulnerabilities[vuln.ref] = []
        
        # Check for duplicate CVE
        existing = [v for v in self._vulnerabilities[vuln.ref] 
                   if v.cve_id == vuln.cve_id]
        
        if not existing:
            self._vulnerabilities[vuln.ref].append(vuln)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the graph state."""
        return {
            "name": self.name,
            "package_count": len(self._packages),
            "edge_count": len(self._edges),
            "maintainer_count": sum(1 for _ in self._maintainers.values()),
            "vulnerability_count": sum(len(v) for v in self._vulnerabilities.values()),
            "resolution_status": self._resolution_status.value,
        }


# =============================================================================
# PARSERS - Multi-ecosystem support
# =============================================================================

class BaseParser:
    """Base class for ecosystem-specific parsers."""
    
    def __init__(self, ecosystem: Ecosystem):
        self.ecosystem = ecosystem
    
    def parse(self, source: Union[str, Path], graph: DependencyGraph) -> bool:
        raise NotImplementedError


class PipParser(BaseParser):
    """Parse pip requirements files and lock files."""
    
    # Common patterns for various formats
    REQUIREMENT_PATTERNS = [
        r'^-r\s+(\S+)$',  # Include other requirement files
        r'^-e\s+(git\+)?(\S+)',  # Editable installs
        r'^# -c\s+\S+$',  # Constraints file
        r'^--extra-index-url\s+\S+',  # Extra indexes
    ]
    
    def __init__(self, ecosystem: Ecosystem = Ecosystem.PIP):
        super().__init__(ecosystem)
    
    def parse(self, source: Union[str, Path], graph: DependencyGraph) -> bool:
        """Parse a pip requirements file."""
        try:
            path = Path(source) if isinstance(source, str) else source
            
            # Handle include files recursively
            includes = []
            for pattern in self.REQUIREMENT_PATTERNS:
                matches = re.findall(pattern, open(path).read())
                includes.extend(matches)
            
            # Parse main file and included files
            all_files = [path] + includes
            
            for req_file in all_files:
                if not req_file.exists():
                    continue
                
                self._parse_requirements_file(req_file, graph)
                
        except Exception as e:
            print(f"Warning: Error parsing pip requirements: {e}")
            return False
        
        return True
    
    def _parse_requirements_file(
        self, 
        path: Path, 
        graph: DependencyGraph
    ) -> None:
        """Parse a single requirements file."""
        try:
            with open(path) as f:
                content = f.read()
            
            # Parse each line
            for line in content.splitlines():
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Handle -r includes (recursively)
                match = re.match(r'^-r\s+(\S+)$', line)
                if match:
                    self._parse_requirements_file(Path(match.group(1)), graph)
                    continue
                
                # Parse package specification
                pkg_match = re.match(
                    r'^(-e\s+)?(\S+)(?:\[(.+)\])?(?:@(.+))?$'
                )
                
                if not pkg_match:
                    continue
                
                editable, name, extras, version_spec = pkg_match.groups()
                
                # Determine ecosystem (pip)
                ref = PackageRef(
                    ecosystem=Ecosystem.PIP,
                    name=name.lower().replace('_', '-'),
                    version=version_spec.strip('[]') if version_spec else None
                )
                
                # Create package info
                info = PackageInfo(
                    ref=ref,
                    name=name,
                    source=path,
                    resolved_at=datetime.now()
                )
                
                graph.add_package(info)
                
        except Exception as e:
            print(f"Warning: Error parsing {path}: {e}")


class NpmParser(BaseParser):
    """Parse npm package.json and lock files."""
    
    def __init__(self, ecosystem: Ecosystem = Ecosystem.NPM):
        super().__init__(ecosystem)