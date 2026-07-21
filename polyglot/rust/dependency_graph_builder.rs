use std::collections::{HashMap, HashSet, BTreeSet};
use serde::{Serialize, Deserialize};
use std::fmt;

/// Represents a single package/dependency node in the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    pub name: String,
    pub version: Option<String>,
    pub source: Option<String>,
    pub maintainer: Option<String>,
    pub checksum: Option<String>,
}

impl Default for DependencyNode {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: None,
            source: None,
            maintainer: None,
            checksum: None,
        }
    }
}

/// Edge represents a dependency relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub constraint: Option<String>, // e.g., ">=1.0,<2.0"
    pub direct: bool,
}

/// The main dependency graph structure.
#[derive(Debug, Default)]
pub struct DependencyGraph {
    nodes: HashMap<String, DependencyNode>,
    edges: Vec<DependencyEdge>,
    /// Tracks which manifest files contributed each node
    provenance: HashMap<String, HashSet<String>>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a dependency node with optional metadata.
    pub fn add_node(&mut self, name: &str, version: Option<&str>, source: Option<&str>) {
        let existing = self.nodes.get(name).map(|n| n.version.as_deref());
        
        // Keep the highest known version if available
        let new_version = match (existing, version) {
            (Some(v), Some(n)) => Some(if v > n { v.to_string() } else { n.to_string() }),
            _ => version.map(|v| v.to_string()),
        };

        self.nodes.insert(
            name.to_string(),
            DependencyNode {
                name: name.to_string(),
                version: new_version,
                source: source.map(|s| s.to_string()),
                ..Default::default()
            },
        );

        // Track provenance
        if let Some(source) = source {
            self.provenance.entry(name.to_string()).or_default().insert(source.to_string());
        } else {
            self.provenance.entry(name.to_string()).or_default();
        }
    }

    /// Add a dependency edge. Returns true if this was a new direct relationship.
    pub fn add_edge(&mut self, from: &str, to: &str, constraint: Option<&str>, is_direct: bool) -> bool {
        let existing = self.edges.iter().any(|e| e.from == from && e.to == to);
        
        if !existing {
            self.edges.push(DependencyEdge {
                from: from.to_string(),
                to: to.to_string(),
                constraint: constraint.map(|c| c.to_string()),
                direct: is_direct,
            });
            return true;
        }

        // Update existing edge if it's a new direct dependency
        if !is_direct {
            self.edges.retain(|e| e.from != from || e.to != to);
            self.add_edge(from, to, constraint, true);
        }

        false
    }

    /// Get all nodes in the graph.
    pub fn nodes(&self) -> impl Iterator<Item = &DependencyNode> {
        self.nodes.values()
    }

    /// Get all edges.
    pub fn edges(&self) -> &[DependencyEdge] {
        &self.edges
    }

    /// Find all direct dependencies of a package (what it depends on).
    pub fn direct_dependencies(&self, name: &str) -> BTreeSet<String> {
        self.edges.iter()
            .filter(|e| e.from == name && e.direct)
            .map(|e| e.to.clone())
            .collect()
    }

    /// Find all transitive dependencies (recursive).
    pub fn transitive_dependencies(&self, name: &str) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        let mut stack = vec![name.to_string()];
        
        while let Some(current) = stack.pop() {
            if !result.contains(&current) {
                result.insert(current.clone());
                
                for dep in self.direct_dependencies(&current) {
                    if !result.contains(&dep) && !stack.contains(&dep) {
                        stack.push(dep);
                    }
                }
            }
        }

        result
    }

    /// Find all packages that depend on a given package (ancestors).
    pub fn ancestors(&self, name: &str) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        let mut stack = vec![name.to_string()];
        
        while let Some(current) = stack.pop() {
            if !result.contains(&current) {
                result.insert(current.clone());
                
                for edge in self.edges.iter().filter(|e| e.to == current && e.direct) {
                    if !result.contains(&edge.from) && !stack.contains(&edge.from) {
                        stack.push(edge.from.clone());
                    }
                }
            }
        }

        result
    }

    /// Find all packages that depend on a given package (descendants).
    pub fn descendants(&self, name: &str) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        let mut stack = vec![name.to_string()];
        
        while let Some(current) = stack.pop() {
            if !result.contains(&current) {
                result.insert(current.clone());
                
                for edge in self.edges.iter().filter(|e| e.from == current && e.direct) {
                    if !result.contains(&edge.to) && !stack.contains(&edge.to) {
                        stack.push(edge.to.clone());
                    }
                }
            }
        }

        result
    }

    /// Check for cycles in the graph. Returns list of cycle paths found.
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        let mut cycles = Vec::new();
        
        for start_node in self.nodes.keys() {
            if let Some(path) = self.find_cycle_from(start_node, &mut HashSet::new()) {
                // Normalize cycle to avoid duplicates (start from smallest element)
                let min_idx = path.iter().enumerate()
                    .min_by_key(|(_, n)| n.as_str())
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                
                let normalized: Vec<String> = path[min_idx..].iter().chain(path[..min_idx].iter()).cloned().collect();
                
                if !cycles.contains(&normalized) {
                    cycles.push(normalized);
                }
            }
        }

        cycles
    }

    fn find_cycle_from(
        &self, 
        start: &str, 
        visited: &mut HashSet<String>
    ) -> Option<Vec<String>> {
        let mut stack = vec![start.to_string()];
        
        while let Some(current) = stack.pop() {
            if current == *start && !visited.contains(&current) {
                return Some(stack.clone());
            }

            for edge in self.edges.iter().filter(|e| e.from == current && e.direct) {
                let next = &edge.to;
                
                if next == *start {
                    return Some(stack.clone() + vec![next.to_string()]);
                }

                if !visited.contains(next) {
                    visited.insert(next.clone());
                    stack.push(next.clone());
                }
            }
        }

        None
    }

    /// Get provenance info for a node.
    pub fn get_provenance(&self, name: &str) -> HashSet<String> {
        self.provenance.get(name).cloned().unwrap_or_default()
    }

    /// Check if two graphs are equivalent (same nodes and edges).
    pub fn is_equivalent_to(&self, other: &Self) -> bool {
        let mut sorted_self = self.nodes.iter().collect::<Vec<_>>();
        let mut sorted_other = other.nodes.iter().collect::<Vec<_>>();
        
        sorted_self.sort_by_key(|(k, _)| k);
        sorted_other.sort_by_key(|(k, _)| k);

        if sorted_self.len() != sorted_other.len() {
            return false;
        }

        for (a, b) in sorted_self.iter().zip(sorted_other.iter()) {
            if a.0 != b.0 || a.1.version != b.1.version {
                return false;
            }
        }

        let mut self_edges = self.edges.clone();
        let mut other_edges = other.edges.clone();
        
        self_edges.sort();
        other_edges.sort();

        self_edges == other_edges
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Get total number of nodes and edges.
    pub fn stats(&self) -> (usize, usize) {
        let node_count = self.nodes.len();
        let edge_count = self.edges.iter()
            .filter(|e| e.direct)
            .count();
        
        (node_count, edge_count)
    }

    /// Find the root dependencies (packages with no incoming edges).
    pub fn roots(&self) -> BTreeSet<String> {
        let mut has_incoming = HashSet::new();
        
        for edge in &self.edges {
            if edge.direct {
                has_incoming.insert(edge.to.clone());
            }
        }

        self.nodes.keys()
            .filter(|n| !has_incoming.contains(n))
            .cloned()
            .collect()
    }

    /// Find leaf dependencies (packages with no outgoing edges).
    pub fn leaves(&self) -> BTreeSet<String> {
        let mut has_outgoing = HashSet::new();
        
        for edge in &self.edges {
            if edge.direct {
                has_outgoing.insert(edge.from.clone());
            }
        }

        self.nodes.keys()
            .filter(|n| !has_outgoing.contains(n))
            .cloned()
            .collect()
    }
}

impl fmt::Display for DependencyGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Dependency Graph:")?;
        writeln!(f, "  Nodes: {}", self.nodes.len())?;
        writeln!(f, "  Direct Edges: {}", 
            self.edges.iter().filter(|e| e.direct).count())?;

        if let Some(roots) = self.roots().first() {
            writeln!(f)?;
            writeln!(f, "  Roots (no incoming): {:?}", roots)?;
        }

        Ok(())
    }
}

/// Builder pattern for constructing graphs incrementally.
pub struct GraphBuilder {
    graph: DependencyGraph,
}

impl GraphBuilder {
    pub fn new() -> Self {
        Self { 
            graph: DependencyGraph::default(), 
        }
    }

    pub fn from_graph(graph: DependencyGraph) -> Self {
        Self { graph }
    }

    pub fn add_node(&mut self, name: &str, version: Option<&str>, source: Option<&str>) {
        self.graph.add_node(name, version, source);
    }

    pub fn add_edge(&mut self, from: &str, to: &str, constraint: Option<&str>, direct: bool) -> bool {
        self.graph.add_edge(from, to, constraint, direct)
    }

    pub fn build(self) -> DependencyGraph {
        self.graph
    }

    /// Load a Cargo.toml file and parse dependencies.
    pub fn load_cargo_toml(&mut self, path: &str) -> Result<(), std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        
        // Simple parser for Cargo.toml format
        let mut current_section = "package";
        let mut in_dependencies = false;
        
        for line in content.lines() {
            let trimmed = line.trim();
            
            if trimmed.starts_with("[") && trimmed.ends_with("]") {
                current_section = &trimmed[1..trimmed.len()-1];
                in_dependencies = current_section == "dependencies";
                continue;
            }

            if in_dependencies {
                // Parse: dep_name = "version" or dep_name = { version = "...", features = [...] }
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                
                if parts.len() == 2 {
                    let name = parts[0].trim().strip_prefix('\"').unwrap_or(parts[0]);
                    let value = parts[1].trim();

                    // Handle inline table: { version = "1.0", features = [] }
                    if value.starts_with('{') && value.ends_with('}') {
                        let inner = &value[1..value.len()-1];
                        let mut ver = None;
                        
                        for kv in inner.split(',') {
                            let k: String = kv.trim().split('=').next().unwrap_or("").trim().to_string();
                            let v: String = kv.trim().split('=').nth(1).unwrap_or("").trim().to_string();
                            
                            if k == "version" {
                                ver = Some(v);
                            } else if k == "features" && !v.is_empty() {
                                // Features are metadata, not critical for graph
                            }
                        }

                        self.add_node(name, ver.as_deref(), None);
                    } else {
                        let ver = value.strip_prefix('"').unwrap_or(&value[1..value.len()-1]);
                        self.add_node(name, Some(ver), None);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for GraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for vulnerability checking.
#[derive(Debug, Clone)]
pub struct VulnerabilityConfig {
    pub check_cve: bool,
    pub cve_sources: Vec<String>,
    pub fail_on_critical: bool,
}

impl Default for VulnerabilityConfig {
    fn default() -> Self {
        Self {
            check_cve: true,
            cve_sources: vec!["nvd.nist.gov".to_string()],
            fail_on_critical: false,
        }
    }
}

/// Result of a vulnerability scan.
#[derive(Debug)]
pub struct VulnerabilityReport {
    pub graph: DependencyGraph,
    pub config: VulnerabilityConfig,
    pub findings: Vec<VulnerabilityFinding>,
    pub summary: SummaryStats,
}

impl VulnerabilityReport {
    /// Create a new report from a graph.
    pub fn new(graph: DependencyGraph) -> Self {
        Self {
            graph,
            config: VulnerabilityConfig::default(),
            findings: Vec::new(),
            summary: SummaryStats::default(),
        }
    }

    /// Add a vulnerability finding.
    pub fn add_finding(&mut self, finding: VulnerabilityFinding) {
        self.findings.push(finding);
        
        // Update summary stats
        match &finding.severity {
            Severity::Critical => self.summary.critical += 1,
            Severity::High => self.summary.high += 1,
            Severity::Medium => self.summary.medium += 1,
            Severity::Low => self.summary.low += 1,
            _ => {}
        }
    }

    /// Check if any critical vulnerabilities exist.
    pub fn has_critical(&self) -> bool {
        self.findings.iter().any(|f| matches!(f.severity, Severity::Critical))
    }

    /// Get all affected packages for a CVE ID.
    pub fn get_affected_by_cve(&self, cve_id: &str) -> Vec<&DependencyNode> {
        self.findings.iter()
            .filter(|f| f.cve.as_deref() == Some(cve_id))
            .flat_map(|f| {
                // Return the primary affected package (usually the first one)
                if let Some(primary) = &f.primary_package {
                    vec![primary]
                } else {
                    Vec::new()
                }
            })
            .collect()
    }

    /// Generate a human-readable report.
    pub fn to_string(&self) -> String {
        let mut output = String::from("=== Vulnerability Report ===\n\n");
        
        output.push_str(&format!("Summary:\n"));
        output.push_str(&format!("  Total findings: {}\n", self.findings.len()));
        output.push_str(&format!("  Critical: {}, High: {}, Medium: {},