use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use regex::Regex;

// =============================================================================
// SPDX 2.3 Data Models - Idiomatic Rust with full serialization support
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomDocument {
    pub spdx_version: String,
    pub name: String,
    pub document_namespace: String,
    pub data_license: String,
    pub creators: Vec<Creator>,
    pub created: String,
    #[serde(default)]
    pub packages: Vec<Package>,
    #[serde(default)]
    pub files: Vec<FileEntry>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Creator {
    Tool(String),
    Person(String),
}

impl Creator {
    pub fn tool_name(&self) -> &str {
        match self {
            Creator::Tool(name) => name,
            Creator::Person(_) => "person",
        }
    }
    
    pub fn is_tool(&self) -> bool {
        matches!(self, Creator::Tool(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version_info: String,
    #[serde(default)]
    pub supplier: Option<String>,
    #[serde(default)]
    pub download_location: Option<String>,
    #[serde(default)]
    pub files_analyzed: bool,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license_concluded: Option<String>,
    #[serde(default)]
    pub license_inferred_from_files: Option<String>,
    #[serde(default)]
    pub copyright_text: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub external_refs: Vec<ExternalRef>,
    #[serde(default)]
    pub relationships: Vec<Relationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub checksums: Vec<Checksum>,
    #[serde(default)]
    pub license_concluded: Option<String>,
    #[serde(default)]
    pub license_inferred_from_files: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checksum {
    pub algorithm: String,
    pub checksum_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExternalRef {
    Reference(Reference),
    Collection(CollectionRef),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub reference_category: String,
    pub reference_type: String,
    pub locator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRef {
    pub collection: String,
    pub collection_version: String,
    pub locator: String,
}

// =============================================================================
// SPDX Parser - Production-ready with error handling
// =============================================================================

pub struct SbomParser {
    cache: HashMap<String, SbomDocument>,
}

impl Default for SbomParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SbomParser {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Parse SPDX JSON from a string
    pub fn parse_json(&mut self, json_str: &str) -> Result<SbomDocument, ParserError> {
        let doc = serde_json::from_str(json_str)?;
        
        // Validate minimum required fields
        if doc.spdx_version.is_empty() {
            return Err(ParserError::InvalidFormat("Missing SPDX version".to_string()));
        }

        self.cache.insert(doc.document_namespace.clone(), doc);
        Ok(doc)
    }

    /// Parse SPDX XML from a string
    pub fn parse_xml(&mut self, xml_str: &str) -> Result<SbomDocument, ParserError> {
        let json = quick_xml::de::from_str::<SbomDocument>(xml_str)?;
        
        if json.spdx_version.is_empty() {
            return Err(ParserError::InvalidFormat("Missing SPDX version".to_string()));
        }

        self.cache.insert(json.document_namespace.clone(), json);
        Ok(json)
    }

    /// Get cached document by namespace
    pub fn get_cached(&self, namespace: &str) -> Option<&SbomDocument> {
        self.cache.get(namespace)
    }

    /// Clear cache - useful for fresh parsing sessions
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Extract all unique package names with versions
    pub fn extract_packages(&self, doc: &SbomDocument) -> Vec<PackageInfo> {
        let mut packages = Vec::new();
        
        // From packages array
        for pkg in &doc.packages {
            if !pkg.name.is_empty() && !pkg.version_info.is_empty() {
                packages.push(PackageInfo::from_spdx(pkg));
            }
        }

        // Also check files_analyzed flag - these are embedded packages
        let mut seen = HashSet::new();
        for file in &doc.files {
            if file.name.contains('/') && !file.checksums.is_empty() {
                let parts: Vec<&str> = file.name.split('/').collect();
                if let Some(base_name) = parts.last() {
                    // Extract version from filename pattern like "libfoo-1.2.3.so"
                    if let Some(version_match) = Regex::new(r"([a-zA-Z0-9._-]+)-(\d+\.\d+(\.\d+)?)").and_then(|re| re.captures(base_name)) {
                        let name = version_match.get(1).unwrap().as_str();
                        let version = format!("{}.{}", version_match.get(2).unwrap().as_str(), 
                            version_match.get(3).map(|m| m.as_str()).unwrap_or("0"));
                        
                        if seen.insert(format!("{name}@{version}")) {
                            packages.push(PackageInfo::from_file(&file.name, name.to_string(), &version));
                        }
                    }
                }
            }
        }

        // Sort for consistent output
        packages.sort_by(|a, b| a.full_name().cmp(b.full_name()));
        packages.dedup();
        
        packages
    }

    /// Extract maintainer information from creators and relationships
    pub fn extract_maintainers(&self, doc: &SbomDocument) -> Vec<MaintainerInfo> {
        let mut maintainers = Vec::new();

        // Check creator tools for maintainer hints
        for creator in &doc.creators {
            if let Creator::Tool(tool_name) = creator {
                // Tools often have embedded maintainer info
                if tool_name.to_lowercase().contains("maintainer") || 
                   tool_name.to_lowercase().contains("author") {
                    maintainers.push(MaintainerInfo {
                        name: format!("Tool: {}", tool_name),
                        email: None,
                        packages: Vec::new(),
                        first_seen: doc.created.clone(),
                    });
                }
            }
        }

        // Check package relationships for "DESCRIBES" or "DEPENDS_ON" with maintainer data
        for rel in &doc.relationships {
            if let RelationshipType::Describes = rel.related_type.as_ref() {
                if let PackageRef::Package(pkg_name) = &rel.related_package {
                    // Look up package details
                    if let Some(pkg) = doc.packages.iter().find(|p| p.name == *pkg_name) {
                        maintainers.push(MaintainerInfo {
                            name: format!("Maintainer for {}", pkg_name),
                            email: None,
                            packages: vec![pkg.name.clone()],
                            first_seen: doc.created.clone(),
                        });
                    }
                }
            }
        }

        // Check external references for maintainer URLs
        for pkg in &doc.packages {
            if let Some(ref homepage) = pkg.homepage {
                if homepage.contains("github.com") || homepage.contains("gitlab.com") {
                    maintainers.push(MaintainerInfo {
                        name: format!("Repository: {}", pkg.name),
                        email: None,
                        packages: vec![pkg.name.clone()],
                        first_seen: doc.created.clone(),
                    });
                }
            }
        }

        // Deduplicate by name + email combination
        let mut seen = HashSet::new();
        maintainers.sort_by(|a, b| (a.name.as_str(), a.email.as_ref().map(|e| e.as_str())).cmp(&(b.name.as_str(), b.email.as_ref().map(|e| e.as_str()))));
        
        for m in &mut maintainers {
            let key = format!("{}:{}", m.name, 
                m.email.as_ref().map(|e| e.as_str()).unwrap_or(""));
            
            if seen.insert(key) {
                // Keep first occurrence
            } else {
                // Remove duplicate - but keep the one with more package info
                let idx = maintainers.iter().position(|x| x.name == m.name).unwrap();
                if idx < 0 || !m.packages.is_empty() && maintainers[idx].packages.is_empty() {
                    maintainers.remove(idx);
                }
            }
        }

        maintainers
    }

    /// Extract license information with confidence scoring
    pub fn extract_licenses(&self, doc: &SbomDocument) -> Vec<LicenseInfo> {
        let mut licenses = Vec::new();

        for pkg in &doc.packages {
            // Primary license from package
            if let Some(ref concluded) = pkg.license_concluded {
                licenses.push(LicenseInfo {
                    name: format!("{} (concluded)", pkg.name),
                    identifier: concluded.clone(),
                    confidence: LicenseConfidence::High,
                    source: "SPDX Package".to_string(),
                    packages: vec![pkg.name.clone()],
                });
            }

            // Inferred license from files
            if let Some(ref inferred) = pkg.license_inferred_from_files {
                licenses.push(LicenseInfo {
                    name: format!("{} (inferred)", pkg.name),
                    identifier: inferred.clone(),
                    confidence: LicenseConfidence::Medium,
                    source: "SPDX File Analysis".to_string(),
                    packages: vec![pkg.name.clone()],
                });
            }

            // Check file-level licenses
            for file in &doc.files {
                if let Some(ref concluded) = file.license_concluded {
                    let key = format!("{}:{}:concluded", pkg.name, file.name);
                    
                    if !licenses.iter().any(|l| l.identifier == *concluded && 
                         l.source.contains("File Analysis")) {
                        licenses.push(LicenseInfo {
                            name: format!("{} (file)", pkg.name),
                            identifier: concluded.clone(),
                            confidence: LicenseConfidence::High,
                            source: "SPDX File".to_string(),
                            packages: vec![pkg.name.clone()],
                        });
                    }
                }
            }
        }

        // Deduplicate by name + identifier + confidence
        let mut seen = HashSet::new();
        licenses.sort_by(|a, b| {
            (a.identifier.as_str(), a.confidence).cmp(&(b.identifier.as_str(), b.confidence))
        });

        for l in &mut licenses {
            let key = format!("{}:{}:{}", 
                l.name, 
                l.identifier, 
                l.confidence);
            
            if seen.insert(key) {
                // Keep first occurrence
            } else {
                let idx = licenses.iter().position(|x| x.name == l.name).unwrap();
                if idx < 0 || !l.packages.is_empty() && licenses[idx].packages.is_empty() {
                    licenses.remove(idx);
                }
            }
        }

        licenses
    }

    /// Extract checksums for integrity verification
    pub fn extract_checksums(&self, doc: &SbomDocument) -> Vec<ChecksumInfo> {
        let mut checksums = Vec::new();

        // Package-level checksums (if present in extended format)
        for pkg in &doc.packages {
            if !pkg.name.is_empty() && !pkg.version_info.is_empty() {
                checksums.push(ChecksumInfo {
                    target: format!("{}@{}", pkg.name, pkg.version_info),
                    algorithm: "SPDX Package",
                    value: format!("{}/{}", pkg.name, pkg.version_info),
                    confidence: ChecksumConfidence::High,
                });
            }
        }

        // File-level checksums
        for file in &doc.files {
            for cs in &file.checksums {
                let key = format!("{}:{}:{}", 
                    file.name, 
                    cs.algorithm, 
                    cs.checksum_value);
                
                if !checksums.iter().any(|c| c.value == cs.checksum_value && 
                     c.target.contains(&file.name)) {
                    checksums.push(ChecksumInfo {
                        target: format!("File: {}", file.name),
                        algorithm: cs.algorithm.clone(),
                        value: cs.checksum_value.clone(),
                        confidence: ChecksumConfidence::High,
                    });
                }
            }
        }

        // Deduplicate
        let mut seen = HashSet::new();
        checksums.sort_by(|a, b| (a.target.as_str(), a.value.as_str()).cmp(&(b.target.as_str(), b.value.as_str())));

        for c in &mut checksums {
            if seen.insert(format!("{}:{}", c.target, c.value)) {
                // Keep first occurrence
            } else {
                let idx = checksums.iter().position(|x| x.target == c.target).unwrap();
                if idx < 0 || !c.value.contains('/') && checksums[idx].value.contains('/') {
                    checksums.remove(idx);
                }
            }
        }

        checksums
    }

    /// Get summary statistics about the document
    pub fn get_stats(&self, doc: &SbomDocument) -> SbomStats {
        let pkg_count = doc.packages.len();
        let file_count = doc.files.len();
        let rel_count = doc.relationships.len();
        
        // Count unique licenses
        let mut license_set = HashSet::new();
        for pkg in &doc.packages {
            if let Some(ref lic) = pkg.license_concluded {
                license_set.insert(lic.clone());
            }
            if let Some(ref lic) = pkg.license_inferred_from_files {
                license_set.insert(lic.clone());
            }
        }

        SbomStats {
            spdx_version: doc.spdx_version.clone(),
            document_name: doc.name.clone(),
            namespace: doc.document_namespace.clone(),
            created: doc.created.clone(),
            creator_tools: doc.creators.iter()
                .filter(|c| c.is_tool())
                .map(|c| match c {
                    Creator::Tool(t) => t.clone(),
                    _ => "person".to_string(),
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .collect(),
            package_count: pkg_count,
            file_count: file_count,
            relationship_count: rel_count,
            unique_licenses: license_set.len(),
        }
    }
}

// =============================================================================
// Supporting Types and Enums
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParserError {
    InvalidFormat(String),
    MissingField(String),
    Io(std::io::Error),
    Serde(serde_json::Error),
    Xml(quick_xml::DeError),
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            ParserError::MissingField(field) => write!(f, "Missing required field: {}", field),
            ParserError::Io(e) => write!(f, "IO error: {}", e),
            ParserError::Serde(e) => write!(f, "JSON parse error: {}", e),
            ParserError::Xml(e) => write!(f, "XML parse error: {}", e),
        }
    }
}

impl std::error::Error for ParserError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub supplier: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub license_concluded: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

impl PackageInfo {
    pub fn full_name(&self) -> String {
        format!("{}@{}", self.name,