package sbom_parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Maintainer represents a person or entity responsible for a component
type Maintainer struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	GitHub   string `json:"github,omitempty"`
}

// SBOMMetadata contains metadata about the BOM itself
type SBOMMetadata struct {
	Authors       []Maintainer `json:"authors,omitempty"`
	CreationTime  string       `json:"creationTime,omitempty"`
	Name          string       `json:"name,omitempty"`
	SBOMSchema    string       `json:"sbomSchema,omitempty"`
	Version       string       `json:"version,omitempty"`
}

// Component represents a software component in an SBOM
type Component struct {
	Name        string      `json:"name,omitempty"`
	Version     string      `json:"version,omitempty"`
	Type        string      `json:"type,omitempty"`
	PURL        string      `json:"purl,omitempty"`
	Maintainers []Maintainer `json:"maintainers,omitempty"`
}

// CycloneDXBOM represents a CycloneDX 1.2 BOM structure
type CycloneDXBOM struct {
	BOMFormat     string       `json:"bomFormat,omitempty"`
	SpecVersion   string       `json:"specVersion,omitempty"`
	Metadata      *CycloneDXMetadata `json:"metadata,omitempty"`
	Components    []Component  `json:"components,omitempty"`
}

// CycloneDXMetadata contains metadata for CycloneDX BOMs
type CycloneDXMetadata struct {
	Authors       []Maintainer `json:"authors,omitempty"`
	DocumentTime  string       `json:"documentTime,omitempty"`
	Name          string       `json:"name,omitempty"`
	SBOMSchema    string       `json:"sbomSchema,omitempty"`
	Version       string       `json:"version,omitempty"`
}

// SPDXDocument represents an SPDX 2.3 document structure
type SPDXDocument struct {
	SpdxVersion   string              `json:"spdxVersion,omitempty"`
	Name          string              `json:"name,omitempty"`
	DocumentTime  string              `json:"documentTime,omitempty"`
	DataLicense   string              `json:"dataLicense,omitempty"`
	Packages      []SPDXPackage       `json:"packages,omitempty"`
	Relationships []SPDXRelationship  `json:"relationships,omitempty"`
}

// SPDXPackage represents a package in an SPDX document
type SPDXPackage struct {
	Name          string            `json:"name,omitempty"`
	Version       string            `json:"version,omitempty"`
	PackageURL    string            `json:"packageUrl,omitempty"`
	DownloadLocation string         `json:"downloadLocation,omitempty"`
	LicenseConcluded   string         `json:"licenseConcluded,omitempty"`
	Authors         []SPDXAuthor     `json:"authors,omitempty"`
	Maintainers      []SPDXMaintainer `json:"maintainers,omitempty"`
}

// SPDXAuthor represents an author in an SPDX document
type SPDXAuthor struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// SPDXMaintainer represents a maintainer in an SPDX document
type SPDXMaintainer struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// SPDXRelationship represents a relationship between entities
type SPDXRelationship struct {
	Type      string `json:"type,omitempty"`
	SpecifiedBy   string `json:"specifiedBy,omitempty"`
}

// ParseResult holds the parsed SBOM and any metadata
type ParseResult struct {
	Format    string
	Version   string
	Metadata  *SBOMMetadata
	Components []Component
	Error     error
}

// DetectFormat determines which SBOM format a file contains
func DetectFormat(content []byte) (string, error) {
	var bom CycloneDXBOM
	var spdx SPDXDocument
	
	if err := json.Unmarshal(content, &bom); err == nil && bom.BOMFormat != "" {
		return "cyclonedx", nil
	}
	
	if err := json.Unmarshal(content, &spdx); err == nil && spdx.SpdxVersion != "" {
		return "spdx", nil
	}
	
	return "", fmt.Errorf("unknown SBOM format")
}

// ParseCycloneDX parses a CycloneDX 1.2 BOM from JSON content
func ParseCycloneDX(content []byte) (*SBOM, error) {
	var bom CycloneDXBOM
	
	if err := json.Unmarshal(content, &bom); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CycloneDX: %w", err)
	}
	
	sbom := &SBOM{
		Format:   "cyclonedx",
		Version:  bom.SpecVersion,
		Metadata: convertCycloneDXMetadata(bom.Metadata),
		Components: normalizeCycloneDXComponents(&bom),
	}
	
	return sbom, nil
}

// ParseSPDX parses an SPDX 2.3 document from JSON content
func ParseSPDX(content []byte) (*SBOM, error) {
	var doc SPDXDocument
	
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SPDX: %w", err)
	}
	
	sbom := &SBOM{
		Format:   "spdx",
		Version:  doc.SpdxVersion,
		Metadata: convertSPDXMetadata(&doc),
		Components: normalizeSPDXPackages(&doc),
	}
	
	return sbom, nil
}

// ParseFile reads and parses an SBOM file from disk
func ParseFile(path string) (*SBOM, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	
	format, detectErr := DetectFormat(content)
	if detectErr != nil {
		return nil, fmt.Errorf("detecting format: %w", detectErr)
	}
	
	var sbom *SBOM
	switch format {
	case "cyclonedx":
		sbom, err = ParseCycloneDX(content)
	case "spdx":
		sbom, err = ParseSPDX(content)
	default:
		return nil, fmt.Errorf("unknown format detected: %s", format)
	}
	
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", format, err)
	}
	
	return sbom, nil
}

// convertCycloneDXMetadata converts CycloneDX metadata to internal SBOMMetadata
func convertCycloneDXMetadata(metadata *CycloneDXMetadata) *SBOMMetadata {
	if metadata == nil {
		return &SBOMMetadata{}
	}
	
	result := &SBOMMetadata{
		Name:        metadata.Name,
		Version:     metadata.Version,
		SBOMSchema:  metadata.SBOMSchema,
		CreationTime: metadata.DocumentTime,
	}
	
	if len(metadata.Authors) > 0 {
		result.Authors = make([]Maintainer, len(metadata.Authors))
		for i, author := range metadata.Authors {
			result.Authors[i] = Maintainer{
				Name:  author.Name,
				Email: author.Email,
			}
		}
	}
	
	return result
}

// convertSPDXMetadata converts SPDX document metadata to internal SBOMMetadata
func convertSPDXMetadata(doc *SPDXDocument) *SBOMMetadata {
	result := &SBOMMetadata{
		Name:        doc.Name,
		Version:     doc.SpdxVersion,
		CreationTime: doc.DocumentTime,
	}
	
	if len(doc.Authors) > 0 {
		result.Authors = make([]Maintainer, len(doc.Authors))
		for i, author := range doc.Authors {
			result.Authors[i] = Maintainer{
				Name:  author.Name,
				Email: author.Email,
			}
		}
	}
	
	return result
}

// normalizeCycloneDXComponents normalizes CycloneDX components to internal format
func normalizeCycloneDXComponents(bom *CycloneDXBOM) []Component {
	if len(bom.Components) == 0 {
		return nil
	}
	
	result := make([]Component, len(bom.Components))
	for i, comp := range bom.Components {
		maintainers := make([]Maintainer, 0, len(comp.Maintainers))
		for _, m := range comp.Maintainers {
			if m.Name != "" || m.Email != "" {
				maintainers = append(maintainers, Maintainer{
					Name:  m.Name,
					Email: m.Email,
				})
			}
		}
		
		result[i] = Component{
			Name:        comp.Name,
			Version:     comp.Version,
			Type:        comp.Type,
			PURL:        comp.PURL,
			Maintainers: maintainers,
		}
	}
	
	return result
}

// normalizeSPDXPackages normalizes SPDX packages to internal format
func normalizeSPDXPackages(doc *SPDXDocument) []Component {
	if len(doc.Packages) == 0 {
		return nil
	}
	
	result := make([]Component, len(doc.Packages))
	for i, pkg := range doc.Packages {
		maintainers := make([]Maintainer, 0, len(pkg.Maintainers))
		for _, m := range pkg.Maintainers {
			if m.Name != "" || m.Email != "" {
				maintainers = append(maintainers, Maintainer{
					Name:  m.Name,
					Email: m.Email,
				})
			}
		}
		
		result[i] = Component{
			Name:        pkg.Name,
			Version:     pkg.Version,
			Type:        "spdx",
			PURL:        pkg.PackageURL,
			Maintainers: maintainers,
		}
	}
	
	return result
}

// GetTopLevelComponents returns only top-level components (not dependencies)
func GetTopLevelComponents(sbom *SBOM) []Component {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil
	}
	
	result := make([]Component, 0, len(sbom.Components))
	for _, comp := range sbom.Components {
		if !comp.IsDependency() {
			result = append(result, comp)
		}
	}
	
	return result
}

// IsDependency checks if a component is likely a dependency (has BOMRef or parent reference)
func (c *Component) IsDependency() bool {
	return strings.Contains(c.Name, "BOMRef") || 
		   c.Type == "npm" && !strings.HasPrefix(c.Version, "0.") ||
		   len(c.Maintainers) > 3 // Heuristic: dependencies often have fewer maintainers
}

// GetUniqueMaintainers returns a deduplicated list of all maintainers across components
func GetUniqueMaintainers(sbom *SBOM) []Maintainer {
	if sbom == nil {
		return nil
	}
	
	maintainerMap := make(map[string]Maintainer)
	for _, comp := range sbom.Components {
		for _, m := range comp.Maintainers {
			key := fmt.Sprintf("%s|%s", strings.ToLower(m.Name), strings.ToLower(m.Email))
			if existing, ok := maintainerMap[key]; !ok {
				maintainerMap[key] = m
			} else if existing.Name != "" && existing.Email != "" {
				// Merge information
				if existing.Name == "" || existing.Name == "Unknown" {
					existing.Name = m.Name
				}
				if existing.Email == "" {
					existing.Email = m.Email
				}
			} else if !existing.HasGitHub() && m.GitHub != "" {
				existing.GitHub = m.GitHub
			}
		}
	}
	
	result := make([]Maintainer, 0, len(maintainerMap))
	for _, m := range maintainerMap {
		if !m.IsUnknown() {
			result = append(result, m)
		}
	}
	
	return result
}

// HasGitHub checks if a maintainer has a GitHub profile set
func (m *Maintainer) HasGitHub() bool {
	return m.GitHub != ""
}

// IsUnknown returns true for maintainers with minimal information
func (m *Maintainer) IsUnknown() bool {
	return m.Name == "" && m.Email == "" && !m.HasGitHub()
}

// GetComponentByPURL finds a component by its Package URL
func GetComponentByPURL(sbom *SBOM, purl string) (*Component, bool) {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil, false
	}
	
	for _, comp := range sbom.Components {
		if strings.EqualFold(comp.PURL, purl) {
			return &comp, true
		}
	}
	
	return nil, false
}

// GetComponentByNameAndVersion finds a component by name and version
func GetComponentByNameAndVersion(sbom *SBOM, name, version string) (*Component, bool) {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil, false
	}
	
	for _, comp := range sbom.Components {
		if strings.EqualFold(comp.Name, name) && comp.Version == version {
			return &comp, true
		}
	}
	
	return nil, false
}

// GetComponentByPkgName finds a component by package name (case-insensitive)
func GetComponentByPkgName(sbom *SBOM, pkgName string) (*Component, bool) {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil, false
	}
	
	for _, comp := range sbom.Components {
		if strings.EqualFold(comp.Name, pkgName) {
			return &comp, true
		}
	}
	
	return nil, false
}

// GetComponentByTypeAndVersion finds a component by type and version
func GetComponentByTypeAndVersion(sbom *SBOM, compType, version string) ([]*Component, bool) {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil, false
	}
	
	result := make([]*Component, 0)
	for _, comp := range sbom.Components {
		if strings.EqualFold(comp.Type, compType) && comp.Version == version {
			result = append(result, &comp)
		}
	}
	
	return result, len(result) > 0
}

// GetComponentsByMaintainer finds all components maintained by a specific maintainer
func GetComponentsByMaintainer(sbom *SBOM, maintainerName string) ([]*Component, bool) {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil, false
	}
	
	result := make([]*Component, 0)
	for _, comp := range sbom.Components {
		for _, m := range comp.Maintainers {
			if strings.EqualFold(m.Name, maintainerName) {
				result = append(result, &comp)
				break
			}
		}
	}
	
	return result, len(result) > 0
}

// GetComponentsByType finds all components of a specific type
func GetComponentsByType(sbom *SBOM, compType string) ([]*Component, bool) {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil, false
	}
	
	result := make([]*Component, 0)
	for _, comp := range sbom.Components {
		if strings.EqualFold(comp.Type, compType) {
			result = append(result, &comp)
		}
	}
	
	return result, len(result) > 0
}

// GetComponentsByPURLPrefix finds components matching a PURL prefix (useful for org-wide queries)
func GetComponentsByPURLPrefix(sbom *SBOM, purlPrefix string) ([]*Component, bool) {
	if sbom == nil || len(sbom.Components) == 0 {
		return nil, false
	}
	
	result := make([]*Component, 0)
	for _, comp := range sbom.Components {
		if strings.HasPrefix(strings.ToLower(comp.PURL), strings.ToLower(p