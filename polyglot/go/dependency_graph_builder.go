package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Data Structures
// =============================================================================

// Component represents a software component/package in the SBOM.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PackageManager string `json:"package_manager,omitempty"`
	Source string `json:"source,omitempty"`
	Licenses []LicenseRef `json:"licenses,omitempty"`
}

// LicenseRef holds license information.
type LicenseRef struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	URL     string   `json:"url,omitempty"`
	Source  string   `json:"source,omitempty"`
	Text    string   `json:"text,omitempty"`
	Content []string `json:"content,omitempty"`
}

// DependencyEdge represents a relationship between two components.
type DependencyEdge struct {
	From       ComponentRef `json:"from"`
	To         ComponentRef `json:"to"`
	Type       DepType      `json:"type"`
	Version    string        `json:"version,omitempty"`
	Optional   bool          `json:"optional,omitempty"`
	Transitive bool          `json:"transitive,omitempty"`
}

// ComponentRef is a lightweight reference to a component.
type ComponentRef struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// DepType defines the nature of the dependency relationship.
type DepType int

const (
	DepDirect DepType = iota // Direct dependency, explicitly declared
	DepTransitive            // Transitive dependency, inferred from parent
	DepDev                   // Development-only dependency
	DepBuild                 // Build-time dependency
	DepRuntime               // Runtime dependency
)

// GraphStatus tracks the current state of graph building.
type GraphStatus struct {
	TotalComponents int
	TotalEdges      int
	CyclesFound     int
	BuildTime       time.Duration
	Error           error
}

// =============================================================================
// Interfaces
// =============================================================================

// SBOMParser defines the interface for parsing different SBOM formats.
type SBOMParser interface {
	Parse(ctx context.Context, data []byte) (*Graph, *GraphStatus, error)
	SupportsFormat() string
	Validate(data []byte) bool
}

// GraphQuerier provides methods to query the built graph.
type GraphQuerier interface {
	GetDependencies(ComponentRef) ([]ComponentRef, error)
	GetDependents(ComponentRef) ([]ComponentRef, error)
	GetRootComponents() ([]ComponentRef, error)
	HasCycle() bool
}

// =============================================================================
// Core Types
// =============================================================================

// Graph represents the complete dependency graph structure.
type Graph struct {
	mu sync.RWMutex
	
	components map[ComponentKey]*Component
	edges      map[EdgeKey][]*DependencyEdge
	index      *GraphIndex
	
	status   *GraphStatus
	parser   SBOMParser
}

// ComponentKey is a hashable key for component identification.
type ComponentKey struct {
	Name    string
	Version string
}

// EdgeKey is a hashable key for edge identification.
type EdgeKey struct {
	From  ComponentKey
	To    ComponentKey
	Type  DepType
}

// GraphIndex provides fast lookup capabilities.
type GraphIndex struct {
	byName     map[string][]ComponentKey
	byVersion  map[string][]ComponentKey
	byPackage  map[string][]ComponentKey
}

// =============================================================================
// Implementation: SBOM Parsers
// =============================================================================

// spdxParser implements SPDX format parsing.
type spdxParser struct{}

func newSPDXParser() *spdxParser {
	return &spdxParser{}
}

func (p *spdxParser) SupportsFormat() string {
	return "SPDX"
}

func (p *spdxParser) Validate(data []byte) bool {
	// Basic validation: check for SPDX header
	return strings.Contains(string(data), "SPDX") || 
		   strings.Contains(string(data), "@package")
}

func (p *spdxParser) Parse(ctx context.Context, data []byte) (*Graph, *GraphStatus, error) {
	g := &Graph{
		components: make(map[ComponentKey]*Component),
		edges:      make(map[EdgeKey][]*DependencyEdge),
		index: &GraphIndex{
			byName:     make(map[string][]ComponentKey),
			byVersion:  make(map[string][]ComponentKey),
			byPackage:  make(map[string][]ComponentKey),
		},
		status: &GraphStatus{
			TotalComponents: 0,
			TotalEdges:      0,
			CyclesFound:     0,
			BuildTime:       0,
		},
		parser: p,
	}

	start := time.Now()
	
	// Parse SPDX document
	doc, err := parseSPDXDocument(data)
	if err != nil {
		g.status.Error = fmt.Errorf("failed to parse SPDX document: %w", err)
		return g, g.status, err
	}

	// Build component index first for fast lookups
	p.buildComponentIndex(doc)

	// Extract components from the parsed document
	p.extractComponents(doc, g)

	// Build dependency edges
	p.buildEdges(doc, g)

	g.status.BuildTime = time.Since(start)
	return g, g.status, nil
}

// =============================================================================
// Implementation: SPDX Parser Functions
// =============================================================================

func parseSPDXDocument(data []byte) (*spdxDoc, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	doc := &spdxDoc{}
	
	if err := decoder.Decode(doc); err != nil {
		return nil, fmt.Errorf("JSON decode failed: %w", err)
	}

	return doc, nil
}

type spdxDoc struct {
	Package []packageInfo `json:"packages"`
	Files   []fileInfo    `json:"files,omitempty"`
	Relates []relateInfo  `json:"relationships,omitempty"`
}

type packageInfo struct {
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PackageMgr string     `json:"package_manager,omitempty"`
	Sources    []source   `json:"sources,omitempty"`
	Licenses   []license  `json:"licenses,omitempty"`
}

type source struct {
	Type   string `json:"type"`
	URI    string `json:"uri"`
}

type license struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	URL     string `json:"url,omitempty"`
	Text    string `json:"text,omitempty"`
}

type fileInfo struct {
	Name   string  `json:"name"`
	SHA256 string  `json:"sha256,omitempty"`
	Files  []fileRef `json:"files,omitempty"`
}

type fileRef struct {
	Type    string `json:"type"`
	URI     string `json:"uri"`
	Sha256  string `json:"sha256,omitempty"`
}

type relateInfo struct {
	Type   string `json:"type"`
	From   string `json:"fromRef"`
	To     string `json:"toRef"`
}

// =============================================================================
// Implementation: Index Building
// =============================================================================

func (p *spdxParser) buildComponentIndex(doc *spdxDoc) {
	for _, pkg := range doc.Package {
		key := ComponentKey{
			Name:    strings.ToLower(pkg.Name),
			Version: strings.TrimSpace(pkg.Version),
		}
		
		if key.Name == "" || key.Version == "" {
			continue
		}

		p.index.byName[key.Name] = append(p.index.byName[key.Name], key)
		p.index.byVersion[key.Version] = append(p.index.byVersion[key.Version], key)
		p.index.byPackage[pkg.PackageMgr] = append(p.index.byPackage[pkg.PackageMgr], key)
	}
}

// =============================================================================
// Implementation: Component Extraction
// =============================================================================

func (p *spdxParser) extractComponents(doc *spdxDoc, g *Graph) {
	for _, pkg := range doc.Package {
		key := ComponentKey{
			Name:    strings.ToLower(pkg.Name),
			Version: strings.TrimSpace(pkg.Version),
		}

		if key.Name == "" || key.Version == "" {
			continue
		}

		component := &Component{
			Name:         pkg.Name,
			Version:      pkg.Version,
			PackageManager: pkg.PackageMgr,
			Source:       buildSourceURL(pkg.Sources),
		}

		if len(pkg.Licenses) > 0 {
			for _, lic := range pkg.Licenses {
				component.Licenses = append(component.Licenses, LicenseRef{
					ID:      lic.ID,
					Name:    lic.Name,
					URL:     lic.URL,
					Text:    lic.Text,
				}...)
			}
		}

		g.components[key] = component
		g.status.TotalComponents++
	}

	// Also extract components from files section if present
	for _, file := range doc.Files {
		if file.Name != "" && !strings.Contains(file.Name, ".") {
			key := ComponentKey{
				Name:    strings.ToLower(file.Name),
				Version: "0.0.1", // Default version for file-based components
			}

			g.components[key] = &Component{
				Name:         file.Name,
				Version:      "0.0.1",
				PackageManager: "file",
				Source:       fmt.Sprintf("file:///%s", filepath.Clean(file.Name)),
			}
			g.status.TotalComponents++
		}
	}
}

func buildSourceURL(sources []source) string {
	if len(sources) == 0 {
		return ""
	}

	var primary SourceInfo
	for _, src := range sources {
		if src.Type == "git" || src.Type == "svn" || src.Type == "hg" || 
		   src.Type == "bzr" || src.Type == "pypi" || src.Type == "npm" {
			primary = src
			break
		}
	}

	return primary.URI
}

type SourceInfo struct {
	Type string `json:"type"`
	URI  string `json:"uri"`
}

// =============================================================================
// Implementation: Edge Building
// =============================================================================

func (p *spdxParser) buildEdges(doc *spdxDoc, g *Graph) {
	for _, rel := range doc.Relates {
		if rel.Type == "DEPENDS_ON" || rel.Type == "REQUIRES" || 
		   rel.Type == "RUNTIME_DEPENDENCY_OF" || rel.Type == "BUILD_DEPENDENCY_OF" {
			p.processRelationship(rel, g)
		} else if rel.Type == "DEV_DEPENDENCY_OF" {
			p.processRelationship(rel, g, DepDev)
		}
	}

	// Infer edges from file relationships (implicit dependencies)
	if len(doc.Files) > 0 {
		p.inferFileDependencies(doc, g)
	}
}

func (p *spdxParser) processRelationship(rel relateInfo, g *Graph, depType DepType) {
	fromKey := ComponentKey{Name: strings.ToLower(rel.From)}
	toKey := ComponentKey{Name: strings.ToLower(rel.To)}

	if fromKey.Name == "" || toKey.Name == "" {
		return
	}

	var edgeType DepType = DepDirect
	if depType != 0 {
		edgeType = depType
	}

	// Check if edge already exists
	existing := g.edges[EdgeKey{from: fromKey, to: toKey, type: edgeType}]
	if len(existing) > 0 {
		return // Avoid duplicate edges
	}

	// Create new edge
	edge := &DependencyEdge{
		From:       ComponentRef{Name: rel.From},
		To:         ComponentRef{Name: rel.To},
		Type:       edgeType,
		Transitive: false,
	}

	g.edges[EdgeKey{from: fromKey, to: toKey, type: edgeType}] = append(g.edges, edge)
	g.status.TotalEdges++
}

func (p *spdxParser) inferFileDependencies(doc *spdxDoc, g *Graph) {
	// Build a map of file contents to their locations
	fileContents := make(map[string][]string)
	
	for _, file := range doc.Files {
		if file.SHA256 != "" {
			key := strings.ToLower(file.SHA256)
			fileContents[key] = append(fileContents[key], file.Name)
		}
	}

	// Infer dependencies based on content similarity (simplified implementation)
	for _, file := range doc.Files {
		if file.Files != nil {
			for _, subFile := range file.Files {
				if subFile.Type == "file" && subFile.URI != "" {
					// Check if this file might be a dependency of the parent
					parentKey := ComponentKey{
						Name:    strings.ToLower(file.Name),
						Version: "0.0.1",
					}

					subKey := ComponentKey{
						Name:    strings.ToLower(subFile.URI),
						Version: "0.0.1",
					}

					if parentKey.Name != "" && subKey.Name != "" {
						g.edges[EdgeKey{from: parentKey, to: subKey, type: DepDirect}] = 
							append(g.edges[EdgeKey{from: parentKey, to: subKey, type: DepDirect}], &DependencyEdge{})
						g.status.TotalEdges++
					}
				}
			}
		}
	}
}

// =============================================================================
// Implementation: Graph Query Methods
// =============================================================================

func (g *Graph) GetDependencies(ref ComponentRef) ([]ComponentRef, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var deps []ComponentRef
	
	for _, edges := range g.edges {
		for _, edge := range edges {
			if strings.EqualFold(edge.From.Name, ref.Name) && 
			   (edge.To.Version == "" || strings.EqualFold(edge.To.Version, ref.Version)) {
				deps = append(deps, ComponentRef{
					Name:    edge.To.Name,
					Version: edge.To.Version,
				})
			}
		}
	}

	return deps, nil
}

func (g *Graph) GetDependents(ref ComponentRef) ([]ComponentRef, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var dependents []ComponentRef
	
	for _, edges := range g.edges {
		for _, edge := range edges {
			if strings.EqualFold(edge.To.Name, ref.Name) && 
			   (edge.From.Version == "" || strings.EqualFold(edge.From.Version, ref.Version)) {
				dependents = append(dependents, ComponentRef{
					Name:    edge.From.Name,
					Version: edge.From.Version,
				})
			}
		}
	}

	return dependents, nil
}

func (g *Graph) GetRootComponents() ([]ComponentRef, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var roots []ComponentRef
	
	for key := range g.components {
		foundAsDep := false
		
		for _, edges := range g.edges {
			for _, edge := range edges {
				if strings.EqualFold(edge.To.Name, key.Name) && 
				   (edge.To.Version == "" || strings.EqualFold(edge.To.Version, key.Version)) {
					foundAsDep = true
					break
				}
			}
			if foundAsDep {
				break
			}
		}

		if !foundAsDep {
			roots = append(roots, ComponentRef{
				Name:    key.Name,
				Version: key.Version,
			})
		}
	}

	return roots, nil
}

func (g *Graph) HasCycle() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Simple cycle detection using DFS
	visited := make(map[ComponentKey]bool)
	recStack := make(map[ComponentKey]bool)

	for key := range g.components {
		if !recStack[key] && !visited[key] {
			if err := g.dfsCycleCheck(key, visited, recStack); err != nil {
				g.status.CyclesFound++
				return true
			}
		}
	}

	return false
}

func (g *Graph) dfsCycleCheck(current ComponentKey, visited map[ComponentKey]bool, 
    recStack map[ComponentKey]bool) error {
	visited[current] = true
	recStack[current] = true

	for _, edges := range g.edges {
		for _, edge := range edges {