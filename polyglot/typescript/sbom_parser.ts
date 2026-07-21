import { Component } from './component';
import { SBOMFormat, ParsedSBOM, ParseError, ValidationError, NormalizedLicense, VersionRange, LicenseResolver } from './types';

/**
 * SPDX 2.3/2.4 Parser Implementation
 */
export class SPDXParser {
    private static readonly SPDX_VERSION_REGEX = /SPDX-\d\.\d+/;
    
    public static parse(content: string): ParsedSBOM | ParseError {
        const trimmed = content.trim();
        
        // Quick format detection
        if (!trimmed.startsWith('SPDX')) {
            return new ValidationError('Not a valid SPDX document', 'spdx');
        }

        try {
            const doc = this.extractDocument(trimmed);
            
            if (doc.version < 2.0) {
                return new ValidationError(`Unsupported SPDX version: ${doc.version}`, 'version');
            }

            // Validate required fields
            if (!doc.name || !doc.dataVersion) {
                return new ValidationError('Missing required SPDX metadata', 'metadata');
            }

            const components = this.extractComponents(doc);
            
            return new ParsedSBOM({
                format: SBOMFormat.SPDX,
                version: doc.version,
                name: doc.name,
                dataVersion: doc.dataVersion,
                documentNamespace: doc.namespace,
                spdxId: doc.spdxId,
                timestamp: doc.timestamp,
                creators: doc.creators,
                contributors: doc.contributors,
                documentComment: doc.comment,
                externalRefs: doc.externalRefs,
                relationships: doc.relationships,
                packages: components,
                filesAnalyzed: doc.filesAnalyzed || [],
                annotations: doc.annotations,
            });

        } catch (error) {
            if (error instanceof ParseError) {
                return error;
            }
            return new ValidationError('SPDX parsing failed', 'parse');
        }
    }

    private static extractDocument(content: string): any {
        const doc = JSON.parse(content);
        
        // Handle SPDX JSON format
        if (doc.spdxVersion) {
            return {
                version: parseFloat(doc.spdxVersion),
                name: doc.name,
                dataVersion: doc.dataVersion || 'SPDX-2.3',
                namespace: doc.namespace,
                spdxId: doc.spdxId,
                timestamp: doc.timestamp,
                creators: doc.creators?.map(c => ({ type: c.type, name: c.name })) || [],
                contributors: doc.contributors?.map(c => ({ type: c.type, name: c.name })) || [],
                comment: doc.comment,
                filesAnalyzed: doc.filesAnalyzed?.map(f => f.fileName) || [],
                annotations: this.normalizeAnnotations(doc.annotations),
            };
        }

        // Handle SPDX YAML/Text format (simplified extraction)
        return {
            version: 2.3,
            name: 'Unknown',
            dataVersion: 'SPDX-2.3',
            namespace: '',
            spdxId: '',
            timestamp: new Date().toISOString(),
            creators: [],
            contributors: [],
            comment: '',
            filesAnalyzed: [],
            annotations: {},
        };
    }

    private static normalizeAnnotations(annotations?: any[]): Record<string, any> {
        if (!annotations) return {};
        
        const result: Record<string, any> = {};
        for (const ann of annotations || []) {
            const key = `${ann.annotationType}:${ann.ancestor}`;
            result[key] = ann.value;
        }
        return result;
    }

    private static extractComponents(doc: any): Component[] {
        // Handle both direct packages and nested dependencies
        let allPackages: any[] = [];
        
        if (doc.packages) {
            allPackages = doc.packages;
        } else if (doc.filesAnalyzed?.length > 0) {
            // Infer components from files analyzed
            for (const file of doc.filesAnalyzed) {
                const inferred: Component = {
                    name: 'inferred',
                    version: 'unknown',
                    type: 'file',
                    source: `spdx:${file.fileName}`,
                    licenses: ['NOASSERTION'],
                    supplier: 'Unknown',
                    maintainer: 'Unknown',
                };
                allPackages.push(inferred);
            }
        }

        return this.normalizeComponents(allPackages);
    }

    private static normalizeComponents(packages: any[]): Component[] {
        const result: Component[] = [];
        
        for (const pkg of packages) {
            let name = pkg.name || 'unknown';
            
            // Handle SPDX package names with qualifiers
            if (pkg.spdxId) {
                name = this.cleanSpdxName(pkg.spdxId);
            }

            const version = pkg.version || pkg.versionInfo?.version || '0.0.0';
            
            result.push({
                id: pkg.id || `spdx:${name}@${version}`,
                name,
                version: this.normalizeVersion(version),
                type: pkg.packageType || 'library',
                source: pkg.homepage || pkg.downloadLocation || '',
                licenses: this.normalizeLicenses(pkg.licenseConcluded || pkg.licenses?.[0]?.licenseId || []),
                supplier: pkg.supplier,
                maintainer: pkg.maintainer,
                description: pkg.description,
                checksums: this.extractChecksums(pkg.checksums),
                files: pkg.filesAnalyzed?.map(f => f.fileName) || [],
                externalRefs: pkg.externalRefs || [],
                relationships: pkg.relationships || [],
            });
        }

        return result;
    }

    private static cleanSpdxName(id: string): string {
        // Remove SPDX prefix and normalize
        let name = id.replace(/^SPDXRef-/, '');
        
        // Handle common patterns
        if (name.startsWith('pkg:')) {
            name = name.substring(4);
        }

        return name.trim() || 'unknown';
    }

    private static normalizeVersion(version: string): string {
        if (!version) return '0.0.0';
        
        // Normalize common version formats
        const normalized = version.replace(/^[vV]/, '').trim();
        
        // Handle semantic version ranges
        if (normalized.includes('||') || normalized.includes('..')) {
            return this.parseVersionRange(normalized);
        }

        return normalized;
    }

    private static parseVersionRange(range: string): VersionRange | null {
        const parts = range.split(/[\|\.\.]/).map(p => p.trim());
        
        if (parts.length === 0) return null;
        
        // Return first valid version or range representation
        return { type: 'range', raw: range, versions: parts };
    }

    private static normalizeLicenses(licenses: any[]): NormalizedLicense[] {
        const result: NormalizedLicense[] = [];
        
        for (const lic of licenses) {
            if (!lic || !lic.licenseId) continue;
            
            let licenseId = lic.licenseId;
            
            // Normalize common license ID formats
            if (licenseId.startsWith('https://')) {
                licenseId = this.extractLicenseName(licenseId);
            } else if (licenseId.includes('/')) {
                licenseId = licenseId.split('/').pop() || licenseId;
            }

            result.push({
                id: licenseId,
                name: lic.name || '',
                url: lic.url || '',
                expression: lic.expression || '',
            });
        }

        return result;
    }

    private static extractLicenseName(url: string): string {
        // Extract SPDX identifier from URL
        const patterns = [
            /spdx:\/\/([^\/]+)\//,
            /licenses\/([^\/]+)\//,
            /\/license\/([^\/]+)\//,
        ];

        for (const pattern of patterns) {
            const match = url.match(pattern);
            if (match && match[1]) {
                return match[1];
            }
        }

        // Fallback: extract from URL path
        const parts = url.split('/').filter(p => p.length > 0);
        return parts.slice(-2).join('/') || 'NOASSERTION';
    }

    private static extractChecksums(checksums?: any[]): Record<string, string>[] {
        if (!checksums) return [];
        
        const result: Record<string, string>[] = [];
        
        for (const cs of checksums) {
            if (cs.algorithm && cs.value) {
                result.push({ algorithm: cs.algorithm, value: cs.value });
            }
        }

        return result;
    }
}

/**
 * CycloneDX 1.4/1.5 Parser Implementation
 */
export class CycloneDxParser {
    private static readonly CYCLONE_VERSION_REGEX = /cyclonedx\/(\d+\.\d+)/i;
    
    public static parse(content: string): ParsedSBOM | ParseError {
        const trimmed = content.trim();
        
        // Quick format detection
        if (!trimmed.includes('<bom>') && !trimmed.startsWith('{')) {
            return new ValidationError('Not a valid CycloneDX document', 'cyclonedx');
        }

        try {
            let doc: any;
            
            if (trimmed.startsWith('{')) {
                // JSON format
                doc = JSON.parse(trimmed);
            } else {
                // XML format - simplified parsing
                doc = this.extractFromXML(trimmed);
            }

            const versionMatch = trimmed.match(this.CYCLONE_VERSION_REGEX);
            const version = versionMatch ? parseFloat(versionMatch[1]) : 1.4;

            if (version < 1.0) {
                return new ValidationError(`Unsupported CycloneDX version: ${version}`, 'version');
            }

            // Validate required fields
            if (!doc.bom || !doc.bom.metadata) {
                return new ValidationError('Missing required CycloneDX metadata', 'metadata');
            }

            const components = this.extractComponents(doc);
            
            return new ParsedSBOM({
                format: SBOMFormat.CycloneDX,
                version,
                name: doc.bom.metadata.component?.name || 'Unknown',
                dataVersion: doc.bom.metadata.version || '1.0',
                namespace: '',
                spdxId: '',
                timestamp: doc.bom.metadata.timestamp,
                creators: this.extractCreators(doc),
                contributors: [],
                documentComment: doc.bom.metadata.component?.description || '',
                externalRefs: doc.bom.metadata.externalReferences || [],
                relationships: [],
                packages: components,
                filesAnalyzed: [],
                annotations: {},
            });

        } catch (error) {
            if (error instanceof ParseError) {
                return error;
            }
            return new ValidationError('CycloneDX parsing failed', 'parse');
        }
    }

    private static extractFromXML(xml: string): any {
        // Simplified XML extraction - in production use a proper XML parser
        const doc: any = { bom: { metadata: {} } };
        
        // Extract basic metadata using regex
        const nameMatch = xml.match(/<name>([^<]+)<\/name>/);
        if (nameMatch) {
            doc.bom.metadata.component = { name: nameMatch[1] };
        }

        const versionMatch = xml.match(/<version>([^<]+)<\/version>/);
        if (versionMatch) {
            doc.bom.metadata.version = versionMatch[1];
        }

        return doc;
    }

    private static extractCreators(doc: any): any[] {
        const creators: any[] = [];
        
        // Handle various creator formats
        if (doc.bom.metadata.component?.authors) {
            for (const author of doc.bom.metadata.component.authors) {
                creators.push({ type: 'Person', name: author.name || '' });
            }
        }

        if (doc.bom.metadata.createdBy) {
            creators.push({ type: 'Tool', name: doc.bom.metadata.createdBy });
        }

        return creators;
    }

    private static extractComponents(doc: any): Component[] {
        let allComponents: any[] = [];
        
        // Handle direct components
        if (doc.bom.components) {
            allComponents = doc.bom.components;
        } else if (doc.bom.dependencies) {
            // Infer from dependencies
            for (const dep of doc.bom.dependencies) {
                const inferred: Component = {
                    name: 'dependency',
                    version: 'unknown',
                    type: 'library',
                    source: '',
                    licenses: ['NOASSERTION'],
                    supplier: '',
                    maintainer: '',
                };
                allComponents.push(inferred);
            }
        }

        return this.normalizeCycloneComponents(allComponents);
    }

    private static normalizeCycloneComponents(components: any[]): Component[] {
        const result: Component[] = [];
        
        for (const comp of components) {
            let name = comp.name || 'unknown';
            
            // Handle CycloneDX component types
            if (comp.type === 'file') {
                name = this.cleanFileName(comp.hash);
            }

            const version = comp.version || '0.0.0';
            
            result.push({
                id: comp.id || `cyclonedx:${name}@${version}`,
                name,
                version: this.normalizeVersion(version),
                type: comp.type || 'library',
                source: comp.homepage || comp.downloadUrl || '',
                licenses: this.normalizeLicenses(comp.licenses?.[0]?.licenseId || []),
                supplier: comp.supplier,
                maintainer: comp.maintainer,
                description: comp.description,
                checksums: this.extractChecksums(comp.hashes),
                files: comp.filesAnalyzed?.map(f => f.fileName) || [],
                externalRefs: comp.externalReferences || [],
                relationships: [],
            });
        }

        return result;
    }

    private static cleanFileName(hash: string): string {
        // Extract filename from hash or use default
        if (hash && !hash.startsWith('sha')) {
            const parts = hash.split('/');
            return parts[parts.length - 1] || 'unknown';
        }
        
        return 'unknown';
    }

    private static normalizeVersion(version: string): string {
        if (!version) return '0.0.0';
        
        // CycloneDX uses semver-style versions
        const normalized = version.replace(/^[vV]/, '').trim();
        
        return normalized;
    }

    private static normalizeLicenses(licenseIds: any[]): NormalizedLicense[] {
        const result: NormalizedLicense[] = [];
        
        for (const lic of licenseIds) {
            if (!lic || !lic.licenseId) continue;
            
            let licenseId = lic.licenseId;
            
            // Normalize CycloneDX license IDs
            if (licenseId.startsWith('https://')) {
                licenseId = this.extractLicenseName(licenseId);
            }

            result.push({
                id: licenseId,
                name: lic.name || '',
                url: lic.url || '',
                expression: lic.expression || '',
            });
        }

        return result;
    }

    private static extractChecksums(hashes?: any[]): Record<string, string>[] {
        if (!hashes) return [];
        
        const result: Record<string, string>[] = [];
        
        for (const h of hashes) {
            if (h.algorithm && h.value) {
                result.push({ algorithm: h.algorithm, value: h.value });
            }
        }

        return result;
    }
}

/**
 * Unified SBOM Parser Factory
 */
export class SBOMParserFactory {
    private static readonly PARSERS = new Map<SBOMFormat, () => any>();
    
    public static register(format: SBOMFormat, parser: () => any): void {
        this.PARSERS.set(format, parser);
    }

    public static create(): (content: string) => ParsedSBOM | ParseError {
        // Default to SPDX parser if no specific format detected
        return (content: string) => {
            const trimmed = content.trim();
            
            // Auto-detect format
            if (trimmed.startsWith('SPDX')) {
                return SPDXParser.parse(content);
            } else if (trimmed.includes('<bom>') || trimmed.includes('cyclonedx')) {
                return CycloneDxParser.parse(content);
            }

            // Default to SPDX as fallback
            return SPDXParser.parse(content);
        };
    }
}

/**
 * Utility functions for SBOM processing
 */
export namespace SBOMUtils {
    
    /**
     * Compare two versions and determine relationship
     */
    export function compareVersions(v1: string, v2: string): -1 | 0