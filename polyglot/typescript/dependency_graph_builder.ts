import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export interface PackageNode {
  name: string;
  version: string;
  type: 'direct' | 'transitive' | 'dev' | 'peer';
  scope?: string; // npm scope like @types/ or private packages
  maintainerEmail?: string;
  lastUpdated: Date;
}

export interface DependencyEdge {
  from: PackageNode;
  to: PackageNode;
  type: 'production' | 'development' | 'peer';
  transitiveDepth: number;
}

export interface GraphMetrics {
  totalNodes: number;
  totalEdges: number;
  maxDepth: number;
  widthAtLevel: Map<number, Set<string>>;
  circularDependencies: string[][];
  orphanedPackages: string[];
  criticalPath: string[];
}

export interface MaintainerChange {
  package: string;
  oldMaintainer?: string;
  newMaintainer: string;
  commitHash: string;
  timestamp: Date;
}

// ============================================================================
// PARSERS FOR DIFFERENT PACKAGE MANAGERS
// ============================================================================

class NpmParser {
  private static readonly PATTERNS = [
    /name\s*:\s*['"]([^'"]+)['"]/g,
    /version\s*:\s*['"]([^'"]+)['"]/g,
    /author\s*:\s*(['"])([^'"]+)\1/g,
  ];

  static parsePackageJson(content: string): PackageNode | null {
    const nameMatch = content.match(/name\s*:\s*['"]([^'"]+)['"]/);
    if (!nameMatch) return null;

    const versionMatch = content.match(/version\s*:\s*['"]([^'"]+)['"]/);
    const authorMatch = content.match(/author\s*:\s*(['"])([^'"]+)\1/g);

    let maintainerEmail: string | undefined;
    if (authorMatch) {
      for (const match of authorMatch) {
        const emailPart = match.split(' ').pop();
        if (emailPart && emailPart.includes('@')) {
          maintainerEmail = emailPart;
          break;
        }
      }
    }

    return {
      name: nameMatch[1],
      version: versionMatch?.[1] || '0.0.0',
      type: 'direct',
      scope: '',
      maintainerEmail,
      lastUpdated: new Date(),
    };
  }

  static parseLockFile(lockContent: string): Map<string, PackageNode> {
    const nodes = new Map<string, PackageNode>();

    // Handle yarn.lock format (YAML-like)
    if (lockContent.includes('## Dependencies')) {
      return this.parseYarnLock(lockContent);
    }

    // Handle package-lock.json (JSON with nested dependencies)
    try {
      const pkg = JSON.parse(lockContent);
      
      // Get root packages from "packages" or "name/version" field
      if (pkg.packages && typeof pkg.packages === 'object') {
        for (const [key, value] of Object.entries(pkg.packages)) {
          if (typeof value === 'string' || typeof value === 'object') {
            const parts = key.split('/');
            let name = parts[0];
            let version = '';

            if (parts.length > 1) {
              // Extract version from path like node_modules/@scope/pkg/1.2.3
              const verMatch = key.match(/\/([^/]+)$/);
              if (verMatch) {
                name = parts.slice(0, -1).join('/');
                version = verMatch[1];
              } else {
                // Try to get from value object
                const valObj = typeof value === 'object' ? value : {};
                const verMatch2 = (valObj as any)?.version;
                if (verMatch2) version = String(verMatch2);
              }

              nodes.set(name, {
                name: name.replace(/\/.*$/, ''), // Remove path suffix
                version,
                type: 'transitive',
                scope: parts[0].startsWith('@') ? parts.slice(1, 2).join('/') : '',
                lastUpdated: new Date(),
              });
            }
          }
        }
      }

      // Also check "dependencies" field for root deps
      if (pkg.dependencies) {
        for (const [depName, depVer] of Object.entries(pkg.dependencies)) {
          const node = nodes.get(depName);
          if (!node) {
            nodes.set(depName, {
              name: depName,
              version: String(depVer),
              type: 'direct',
              scope: '',
              lastUpdated: new Date(),
            });
          } else {
            node.type = 'direct';
          }
        }
      }

      return nodes;
    } catch (e) {
      // Fallback to simple parsing
      return this.parseSimpleLock(lockContent);
    }
  }

  private static parseYarnLock(content: string): Map<string, PackageNode> {
    const nodes = new Map<string, PackageNode>();
    
    // Extract package blocks
    const blockRegex = /##\s+Dependencies\n([\s\S]*?)(?===|\n##\s+)/g;
    let match;

    while ((match = blockRegex.exec(content)) !== null) {
      const block = match[1];
      
      // Extract name and version from header line
      const headerMatch = block.match(/^(\S+)\s+(\S+)/);
      if (headerMatch) {
        const [, name, version] = headerMatch;
        
        let scope = '';
        if (name.startsWith('@')) {
          const parts = name.split('/');
          scope = parts.slice(1).join('/');
        }

        nodes.set(name, {
          name: name,
          version: version || '0.0.0',
          type: 'transitive',
          scope,
          lastUpdated: new Date(),
        });
      }
    }

    return nodes;
  }

  private static parseSimpleLock(content: string): Map<string, PackageNode> {
    const nodes = new Map<string, PackageNode>();
    
    // Simple regex-based extraction
    const nameVerRegex = /name\s*:\s*['"]([^'"]+)['"]/g;
    let match;

    while ((match = nameVerRegex.exec(content)) !== null) {
      const [, name] = match;
      
      const versionMatch = content.match(/version\s*:\s*['"]([^'"]+)['"]/);
      nodes.set(name, {
        name: name,
        version: versionMatch?.[1] || '0.0.0',
        type: 'transitive',
        scope: '',
        lastUpdated: new Date(),
      });
    }

    return nodes;
  }
}

class CargoParser {
  static parseCargoLock(content: string): Map<string, PackageNode> {
    const nodes = new Map<string, PackageNode>();
    
    // Parse package blocks from cargo.lock
    const pkgRegex = /package\s*\(\s*name\s*=\s*"([^"]+)"\s*,\s*version\s*=\s*"([^"]+)"/g;
    let match;

    while ((match = pkgRegex.exec(content)) !== null) {
      const [, name, version] = match;
      
      // Extract authors if present
      let authorEmail: string | undefined;
      const authorRegex = /author\s*=\s*"([^"]+)"/g;
      for (const authMatch of content.matchAll(authorRegex)) {
        const emailPart = authMatch[1].split(' ').pop();
        if (emailPart && emailPart.includes('@')) {
          authorEmail = emailPart;
          break;
        }
      }

      nodes.set(name, {
        name: name,
        version: version || '0.0.0',
        type: 'transitive',
        scope: '',
        maintainerEmail: authorEmail,
        lastUpdated: new Date(),
      });
    }

    return nodes;
  }
}

class PipParser {
  static parsePipLock(content: string): Map<string, PackageNode> {
    const nodes = new Map<string, PackageNode>();
    
    // Parse requirements from pip freeze or pip-compile output
    const pkgRegex = /^(\S+)\s*==\s*(\S+)/gm;
    let match;

    while ((match = pkgRegex.exec(content)) !== null) {
      nodes.set(match[1], {
        name: match[1],
        version: match[2] || '0.0.0',
        type: 'direct',
        scope: '',
        lastUpdated: new Date(),
      });
    }

    return nodes;
  }
}

// ============================================================================
// GRAPH DATA STRUCTURE
// ============================================================================

class DependencyGraph {
  private nodes: Map<string, PackageNode> = new Map();
  private edges: Map<string, Set<DependencyEdge>> = new Map();
  private rootNodes: string[] = [];

  constructor() {}

  addRootPackage(name: string, node: PackageNode) {
    this.nodes.set(name, node);
    if (!this.edges.has(name)) {
      this.edges.set(name, new Set());
    }
    this.rootNodes.push(name);
  }

  addEdge(fromName: string, toName: string, type: 'production' | 'development' | 'peer', depth: number = 0) {
    const fromNode = this.nodes.get(fromName);
    if (!fromNode) return;

    // Update node's last updated timestamp
    fromNode.lastUpdated = new Date();

    let edge: DependencyEdge;
    if (this.edges.has(fromName)) {
      for (const existing of this.edges.get(fromName)!) {
        if (existing.to.name === toName && existing.transitiveDepth === depth) {
          // Update existing edge
          existing.type = type;
          return;
        }
      }
    }

    const newEdge: DependencyEdge = {
      from: fromNode,
      to: this.nodes.get(toName) || { name: toName, version: '0.0.0', type: 'transitive' as any },
      type,
      transitiveDepth: depth,
    };

    if (!this.edges.has(fromName)) {
      this.edges.set(fromName, new Set());
    }
    this.edges.get(fromName)!.add(newEdge);
  }

  getNodes(): PackageNode[] {
    return Array.from(this.nodes.values());
  }

  getEdges(): DependencyEdge[] {
    const edges: DependencyEdge[] = [];
    
    for (const [from, edgeSet] of this.edges.entries()) {
      for (const edge of edgeSet) {
        edges.push(edge);
      }
    }

    return edges;
  }

  getMetrics(): GraphMetrics {
    let maxDepth = 0;
    const widthAtLevel: Map<number, Set<string>> = new Map();
    const circularDependencies: string[][] = [];
    const orphanedPackages: string[] = [];
    let criticalPath: string[] = [];

    // Calculate depth and width for each node
    for (const [name, node] of this.nodes.entries()) {
      if (node.type === 'direct') {
        maxDepth = Math.max(maxDepth, 0);
        
        // Track width at each level
        const currentLevel = new Set<string>();
        let depth = 0;

        // BFS to find depth from root
        const visited: Set<string> = new Set();
        const queue: [string, number][] = [[name, 0]];

        while (queue.length > 0) {
          const [current, d] = queue.shift()!;
          
          if (!visited.has(current)) {
            visited.add(current);
            
            // Track width at this depth
            if (!widthAtLevel.has(d)) {
              widthAtLevel.set(d, new Set());
            }
            widthAtLevel.get(d)!.add(name);

            // Get children
            const children = this.edges.get(current)?.toArray() || [];
            
            for (const child of children) {
              if (!visited.has(child.to.name)) {
                queue.push([child.to.name, d + 1]);
                maxDepth = Math.max(maxDepth, d + 1);
              }
            }
          }
        }

        // Find orphaned packages (nodes with no incoming edges from root)
        const hasIncomingFromRoot = this.rootNodes.some(r => 
          this.edges.get(r)?.some(e => e.to.name === name)
        );
        
        if (!hasIncomingFromRoot && node.type !== 'transitive') {
          orphanedPackages.push(name);
        }

        // Find critical path (longest path from root)
        const longestPath = this.findLongestPathToNode(name, visited);
        if (longestPath.length > criticalPath.length) {
          criticalPath = longestPath;
        }
      }
    }

    // Detect circular dependencies using DFS
    this.detectCycles(circularDependencies);

    return {
      totalNodes: this.nodes.size,
      totalEdges: edges.length,
      maxDepth,
      widthAtLevel,
      circularDependencies,
      orphanedPackages,
      criticalPath,
    };
  }

  private findLongestPathToNode(nodeName: string, visited: Set<string>): string[] {
    if (!this.nodes.has(nodeName)) return [];

    const current = this.nodes.get(nodeName);
    if (!current) return [];

    // Get children
    const children = this.edges.get(nodeName)?.toArray() || [];
    
    let longestPath: string[] = [nodeName];
    
    for (const child of children) {
      if (!visited.has(child.to.name)) {
        visited.add(child.to.name);
        const childPath = this.findLongestPathToNode(child.to.name, visited);
        
        if (childPath.length + 1 > longestPath.length) {
          longestPath = [nodeName, ...childPath];
        }

        visited.delete(child.to.name);
      }
    }

    return longestPath;
  }

  private detectCycles(circularDependencies: string[][]) {
    const visited: Set<string> = new Set();
    const recStack: Set<string> = new Set();
    
    for (const [name, node] of this.nodes.entries()) {
      if (!visited.has(name)) {
        const path: string[] = [];
        this.dfsCycleCheck(name, visited, recStack, path, circularDependencies);
      }
    }
  }

  private dfsCycleCheck(
    name: string, 
    visited: Set<string>, 
    recStack: Set<string>, 
    path: string[],
    circularDependencies: string[][]
  ) {
    if (recStack.has(name)) {
      // Found cycle - extract it
      const cycleStart = path.indexOf(name);
      if (cycleStart !== -1) {
        circularDependencies.push(path.slice(cycleStart));
      }
      return;
    }

    visited.add(name);
    recStack.add(name);
    
    const children = this.edges.get(name)?.toArray() || [];
    
    for (const child of children) {
      if (!visited.has(child.to.name)) {
        path.push(child.to.name);
        this.dfsCycleCheck(child.to.name, visited, recStack, path, circularDependencies);
        path.pop();
      }
    }

    recStack.delete(name);
  }

  getRootNodes(): string[] {
    return [...this.rootNodes];
  }

  // ============================================================================
  // MAINTAINER CHANGE TRACKING
  // ============================================================================

  async trackMaintainerChanges(workingDir: string, gitRepo?: boolean): Promise<MaintainerChange[]> {
    const changes: MaintainerChange[] = [];

    if (!gitRepo) return changes;

    try {
      // Get list of root packages
      const rootPackages = this.getRootNodes();

      for (const pkgName of rootPackages) {
        const node = this.nodes.get(pkgName);
        if (!node || !node.maintainerEmail) continue;

        // Check git log for maintainer changes
        try {
          const result = await execSync(
            `git -C "${workingDir}" log --format="%H %ae" --grep="${pkgName}" | tail -10`,
            { encoding: 'utf8' }
          );

          // Parse git output to find maintainer changes
          const lines = result.split('\n');
          
          for (const line of lines) {
            if (!line.trim()) continue;

            const parts = line.trim().split(' ');
            const commitHash = parts[0];
            const email = parts.slice(1).join(' ').trim();

            // Check if this is a new maintainer
            if (email !== node.maintainerEmail) {
              changes.push({
                package: pkgName,
                oldMaintainer: node.maintainerEmail,
                newMaintainer: email,