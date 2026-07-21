require 'yaml'
require 'json'
require 'date'
require 'time'

module Sbomgate
  # Container for parsed SBOM data
  class SboMData < Struct.new(:packages, :metadata, :relationships)
    def self.from_yaml(yaml_string)
      new.from_yaml(yaml_string)
    end
    
    def from_yaml(yaml_string)
      @yaml = yaml_string
      parse!
      self
    end

    private

    def parse!
      begin
        doc = YAML.safe_load(@yaml, permitted_classes: [Date, Time]) || {}
        
        # Extract metadata
        extract_metadata(doc)
        
        # Extract packages
        @packages = extract_packages(doc)
        
        # Extract relationships (dependencies)
        @relationships = extract_relationships(doc)
      rescue => e
        raise "SBOM parse error: #{e.message}"
      end
      
      self
    end

    def extract_metadata(doc)
      return unless doc.key?('spdxVersion') || doc.key?('documentNamespace')
      
      @metadata = {
        spdx_version: doc['spdxVersion']&.to_s,
        document_namespace: doc['documentNamespace']&.to_s,
        name: doc['name']&.to_s,
        data_license: doc['dataLicense']&.to_s,
        document_date: parse_date(doc['documentDate']),
        creator: extract_creators(doc),
        contributors: extract_contributors(doc)
      }
    end

    def extract_packages(doc)
      return [] unless doc.key?('packages')
      
      packages = []
      doc['packages'].each do |pkg|
        next unless pkg.is_a?(Hash) && pkg.key?('name') || pkg.key?('SPDXID')
        
        # Normalize package name to SPDX ID format if needed
        spdx_id = pkg['SPDXID']&.to_s || 
                  (pkg['name']&.to_s&.gsub(/\s+/, '_').upcase)
        
        packages << {
          spdx_id: spdx_id,
          name: pkg['name']&.to_s,
          version_info: extract_version(pkg),
          supplier: pkg['supplier']&.to_s,
          download_location: pkg['downloadLocation']&.to_s,
          files_analyzed: pkg['filesAnalyzed'] == true,
          license_concluded: pkg['licenseConcluded']&.to_s,
          license_declared: pkg['licenseDeclared']&.to_s,
          copyright_text: pkg['copyrightText']&.to_s,
          summary: pkg['summary']&.to_s,
          description: pkg['description']&.to_s,
          external_references: extract_external_refs(pkg),
          attributes: extract_attributes(pkg)
        }
      end
      
      packages
    end

    def extract_version(pkg)
      # Try various version fields
      ver = pkg['versionInfo']&.to_s || 
            pkg['version']&.to_s || 
            pkg['packageVersion']&.to_s
      
      return nil if ver.nil? || ver.empty?
      
      { raw: ver, normalized: normalize_version(ver) }
    end

    def normalize_version(v)
      # Remove common prefixes/suffixes for comparison
      v.to_s.gsub(/^[vV]|\.(dev|alpha|beta|rc|pre)/i, '')&.strip
    end

    def extract_creators(doc)
      return [] unless doc.key?('creators')
      
      doc['creators'].map { |c| c.is_a?(Hash) ? c['name'] : c.to_s }.compact
    end

    def extract_contributors(doc)
      return [] unless doc.key?('contributors')
      
      doc['contributors'].map { |c| c.is_a?(Hash) ? c['name'] : c.to_s }.compact
    end

    def extract_external_refs(pkg)
      return {} unless pkg.key?('externalRefs')
      
      refs = {}
      pkg['externalRefs'].each do |ref|
        next unless ref.is_a?(Hash) && ref.key?('referenceCategory')
        
        cat = ref['referenceCategory']&.to_s || 'OTHER'
        ref_id = ref['referenceLocator']&.to_s
        
        refs[cat] ||= []
        refs[cat] << { id: ref_id, type: ref['referenceType']&.to_s } if ref_id
      end
      
      refs
    end

    def extract_attributes(pkg)
      return {} unless pkg.key?('attributes')
      
      attrs = {}
      pkg['attributes'].each do |attr|
        next unless attr.is_a?(Hash) && 
                     (attr.key?('attributeName') || attr.key?('key'))
        
        key = attr['attributeName']&.to_s || attr['key']&.to_s
        value = attr['attributeValue']&.to_s || attr['value']&.to_s
        
        attrs[key] = { raw: value, normalized: normalize_attr_value(value) } if value
      end
      
      attrs
    end

    def extract_relationships(doc)
      return [] unless doc.key?('relationships')
      
      rels = []
      doc['relationships'].each do |rel|
        next unless rel.is_a?(Hash) && 
                     (rel.key?('spdxElementId') || rel.key?('fromSPDXID'))
        
        from_id = rel['spdxElementId']&.to_s || rel['fromSPDXID']&.to_s
        to_id = rel['spdxRelationTo']&.to_s || rel['toSPDXID']&.to_s
        
        next unless from_id && to_id
        
        rels << {
          from: from_id,
          to: to_id,
          type: rel['relationshipType']&.to_s || 'DEPENDENCY'
        }
      end
      
      rels
    end

    def parse_date(date_str)
      return nil if date_str.nil? || date_str.empty?
      
      formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M:%S%z'
      ]
      
      formats.each do |fmt|
        begin
          return Time.parse(date_str) if date_str =~ /\A#{Regexp.escape(fmt)}\z/
        rescue
          next
        end
      end
      
      nil
    end

    def normalize_attr_value(v)
      v.to_s.gsub(/\s+/, ' ').strip
    end

    public

    # Quick summary of the parsed SBOM
    def summary
      {
        packages_count: @packages.size,
        metadata: @metadata&.merge({
          spdx_version: @metadata[:spdx_version]&.to_s || 'Unknown',
          document_date: @metadata[:document_date].iso8601 if @metadata[:document_date]
        })
      }
    end

    # Find package by SPDX ID or name+version
    def find_package(spdx_id, version: nil)
      spdx_id = spdx_id.to_s.upcase.gsub(/_/, ' ')
      
      @packages.find do |pkg|
        pkg[:spdx_id].to_s.upcase == spdx_id ||
          (pkg[:name]&.to_s&.upcase&.gsub(/\s+/, '_') == spdx_id)
      end
    end

    # Find all packages matching a name pattern
    def find_by_name_pattern(pattern, case_sensitive: false)
      regex = case_sensitive ? Regexp.new(pattern) : Regexp.new(escape_regex(pattern), 'i')
      
      @packages.select { |p| p[:name]&.to_s =~ regex }
    end

    # Build a dependency graph from relationships
    def build_dependency_graph
      nodes = {}
      edges = []
      
      @relationships.each do |rel|
        from_id, to_id = rel[:from], rel[:to]
        
        next unless from_id && to_id
        
        nodes[from_id] ||= { name: from_id, children: [], parents: [] }
        nodes[to_id] ||= { name: to_id, children: [], parents: [] }
        
        edges << { from: from_id, to: to_id, type: rel[:type] }
      end
      
      # Add package names if available
      @packages.each do |pkg|
        next unless pkg[:spdx_id] && nodes[pkg[:spdx_id]]
        name = pkg[:name]&.to_s&.upcase&.gsub(/\s+/, '_') || pkg[:spdx_id].to_s.upcase
        
        nodes[pkg[:spdx_id]].merge!(name: name)
      end
      
      { nodes: nodes.values, edges: edges }
    end

    # Check if a package is vulnerable (placeholder for integration)
    def check_vulnerabilities(pkg_spdx_id, vuln_db = {})
      pkg = find_package(pkg_spdx_id)
      return [] unless pkg
      
      vulnerabilities = []
      
      pkg[:version_info]&.each do |ver|
        next unless ver[:raw]
        
        # Check against vulnerability database (placeholder)
        if vuln_db[pkg[:spdx_id]]
          vuln_db[pkg[:spdx_id]].each do |vuln|
            if version_matches?(ver[:normalized], vuln[:version])
              vulnerabilities << {
                cve: vuln[:cve],
                severity: vuln[:severity] || 'Unknown',
                fixed_in: vuln[:fixed_in]
              }
            end
          end
        end
      end
      
      vulnerabilities
    end

    private

    def escape_regex(str)
      str.gsub(/[\^\$\.\|\[\]\(\)\{\}\*\+\?\/\\\s]/, '\\\\&')
    end

    def version_matches?(pkg_version, vuln_version)
      return false if pkg_version.nil? || vuln_version.nil?
      
      # Simple semantic comparison - can be enhanced
      pkg_parts = pkg_version.split('.').map(&:to_i).compact
      vuln_parts = vuln_version.split('.').map(&:to_i).compact
      
      return true if pkg_parts == vuln_parts
      
      false
    end

    def extract_version(pkg)
      # Try various version fields
      ver = pkg['versionInfo']&.to_s || 
            pkg['version']&.to_s || 
            pkg['packageVersion']&.to_s
      
      return nil if ver.nil? || ver.empty?
      
      { raw: ver, normalized: normalize_version(ver) }
    end

    def normalize_version(v)
      # Remove common prefixes/suffixes for comparison
      v.to_s.gsub(/^[vV]|\.(dev|alpha|beta|rc|pre)/i, '')&.strip
    end

    def extract_external_refs(pkg)
      return {} unless pkg.key?('externalRefs')
      
      refs = {}
      pkg['externalRefs'].each do |ref|
        next unless ref.is_a?(Hash) && ref.key?('referenceCategory')
        
        cat = ref['referenceCategory']&.to_s || 'OTHER'
        ref_id = ref['referenceLocator']&.to_s
        
        refs[cat] ||= []
        refs[cat] << { id: ref_id, type: ref['referenceType']&.to_s } if ref_id
      end
      
      refs
    end

    def extract_attributes(pkg)
      return {} unless pkg.key?('attributes')
      
      attrs = {}
      pkg['attributes'].each do |attr|
        next unless attr.is_a?(Hash) && 
                     (attr.key?('attributeName') || attr.key?('key'))
        
        key = attr['attributeName']&.to_s || attr['key']&.to_s
        value = attr['attributeValue']&.to_s || attr['value']&.to_s
        
        attrs[key] = { raw: value, normalized: normalize_attr_value(value) } if value
      end
      
      attrs
    end

    def extract_relationships(doc)
      return [] unless doc.key?('relationships')
      
      rels = []
      doc['relationships'].each do |rel|
        next unless rel.is_a?(Hash) && 
                     (rel.key?('spdxElementId') || rel.key?('fromSPDXID'))
        
        from_id = rel['spdxElementId']&.to_s || rel['fromSPDXID']&.to_s
        to_id = rel['spdxRelationTo']&.to_s || rel['toSPDXID']&.to_s
        
        next unless from_id && to_id
        
        rels << {
          from: from_id,
          to: to_id,
          type: rel['relationshipType']&.to_s || 'DEPENDENCY'
        }
      end
      
      rels
    end

    def parse_date(date_str)
      return nil if date_str.nil? || date_str.empty?
      
      formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M:%S%z'
      ]
      
      formats.each do |fmt|
        begin
          return Time.parse(date_str) if date_str =~ /\A#{Regexp.escape(fmt)}\z/
        rescue
          next
        end
      end
      
      nil
    end

    def normalize_attr_value(v)
      v.to_s.gsub(/\s+/, ' ').strip
    end

    public

    # Quick summary of the parsed SBOM
    def summary
      {
        packages_count: @packages.size,
        metadata: @metadata&.merge({
          spdx_version: @metadata[:spdx_version]&.to_s || 'Unknown',
          document_date: @metadata[:document_date].iso8601 if @metadata[:document_date]
        })
      }
    end

    # Find package by SPDX ID or name+version
    def find_package(spdx_id, version: nil)
      spdx_id = spdx_id.to_s.upcase.gsub(/_/, ' ')
      
      @packages.find do |pkg|
        pkg[:spdx_id].to_s.upcase == spdx_id ||
          (pkg[:name]&.to_s&.upcase&.gsub(/\s+/, '_') == spdx_id)
      end
    end

    # Find all packages matching a name pattern
    def find_by_name_pattern(pattern, case_sensitive: false)
      regex = case_sensitive ? Regexp.new(pattern) : Regexp.new(escape_regex(pattern), 'i')
      
      @packages.select { |p| p[:name]&.to_s =~ regex }
    end

    # Build a dependency graph from relationships
    def build_dependency_graph
      nodes = {}
      edges = []
      
      @relationships.each do |rel|
        from_id, to_id = rel[:from], rel[:to]
        
        next unless from_id && to_id
        
        nodes[from_id] ||= { name: from_id, children: [], parents: [] }
        nodes[to_id] ||= { name: to_id, children: [], parents: [] }
        
        edges << { from: from_id, to: to_id, type: rel[:type] }
      end
      
      # Add package names if available
      @packages.each do |pkg|
        next unless pkg[:spdx_id] && nodes[pkg[:spdx_id]]
        name = pkg[:name]&.to_s&.upcase&.gsub(/\s+/, '_') || pkg[:spdx_id].to_s.upcase
        
        nodes[pkg[:spdx_id]].merge!(name: name)
      end
      
      { nodes: nodes.values, edges: edges }
    end

    # Check if a package is vulnerable (placeholder for integration)
    def check_vulnerabilities(pkg_spdx_id, vuln_db = {})
      pkg = find_package(pkg_spdx_id)
      return [] unless pkg
      
      vulnerabilities = []
      
      pkg[:version_info]&.each do |ver|
        next unless ver[:raw]
        
        # Check against vulnerability database (placeholder)
        if vuln_db[pkg[:spdx_id]]
          vuln_db[pkg[:spdx_id]].each do |vuln|
            if version_matches?(ver[:normalized], vuln[:version])
              vulnerabilities << {
                cve: vuln[:cve],
                severity: vuln[:severity] || 'Unknown',
                fixed_in: vuln[:fixed_in]
              }
            end
          end
        end
      end
      
      vulnerabilities
    end

    private

    def escape_regex(str)
      str.gsub(/[\^\$\.\|\[\]\(\)\{\}\*\+\?\/\\\s]/, '\\\\&')
    end

    def version_matches?(pkg_version, vuln_version)
      return false if pkg_version.nil? || vuln_version.nil?
      
      # Simple semantic comparison - can be enhanced
      pkg_parts = pkg_version.split('.').map(&:to_i).compact
      vuln_parts = vuln_version.split('.').map(&:to_i).compact