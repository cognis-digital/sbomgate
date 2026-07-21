using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace sbomgate
{
    /// <summary>
    /// Core domain model for SBOM representation.
    /// </summary>
    public class SbomRecord
    {
        public string? Name { get; set; }
        public string? Version { get; set; }
        public List<SpdxPackage> Components { get; set; } = new();
        public List<SpdxMaintainer> Maintainers { get; set; } = new();
        public DateTime? Created { get; set; }
        public DateTime? Updated { get; set; }
        public string? DataVersion { get; set; }

        /// <summary>
        /// Returns all unique maintainer email addresses.
        /// </summary>
        public IReadOnlyList<string> GetMaintainerEmails() => 
            Maintainers.Select(m => m.Email).Distinct().ToList();

        /// <summary>
        /// Compares this SBOM against another and returns changed maintainers.
        /// </summary>
        public SbomDiffResult CompareTo(SbomRecord other)
        {
            var myEmails = GetMaintainerEmails().ToHashSet();
            var theirEmails = other.GetMaintainerEmails().ToHashSet();

            var added = theirEmails.Except(myEmails).ToList();
            var removed = myEmails.Except(theirEmails).ToList();
            var common = myEmails.Intersect(theirEmails).ToList();

            return new SbomDiffResult
            {
                AddedMaintainers = added,
                RemovedMaintainers = removed,
                CommonMaintainers = common,
                NameChanged = !string.Equals(Name, other.Name, StringComparison.Ordinal),
                VersionChanged = !string.Equals(Version, other.Version, StringComparison.Ordinal)
            };
        }

        public override string ToString() => 
            $"SbomRecord({Name ?? "unnamed"}, v{Version ?? "?"})";
    }

    /// <summary>
    /// Represents a single package/component within an SBOM.
    /// </summary>
    public class SpdxPackage
    {
        public string? Name { get; set; }
        public string? Version { get; set; }
        public string? DownloadLocation { get; set; }
        public List<SpdxMaintainer> Maintainers { get; set; } = new();

        /// <summary>
        /// Returns a normalized identifier for comparison.
        /// </summary>
        public string GetNormalizedId() => 
            $"{Name}#{Version ?? "latest"}";
    }

    /// <summary>
    /// Represents a maintainer/contact person.
    /// </summary>
    public class SpdxMaintainer
    {
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? Organization { get; set; }

        /// <summary>
        /// Returns a normalized key for deduplication.
        /// </summary>
        public string GetNormalizedKey() => 
            $"{Name}#{Email ?? "noemail"}#{Organization ?? "none"}";
    }

    /// <summary>
    /// Result of comparing two SBOM records.
    /// </summary>
    public class SbomDiffResult
    {
        public List<string> AddedMaintainers { get; set; } = new();
        public List<string> RemovedMaintainers { get; set; } = new();
        public List<string> CommonMaintainers { get; set; } = new();
        public bool NameChanged { get; set; }
        public bool VersionChanged { get; set; }

        /// <summary>
        /// Returns a human-readable summary.
        /// </summary>
        public string GetSummary()
        {
            var parts = new List<string>();

            if (NameChanged) parts.Add("Name changed");
            if (VersionChanged) parts.Add($"v{Version ?? "?"} → v{AddedMaintainers.Count > 0 ? "new" : "?"}");

            if (parts.Count == 0) parts.Add("No significant changes");

            return string.Join(", ", parts);
        }
    }

    /// <summary>
    /// Main parser for SPDX-format SBOMs.
    /// Supports JSON and YAML inputs via auto-detection.
    /// </summary>
    public class SbomParser
    {
        private const string SPDX_VERSION_KEY = "spdxVersion";
        private const string NAME_KEY = "name";
        private const string VERSION_KEY = "version";

        /// <summary>
        /// Parses an SBOM from a file path. Auto-detects format.
        /// </summary>
        public static SbomRecord ParseFile(string path) => 
            ParseContent(File.ReadAllText(path));

        /// <summary>
        /// Parses an SBOM from raw content string.
        /// </summary>
        public static SbomRecord ParseContent(string content)
        {
            var (format, jsonContent) = DetectFormat(content);

            if (format == Format.Json)
                return ParseJson(jsonContent);
            
            if (format == Format.Yaml)
                return ParseYaml(content);

            throw new FormatException($"Unsupported SBOM format: {format}");
        }

        private static (Format, string) DetectFormat(string content)
        {
            var trimmed = content.Trim();
            var jsonCheck = JsonDocument.Parse(trimmed).RootElement;
            
            // Check for SPDX-specific fields in JSON
            if (jsonCheck.TryGetProperty("spdxVersion", out _))
                return (Format.Json, trimmed);

            // Check for YAML indicators
            if (trimmed.StartsWith("---") || 
                trimmed.Contains(": ") && !trimmed.Contains("\""))
                return (Format.Yaml, trimmed);

            // Default to JSON as it's more common in CI/CD pipelines
            return (Format.Json, trimmed);
        }

        private static SbomRecord ParseJson(string json)
        {
            var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Extract top-level metadata
            var record = new SbomRecord();

            if (root.TryGetProperty("spdxVersion", out var spdxVer))
                record.DataVersion = spdxVer.GetString();

            if (root.TryGetProperty(NAME_KEY, out var nameProp))
                record.Name = nameProp.GetString();

            if (root.TryGetProperty(VERSION_KEY, out var verProp))
                record.Version = verProp.GetString();

            // Extract components/packages
            if (root.TryGetProperty("packages", out var packagesArr))
            {
                foreach (var pkg in packagesArr.EnumerateArray())
                {
                    var spdxPkg = new SpdxPackage();

                    if (pkg.TryGetProperty(NAME_KEY, out var pName))
                        spdxPkg.Name = pName.GetString();

                    if (pkg.TryGetProperty(VERSION_KEY, out var pVer))
                        spdxPkg.Version = pVer.GetString();

                    if (pkg.TryGetProperty("downloadLocation", out var dlLoc))
                        spdxPkg.DownloadLocation = dlLoc.GetString();

                    // Extract maintainers from package level
                    if (pkg.TryGetProperty("maintainers", out var maintArr))
                    {
                        foreach (var m in maintArr.EnumerateArray())
                        {
                            var spdxM = new SpdxMaintainer();
                            
                            if (m.TryGetProperty("name", out var mName))
                                spdxM.Name = mName.GetString();

                            if (m.TryGetProperty("email", out var mEmail))
                                spdxM.Email = mEmail.GetString();

                            if (m.TryGetProperty("organization", out var mOrg))
                                spdxM.Organization = mOrg.GetString();

                            spdxPkg.Maintainers.Add(spdxM);
                        }
                    }

                    record.Components.Add(spdxPkg);
                }
            }

            // Extract top-level maintainers (optional, per SPDX spec)
            if (root.TryGetProperty("maintainers", out var topMaintArr))
            {
                foreach (var m in topMaintArr.EnumerateArray())
                {
                    var spdxM = new SpdxMaintainer();

                    if (m.TryGetProperty(NAME_KEY, out var mName))
                        spdxM.Name = mName.GetString();

                    if (m.TryGetProperty(VERSION_KEY, out var mEmail)) // YAML uses version for email sometimes
                        spdxM.Email = mEmail.GetString();

                    record.Maintainers.Add(spdxM);
                }
            }

            return record;
        }

        private static SbomRecord ParseYaml(string yaml)
        {
            var doc = JsonDocument.Parse(yaml);
            var root = doc.RootElement;

            // YAML often uses different property names, so we normalize
            var record = new SbomRecord();

            if (root.TryGetProperty("spdxVersion", out _))
                record.DataVersion = "2.3"; // Default for SPDX 2.3+

            if (root.TryGetProperty(NAME_KEY, out _))
                record.Name = root.GetProperty(NAME_KEY).GetString();

            if (root.TryGetProperty(VERSION_KEY, out _))
                record.Version = root.GetProperty(VERSION_KEY).GetString();

            // Handle YAML-style maintainers array
            if (root.TryGetProperty("maintainers", out var maintArr))
            {
                foreach (var m in maintArr.EnumerateArray())
                {
                    var spdxM = new SpdxMaintainer();

                    if (m.TryGetProperty(NAME_KEY, out _))
                        spdxM.Name = m.GetProperty(NAME_KEY).GetString();

                    if (m.TryGetProperty("email", out _))
                        spdxM.Email = m.GetProperty("email").GetString();

                    record.Maintainers.Add(spdxM);
                }
            }

            // Handle YAML-style packages array
            if (root.TryGetProperty("packages", out var pkgArr))
            {
                foreach (var p in pkgArr.EnumerateArray())
                {
                    var spdxPkg = new SpdxPackage();

                    if (p.TryGetProperty(NAME_KEY, out _))
                        spdxPkg.Name = p.GetProperty(NAME_KEY).GetString();

                    if (p.TryGetProperty(VERSION_KEY, out _))
                        spdxPkg.Version = p.GetProperty(VERSION_KEY).GetString();

                    record.Components.Add(spdxPkg);
                }
            }

            return record;
        }

        /// <summary>
        /// Returns a formatted summary of the SBOM.
        /// </summary>
        public static string FormatSummary(SbomRecord record)
        {
            var lines = new List<string>();

            lines.Add($"SBOM: {record.Name ?? "unnamed"}");
            lines.Add($"Version: {record.Version ?? "unknown"}");
            lines.Add($"Components: {record.Components.Count}");
            lines.Add($"Maintainers: {record.Maintainers.Count}");

            if (record.Created.HasValue)
                lines.Add($"Created: {record.Created.Value:yyyy-MM-dd}");

            if (record.Updated.HasValue)
                lines.Add($"Updated: {record.Updated.Value:yyyy-MM-dd}");

            return string.Join("\n", lines);
        }

        /// <summary>
        /// Formats a diff result for display.
        /// </summary>
        public static string FormatDiff(SbomDiffResult diff) => 
            $"Diff: {diff.GetSummary()}";
    }

    /// <summary>
    /// Demonstrates and tests the SBOM parser functionality.
    /// Run this file to see examples in action.
    /// </summary>
    public class Program
    {
        public static void Main()
        {
            Console.WriteLine("=== sbomgate: SBOM Parser Demo ===\n");

            // Example 1: Parse a sample JSON SBOM content
            var sampleJson = @"{
                ""spdxVersion"": ""2.3"",
                ""name"": ""sample-app"",
                ""version"": ""1.0.0"",
                ""packages"": [
                    {
                        ""name"": ""libcurl"",
                        ""version"": ""7.84.0"",
                        ""downloadLocation"": ""https://github.com/curl/libcurl/archive/v7.84.0.tar.gz"",
                        ""maintainers"": [
                            {""name"": ""John Doe"", ""email"": ""john@example.com""},
                            {""name"": ""Jane Smith"", ""email"": ""jane@corp.org""}
                        ]
                    },
                    {
                        ""name"": ""openssl"",
                        ""version"": ""3.0.8"",
                        ""maintainers"": [
                            {""name"": ""OpenSSL Team"", ""organization"": ""OpenSSL Project""}
                        ]
                    }
                ],
                ""maintainers"": [
                    {""name"": ""Alice Admin"", ""email"": ""admin@sample-app.com""},
                    {""name"": ""Bob DevOps"", ""email"": ""bob@ops.io""}
                ]
            }";

            Console.WriteLine("--- Example 1: Parse JSON SBOM ---");
            var record = SbomParser.ParseContent(sampleJson);
            Console.WriteLine(SbomParser.FormatSummary(record));
            Console.WriteLine();

            // Show extracted maintainers
            Console.WriteLine("Extracted Maintainers:");
            foreach (var m in record.Maintainers)
            {
                Console.WriteLine($"  - {m.Name} <{m.Email}> ({m.Organization ?? "N/A"})");
            }
            Console.WriteLine();

            // Example 2: Compare two SBOMs for maintainer changes
            var oldRecord = SbomParser.ParseContent(sampleJson);
            
            // Simulate a change - add/remove maintainers
            var newMaintainers = new List<SpdxMaintainer> {
                new SpdxMaintainer { Name = "Alice Admin", Email = "admin@sample-app.com" },
                new SpdxMaintainer { Name = "Charlie New", Email = "charlie@new.io" }
            };

            var newRecord = oldRecord; // In real usage, parse a new SBOM file
            newRecord.Maintainers = newMaintainers;

            Console.WriteLine("--- Example 2: Compare SBOMs for Maintainer Changes ---");
            var diff = oldRecord.CompareTo(newRecord);
            Console.WriteLine($"Summary: {diff.GetSummary()}");
            
            if (diff.AddedMaintainers.Count > 0)
                Console.WriteLine("Added: " + string.Join(", ", diff.AddedMaintainers));
            if (diff.RemovedMaintainers.Count > 0)
                Console.WriteLine("Removed: " + string.Join(", ", diff.RemovedMaintainers));
            
            Console.WriteLine();

            // Example 3: Error handling - invalid JSON
            Console.WriteLine("--- Example 3: Error Handling ---");
            try
            {
                var badJson = "{ not valid json";
                SbomParser.ParseContent(badJson);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Caught expected error: {ex.GetType().Name}: {ex.Message}");
            }

            // Example 4: Edge case - empty SBOM
            Console.WriteLine("\n--- Example 4: Empty/Minimal SBOM ---");
            var minimal = @"{""spdxVersion"": ""2.3""}";
            var minimalRecord = SbomParser.ParseContent(minimal);
            Console.WriteLine($"Parsed minimal SBOM: {minimalRecord.Name ?? "unnamed"}, v{minimalRecord.Version ?? "?"}");

            // Example 5: Batch processing simulation
            Console.WriteLine("\n--- Example 5: Batch Processing Simulation ---");
            var sboms = new[] { sampleJson, minimal };
            
            foreach (var sbom in sboms)
            {
                try
                {
                    var r = SbomParser.ParseContent(sbom);
                    Console.WriteLine($"✓ Parsed: {r.Name ?? "unnamed"}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"✗ Failed: {ex.Message}");
                }
            }

            Console.WriteLine("\n=== Demo Complete ===");
        }
    }
}