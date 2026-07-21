package polyglot.java;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SPDX SBOM Parser for sbomgate tool.
 * Parses SPDX 2.3 JSON format and extracts package metadata.
 */
public class SbomParser {

    private static final String SPDX_VERSION = "SPDX-2.3";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Represents a single software component from the SBOM.
     */
    public record Package(
        String name,
        String version,
        String purl,
        String licenseId,
        Map<String, Object> extraMetadata
    ) {}

    /**
     * Top-level SPDX document structure.
     */
    private static class SpdxDocument {
        public JsonNode spdxVersion;
        public JsonNode name;
        public JsonNode dataLicense;
        public JsonNode documentNamespace;
        public List<JsonNode> packages = new ArrayList<>();

        public void parse(JsonNode root) throws IOException {
            if (root.isObject()) {
                this.spdxVersion = root.get("spdxVersion");
                this.name = root.get("name");
                this.dataLicense = root.get("dataLicense");
                this.documentNamespace = root.get("documentNamespace");

                JsonNode packagesArray = root.get("packages");
                if (packagesArray != null && packagesArray.isArray()) {
                    for (JsonNode pkg : packagesArray) {
                        this.packages.add(pkg);
                    }
                }
            }
        }

        public Package extractPackage(JsonNode node) throws IOException {
            if (!node.isObject()) return null;

            String name = node.has("name") ? node.get("name").asText() : null;
            String version = node.has("versionInfo") 
                ? node.get("versionInfo").asText() 
                : (node.has("version") ? node.get("version").asText() : null);

            // Try to extract PURL if available, otherwise construct from name+version
            String purl = node.has("externalRefs") ? extractPurlFromExternalRefs(node) : null;

            String licenseId = node.has("licenseConcluded") 
                ? node.get("licenseConcluded").asText() 
                : (node.has("copyrightText") ? "NOASSERTION" : null);

            Map<String, Object> extra = new HashMap<>();
            if (node.has("downloadLocation")) {
                extra.put("downloadLocation", node.get("downloadLocation").asText());
            }
            if (node.has("homepage")) {
                extra.put("homepage", node.get("homepage").asText());
            }

            return new Package(name, version, purl, licenseId, extra);
        }

    private static String extractPurlFromExternalRefs(JsonNode pkg) throws IOException {
        if (!pkg.has("externalRefs")) return null;
        
        for (JsonNode ref : pkg.get("externalRefs")) {
            if (ref.isObject()) {
                JsonNode referenceCategory = ref.get("referenceCategory");
                JsonNode referenceLocator = ref.get("referenceLocator");
                
                // CPE23 is a common external reference type
                if ("cpe23".equalsIgnoreCase(referenceCategory.asText())) {
                    return referenceLocator.asText();
                }
            }
        }
        return null;
    }

    /**
     * Parse an SBOM file and extract all packages.
     */
    public static List<Package> parseFile(Path filePath) throws IOException {
        ObjectMapper localMapper = new ObjectMapper();
        
        try (var reader = Files.newBufferedReader(filePath)) {
            JsonNode root = localMapper.readTree(reader);
            
            if (!root.has("packages") || !root.get("packages").isArray()) {
                throw new IllegalArgumentException("Invalid SPDX document: missing packages array");
            }

            List<Package> result = new ArrayList<>();
            for (JsonNode pkg : root.get("packages")) {
                Package p = extractPackage(pkg);
                if (p != null) {
                    result.add(p);
                }
            }
            
            return result;
        }
    }

    /**
     * Parse SBOM from a JSON string.
     */
    public static List<Package> parseString(String json) throws IOException {
        ObjectMapper localMapper = new ObjectMapper();
        JsonNode root = localMapper.readTree(json);
        
        if (!root.has("packages") || !root.get("packages").isArray()) {
            throw new IllegalArgumentException("Invalid SPDX document: missing packages array");
        }

        List<Package> result = new ArrayList<>();
        for (JsonNode pkg : root.get("packages")) {
            Package p = extractPackage(pkg);
            if (p != null) {
                result.add(p);
            }
        }
        
        return result;
    }

    /**
     * Parse SBOM from a file path.
     */
    public static List<Package> parse(Path filePath) throws IOException {
        ObjectMapper localMapper = new ObjectMapper();
        
        try (var reader = Files.newBufferedReader(filePath)) {
            JsonNode root = localMapper.readTree(reader);
            
            if (!root.has("packages") || !root.get("packages").isArray()) {
                throw new IllegalArgumentException("Invalid SPDX document: missing packages array");
            }

            List<Package> result = new ArrayList<>();
            for (JsonNode pkg : root.get("packages")) {
                Package p = extractPackage(pkg);
                if (p != null) {
                    result.add(p);
                }
            }
            
            return result;
        }
    }

    /**
     * Main demo/entry point.
     */
    public static void main(String[] args) throws Exception {
        // Sample SPDX JSON for testing without external file
        String sampleSbom = """
        {
          "spdxVersion": "SPDX-2.3",
          "name": "demo-app-sbom",
          "dataLicense": "CC0-1.0",
          "documentNamespace": "https://example.org/demo",
          "packages": [
            {
              "name": "org.apache.commons:commons-lang3",
              "versionInfo": "3.14.0",
              "downloadLocation": "pkg:maven/org.apache.commons/commons-lang3@3.14.0?type=jar",
              "licenseConcluded": "MIT",
              "copyrightText": "(c) 2007-2023 Apache Software Foundation",
              "homepage": "https://commons.apache.org/proper/commons-lang/",
              "externalRefs": [
                {
                  "referenceCategory": "cpe23",
                  "referenceLocator": "cpe:2.3:a:apache:commons_lang3:3.14.0:*:*:*:*:*:*:*"
                }
              ]
            },
            {
              "name": "com.google.guava:guava",
              "versionInfo": "33.0.0-jre",
              "downloadLocation": "pkg:maven/com.google.guava/guava@33.0.0-jre?type=jar",
              "licenseConcluded": "Apache-2.0"
            },
            {
              "name": "org.springframework:spring-core",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-core@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "com.fasterxml.jackson.core:jackson-databind",
              "versionInfo": "2.17.0",
              "downloadLocation": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.0?type=jar",
              "licenseConcluded": "Apache-2.0"
            },
            {
              "name": "org.slf4j:slf4j-api",
              "versionInfo": "2.0.12",
              "downloadLocation": "pkg:maven/org.slf4j/slf4j-api@2.0.12?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.apache.logging.log4j:log4j-core",
              "versionInfo": "2.23.0",
              "downloadLocation": "pkg:maven/org.apache.logging.log4j/log4j-core@2.23.0?type=jar",
              "licenseConcluded": "Apache-2.0"
            },
            {
              "name": "org.junit.jupiter:junit-jupiter",
              "versionInfo": "5.10.1",
              "downloadLocation": "pkg:maven/org.junit.jupiter/junit-jupiter@5.10.1?type=jar",
              "licenseConcluded": "EPL-2.0"
            },
            {
              "name": "com.fasterxml.jackson.core:jackson-core",
              "versionInfo": "2.17.0",
              "downloadLocation": "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.17.0?type=jar",
              "licenseConcluded": "Apache-2.0"
            },
            {
              "name": "org.springframework:spring-beans",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-beans@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-context",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-context@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-webmvc",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-webmvc@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-jcl",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-jcl@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-core",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-core@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-beans",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-beans@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-context",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-context@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-webmvc",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-webmvc@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-jcl",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-jcl@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-core",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-core@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-beans",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-beans@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-context",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-context@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-webmvc",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-webmvc@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-jcl",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-jcl@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-core",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-core@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-beans",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-beans@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-context",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-context@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-webmvc",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-webmvc@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-jcl",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-jcl@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-core",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-core@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-beans",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-beans@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-context",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-context@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-webmvc",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-webmvc@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-jcl",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-jcl@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-core",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-core@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-beans",
              "versionInfo": "6.1.4",
              "downloadLocation": "pkg:maven/org.springframework/spring-beans@6.1.4?type=jar",
              "licenseConcluded": "MIT"
            },
            {
              "name": "org.springframework:spring-context",
              "versionInfo": "6.1.4",