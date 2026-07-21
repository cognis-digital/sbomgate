#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <algorithm>
#include <regex>
#include <ctime>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

// ============================================================================
// Data Structures
// ============================================================================

struct MaintainerInfo {
    std::string name;
    std::string email;
    std::string url;
    std::time_t last_seen;
    
    bool operator==(const MaintainerInfo& other) const {
        return name == other.name && 
               email == other.email && 
               url == other.url &&
               last_seen == other.last_seen;
    }
};

struct Component {
    std::string name;
    std::string version;
    std::string purl;
    std::string namespace_;
    
    MaintainerInfo maintainer;
    std::vector<std::string> licenses;
    std::map<std::string, std::string> properties;
    
    bool operator<(const Component& other) const {
        if (name != other.name) return name < other.name;
        return version < other.version;
    }
};

struct Dependency {
    std::string component_id;
    std::string relationship_type;  // DEPENDS_ON, REQUIRED_BY, etc.
    std::string target_component_id;
    
    bool operator<(const Dependency& other) const {
        if (component_id != other.component_id) return component_id < other.component_id;
        return relationship_type < other.relationship_type;
    }
};

struct SBOMHeader {
    std::string format_version;
    std::string spec_version;
    std::time_t timestamp;
    std::string tool_name;
    std::string tool_version;
    
    bool operator<(const SBOMHeader& other) const {
        if (format_version != other.format_version) return format_version < other.format_version;
        return spec_version < other.spec_version;
    }
};

struct SBOMDocument {
    SBOMHeader header;
    std::vector<Component> components;
    std::vector<Dependency> dependencies;
    
    bool operator<(const SBOMDocument& other) const {
        if (header != other.header) return header < other.header;
        if (components.size() != other.components.size()) 
            return components.size() < other.components.size();
        
        for (size_t i = 0; i < components.size(); ++i) {
            if (components[i] < other.components[i]) return true;
            if (other.components[i] < components[i]) return false;
        }
        return dependencies.size() < other.dependencies.size();
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string trim(const std::string& str) {
    auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    return result;
}

// Parse ISO 8601 timestamp to time_t
time_t parse_timestamp(const std::string& ts) {
    try {
        auto [year, month, day] = split(ts, '-');
        if (year.empty() || month.empty() || day.empty()) return std::time(nullptr);
        
        int y = std::stoi(year);
        int m = std::stoi(month);
        int d = std::stoi(day);
        
        // Handle timezone offset like +05:30 or -08:00
        auto [h, tz] = split(ts.substr(19), ':');
        int hour = 0;
        if (!h.empty()) {
            hour = std::stoi(h);
            if (tz.size() > 0) {
                char sign = tz[0];
                int offset = std::stoi(tz.substr(1));
                hour += (sign == '+' ? -offset : offset);
            }
        }
        
        struct tm t = {};
        t.tm_year = y - 1900;
        t.tm_mon = m - 1;
        t.tm_mday = d;
        t.tm_hour = hour;
        t.tm_min = 0;
        t.tm_sec = 0;
        t.tm_isdst = 0;
        
        return std::mktime(&t);
    } catch (...) {
        return std::time(nullptr);
    }
}

// ============================================================================
// SPDX Parser Implementation
// ============================================================================

class SPDXParser {
public:
    static SBOMDocument parse(const std::string& content) {
        SBOMDocument doc;
        
        // Parse header
        auto [version, spec] = extract_spdx_version(content);
        if (!version.empty()) {
            doc.header.format_version = version;
            doc.header.spec_version = spec;
        }
        
        // Extract timestamp
        auto ts_match = std::regex_search(content, 
            std::regex(R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"));
        if (ts_match) {
            doc.header.timestamp = parse_timestamp(ts_match[0].str());
        } else {
            doc.header.timestamp = std::time(nullptr);
        }
        
        // Parse components from packages section
        auto pkg_section = extract_spdx_packages(content);
        for (const auto& pkg : pkg_section) {
            Component comp;
            comp.name = pkg["name"];
            comp.version = pkg["version"];
            comp.purl = pkg["purl"].value_or("");
            comp.namespace_ = pkg["namespace"].value_or("");
            
            // Parse maintainer
            if (pkg.contains("maintainer")) {
                auto maint = extract_maintainer(pkg["maintainer"]);
                comp.maintainer.name = maint.first;
                comp.maintainer.email = maint.second;
            }
            
            // Parse licenses
            if (pkg.contains("license")) {
                std::string lic_str = pkg["license"];
                auto lic_parts = split(lic_str, ',');
                for (const auto& part : lic_parts) {
                    comp.licenses.push_back(trim(part));
                }
            }
            
            doc.components.push_back(comp);
        }
        
        // Parse dependencies from depends section
        auto deps_section = extract_spdx_dependencies(content);
        for (const auto& dep : deps_section) {
            Dependency d;
            d.component_id = dep["from"];
            d.relationship_type = "DEPENDS_ON";
            d.target_component_id = dep["to"];
            doc.dependencies.push_back(d);
        }
        
        return doc;
    }

private:
    static std::pair<std::string, std::string> extract_spdx_version(const std::string& content) {
        auto version_match = std::regex_search(content, 
            std::regex(R"(SPDXVersion:\s*(\d+\.\d+))"));
        auto spec_match = std::regex_search(content, 
            std::regex(R"(SPDXSpecVersion:\s*(\d+\.\d+)"));
        
        return {version_match.empty() ? "2.0" : version_match[1].str(),
                spec_match.empty() ? "1.0" : spec_match[1].str()};
    }

    static std::vector<std::map<std::string, std::string>> extract_spdx_packages(const std::string& content) {
        std::vector<std::map<std::string, std::string>> packages;
        
        // Simple regex-based extraction for SPDX 2.0+
        auto pkg_match = std::regex_search(content, 
            std::regex(R"(Name:\s*([^\n]+)\r?\n?Version:\s*(\S+)"));
        
        if (pkg_match) {
            packages.push_back({{"name", pkg_match[1].str()}, {"version", pkg_match[2].str()}});
        } else {
            // Fallback: split by "Name:" occurrences
            auto name_matches = std::regex_find_all(content, 
                std::regex(R"(^Name:\s*(\S+)\r?\n?Version:\s*(\S+)"));
            
            for (const auto& match : name_matches) {
                packages.push_back({{"name", match[1]}, {"version", match[2]}});
            }
        }
        
        return packages;
    }

    static std::pair<std::string, std::string> extract_maintainer(const std::map<std::string, std::string>& pkg) {
        // Try to find maintainer info in various formats
        auto maint_match = std::regex_search(pkg["name"], 
            std::regex(R"(Maintainer:\s*([^,\n]+)\s*(<[^>]+>)?"));
        
        if (maint_match) {
            return {"", ""};  // Simplified extraction
        }
        
        // Default fallback
        return {"Unknown", "unknown@sbomgate.io"};
    }

    static std::vector<std::map<std::string, std::string>> extract_spdx_dependencies(const std::string& content) {
        std::vector<std::map<std::string, std::string>> dependencies;
        
        // Extract from DEPENDS section
        auto dep_match = std::regex_search(content, 
            std::regex(R"(DEPENDS:\s*(\S+)\s+ON\s+(\S+)"));
        
        if (dep_match) {
            while (!dep_match.empty()) {
                dependencies.push_back({{"from", dep_match[1].str()}, {"to", dep_match[2].str()}});
                dep_match = std::regex_search(content, 
                    std::regex(R"(DEPENDS:\s*(\S+)\s+ON\s+(\S+)"));
            }
        }
        
        return dependencies;
    }
};

// ============================================================================
// CycloneDX Parser Implementation
// ============================================================================

class CycloneDXParser {
public:
    static SBOMDocument parse(const std::string& content) {
        SBOMDocument doc;
        
        // Parse header
        auto version_match = std::regex_search(content, 
            std::regex(R"(<bomFormat>\s*(\S+)\s*</bomFormat>"));
        if (version_match) {
            doc.header.format_version = version_match[1].str();
        } else {
            doc.header.format_version = "CycloneDX 1.4";
        }
        
        // Parse timestamp
        auto ts_match = std::regex_search(content, 
            std::regex(R"(<timestamp>\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"));
        if (ts_match) {
            doc.header.timestamp = parse_timestamp(ts_match[1].str());
        } else {
            doc.header.timestamp = std::time(nullptr);
        }
        
        // Parse components
        auto component_matches = std::regex_find_all(content, 
            std::regex(R"(<component>\s*<name>([^<]+)</name>\s*<version>([^<]+)</version>"));
        
        for (const auto& match : component_matches) {
            Component comp;
            comp.name = match[1].str();
            comp.version = match[2].str();
            
            // Try to extract purl
            auto purl_match = std::regex_search(content, 
                std::regex(R"(<purl>\s*([^>]+)"));
            if (purl_match) {
                comp.purl = purl_match[1].str();
            }
            
            // Try to extract maintainer
            auto maint_match = std::regex_search(content, 
                std::regex(R"(<maintainer>\s*<name>([^<]+)</name>"));
            if (maint_match) {
                comp.maintainer.name = maint_match[1].str();
            }
            
            doc.components.push_back(comp);
        }
        
        // Parse dependencies (relationships)
        auto rel_matches = std::regex_find_all(content, 
            std::regex(R"(<relationship>\s*<sourceRef>([^>]+)</sourceRef>\s*<targetRef>([^>]+)</targetRef>"));
        
        for (const auto& match : rel_matches) {
            Dependency d;
            d.component_id = "rel:" + match[1].str();
            d.relationship_type = "DEPENDS_ON";
            d.target_component_id = match[2].str();
            doc.dependencies.push_back(d);
        }
        
        return doc;
    }

private:
};

// ============================================================================
// Unified SBOM Parser Interface
// ============================================================================

class SBOMLoader {
public:
    static std::string read_file(const fs::path& path) {
        if (!fs::exists(path)) {
            throw std::runtime_error("File not found: " + path.string());
        }
        
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + path.string());
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    static SBOMDocument load(const fs::path& path) {
        try {
            auto content = read_file(path);
            
            // Auto-detect format and parse accordingly
            if (content.find("SPDX") != std::string::npos || 
                content.find("Name:") == 0) {
                return SPDXParser::parse(content);
            } else if (content.find("<bomFormat>") != std::string::npos ||
                       content.find("<component>") != std::string::npos) {
                return CycloneDXParser::parse(content);
            } else {
                // Try generic parsing
                return parse_generic(content);
            }
        } catch (const std::exception& e) {
            throw std::runtime_error("Parse error: " + std::string(e.what()));
        }
    }

private:
    static SBOMDocument parse_generic(const std::string& content) {
        SBOMDocument doc;
        
        // Generic header extraction
        auto ts_match = std::regex_search(content, 
            std::regex(R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"));
        if (ts_match) {
            doc.header.timestamp = parse_timestamp(ts_match[1].str());
        } else {
            doc.header.timestamp = std::time(nullptr);
        }
        
        // Generic component extraction
        auto comp_matches = std::regex_find_all(content, 
            std::regex(R"(name\s*[:=]\s*"([^"]+)"[^<]*version\s*[:=]\s*"([^"]+)"));
        
        for (const auto& match : comp_matches) {
            Component comp;
            comp.name = trim(match[1].str());
            comp.version = trim(match[2].str());
            
            // Try to find maintainer
            auto maint_match = std::regex_search(content, 
                std::regex(R"(maintainer\s*[:=]\s*"([^"]+)"));
            if (maint_match) {
                comp.maintainer.name = trim(maint_match[1].str());
            }
            
            doc.components.push_back(comp);
        }
        
        return doc;
    }
};

// ============================================================================
// SBOM Diff Engine
// ============================================================================

class SBOMDiffEngine {
public:
    struct Change {
        enum Type { ADDED, REMOVED, MODIFIED, MOVED };
        std::string component_name;
        std::string old_version;
        std::string new_version;
        Type type;
        
        bool operator<(const Change& other) const {
            if (component_name != other.component_name) 
                return component_name < other.component_name;
            return static_cast<int>(type) < static_cast<int>(other.type);
        }
    };

    static std::vector<Change> diff(const SBOMDocument& old_sbo, 
                                    const SBOMDocument& new_sbo) {
        std::vector<Change> changes;
        
        // Create lookup maps
        auto create_map = [&](const SBOMDocument& doc) -> 
            std::map<std::string, Component> {
            std::map<std::string, Component> map;
            
            for (auto& comp : doc.components) {
                std::string key = comp.name + ":" + comp.version;
                map[key] = comp;
            }
            
            return map;
        };
        
        auto old_map = create_map(old_sbo);
        auto new_map = create_map(new_sbo