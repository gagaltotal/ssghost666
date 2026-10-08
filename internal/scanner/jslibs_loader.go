package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"ssghost666/internal/model"
)

// JSLibDatabase represents an external vulnerability database for JS libraries
type JSLibDatabase struct {
	Version         string            `json:"version"`
	LastUpdated     string            `json:"last_updated"`
	Vulnerabilities []JSLibVulnEntry  `json:"vulnerabilities"`
	LibraryAliases  map[string]string `json:"library_aliases,omitempty"`
	VersionPatterns []JSLibPattern    `json:"version_patterns,omitempty"`
}

// JSLibVulnEntry represents a single vulnerability entry in the database
type JSLibVulnEntry struct {
	Library      string `json:"library"`
	MajorVersion int    `json:"major_version,omitempty"`
	FixedVersion string `json:"fixed_version"`
	CVE          string `json:"cve"`
	Description  string `json:"description"`
	Severity     string `json:"severity"` // "critical", "high", "medium", "low", "info"
}

// JSLibPattern represents a regex pattern to detect library versions
type JSLibPattern struct {
	Library string `json:"library"`
	Pattern string `json:"pattern"`
}

// LoadExternalJSLibDatabase loads an external JS library vulnerability database
func LoadExternalJSLibDatabase(path string) (*JSLibDatabase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read database file: %w", err)
	}

	var db JSLibDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse database JSON: %w", err)
	}

	return &db, nil
}

// MergeExternalDatabase merges an external database with the built-in one
func MergeExternalDatabase(externalDB *JSLibDatabase) error {
	if externalDB == nil {
		return nil
	}

	// Merge vulnerabilities
	for _, vuln := range externalDB.Vulnerabilities {
		sev := parseSeverity(vuln.Severity)
		knownVulnJSLibs = append(knownVulnJSLibs, jsLibVuln{
			Library:      vuln.Library,
			MajorVersion: vuln.MajorVersion,
			FixedVersion: vuln.FixedVersion,
			CVE:          vuln.CVE,
			Description:  vuln.Description,
			Severity:     sev,
		})
	}

	// Merge library aliases
	for alias, canonical := range externalDB.LibraryAliases {
		filenameLibAliases[alias] = canonical
	}

	// Merge version patterns
	for _, pattern := range externalDB.VersionPatterns {
		re, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			continue // Skip invalid patterns
		}
		libVersionPatterns = append(libVersionPatterns, struct {
			Library string
			Pattern *regexp.Regexp
		}{
			Library: pattern.Library,
			Pattern: re,
		})
	}

	return nil
}

// LoadDatabaseFromDirectory loads all JSON database files from a directory
func LoadDatabaseFromDirectory(dirPath string) error {
	if dirPath == "" {
		return nil
	}

	// Check if directory exists
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, skip
		}
		return fmt.Errorf("failed to stat database directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dirPath)
	}

	// Read all JSON files
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read database directory: %w", err)
	}

	loadedCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(dirPath, entry.Name())
		db, err := LoadExternalJSLibDatabase(filePath)
		if err != nil {
			// Log error but continue with other files
			fmt.Fprintf(os.Stderr, "Warning: failed to load %s: %v\n", filePath, err)
			continue
		}

		if err := MergeExternalDatabase(db); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to merge %s: %v\n", filePath, err)
			continue
		}

		loadedCount++
	}

	if loadedCount > 0 {
		fmt.Fprintf(os.Stderr, "Loaded %d external JS library database(s)\n", loadedCount)
	}

	return nil
}

// parseSeverity converts string severity to model.Severity
func parseSeverity(s string) model.Severity {
	switch s {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	case "info":
		return model.SeverityInfo
	default:
		return model.SeverityMedium
	}
}

// ExportBuiltinDatabase exports the built-in database to a JSON file
func ExportBuiltinDatabase(path string) error {
	vulns := make([]JSLibVulnEntry, 0, len(knownVulnJSLibs))
	for _, v := range knownVulnJSLibs {
		vulns = append(vulns, JSLibVulnEntry{
			Library:      v.Library,
			MajorVersion: v.MajorVersion,
			FixedVersion: v.FixedVersion,
			CVE:          v.CVE,
			Description:  v.Description,
			Severity:     severityToString(v.Severity),
		})
	}

	patterns := make([]JSLibPattern, 0, len(libVersionPatterns))
	for _, p := range libVersionPatterns {
		patterns = append(patterns, JSLibPattern{
			Library: p.Library,
			Pattern: p.Pattern.String(),
		})
	}

	db := JSLibDatabase{
		Version:         "1.0",
		LastUpdated:     "2024-01-01",
		Vulnerabilities: vulns,
		LibraryAliases:  filenameLibAliases,
		VersionPatterns: patterns,
	}

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal database: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write database file: %w", err)
	}

	return nil
}

func severityToString(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "critical"
	case model.SeverityHigh:
		return "high"
	case model.SeverityMedium:
		return "medium"
	case model.SeverityLow:
		return "low"
	case model.SeverityInfo:
		return "info"
	default:
		return "medium"
	}
}
