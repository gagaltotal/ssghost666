package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// apiVersionPatterns defines common API versioning patterns
var apiVersionPatterns = []struct {
	pattern     *regexp.Regexp
	replacement string
	description string
}{
	{
		pattern:     regexp.MustCompile(`/v(\d+)/`),
		replacement: "/v%d/",
		description: "Path-based versioning (/v1/, /v2/)",
	},
	{
		pattern:     regexp.MustCompile(`/api/v(\d+)/`),
		replacement: "/api/v%d/",
		description: "API path versioning (/api/v1/, /api/v2/)",
	},
	{
		pattern:     regexp.MustCompile(`/v(\d+)\.(\d+)/`),
		replacement: "/v%d.0/",
		description: "Semantic versioning in path (/v1.0/, /v2.0/)",
	},
}

// versionTestRange defines how many versions to test
const maxVersionsToTest = 5 // Test v0 through v5

// CheckAPIVersioning scans for API versioning issues where old versions
// remain active but unmaintained, potentially containing patched vulnerabilities
func CheckAPIVersioning(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target) []model.Finding {
	var findings []model.Finding

	// Check if this endpoint uses versioning
	versionInfo := detectVersioning(t.URL)
	if versionInfo.currentVersion == 0 {
		// No versioning detected in this URL
		return nil
	}

	// Fetch the baseline (current-version) response once so the version
	// comparison has a stable reference without re-requesting it inside
	// the analysis pass.
	baselineEx := sendWithPayload(ctx, lim, cli, t, "", "")

	// Test other versions of the same endpoint
	testedVersions := testOtherVersions(ctx, lim, cli, t, versionInfo)

	if len(testedVersions) == 0 {
		return nil
	}

	// Analyze version availability and differences
	analysis := analyzeVersionDifferences(versionInfo, baselineEx, testedVersions)

	// Report findings based on analysis

	// 1. Old versions still active
	if len(analysis.olderActiveVersions) > 0 {
		severity := model.SeverityMedium
		if analysis.hasSignificantDifferences {
			severity = model.SeverityHigh
		}

		versionsStr := make([]string, len(analysis.olderActiveVersions))
		for i, v := range analysis.olderActiveVersions {
			versionsStr[i] = fmt.Sprintf("v%d", v)
		}

		desc := fmt.Sprintf("Current endpoint is version v%d, but older versions are still active and accessible: %s. ",
			versionInfo.currentVersion, strings.Join(versionsStr, ", "))

		if analysis.hasSignificantDifferences {
			desc += "Significant differences detected between versions (status codes, response structure, headers), suggesting the older versions may not have security patches applied to newer versions. "
		}

		desc += "Old API versions often contain vulnerabilities that have been patched in newer versions but remain exploitable in the legacy endpoints."

		evidence := fmt.Sprintf("Active versions found: %s. Current version: v%d. Differences: %s",
			strings.Join(versionsStr, ", "), versionInfo.currentVersion, analysis.differencesSummary)

		findings = append(findings, model.Finding{
			Category:    "API Versioning",
			Severity:    severity,
			Title:       fmt.Sprintf("Unmaintained legacy API versions accessible at %s", t.URL),
			Description: desc,
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   "",
			Evidence:    model.Evidence{RequestRaw: testedVersions[0].exchange.RequestRaw, ResponseRaw: testedVersions[0].exchange.ResponseRaw, Notes: evidence},
			Remediation: "Implement API version deprecation policy: 1) Clearly communicate deprecation timeline to API consumers. 2) Return deprecation warnings in response headers (e.g., 'Deprecated: true', 'Sunset: date'). 3) Eventually disable old versions entirely or redirect to current version. 4) If old versions must remain active, backport security patches. 5) Monitor and alert on usage of deprecated versions.",
		})
	}

	// 2. Very old versions (v0, v1) still accessible when current is much higher
	if versionInfo.currentVersion >= 3 && analysis.hasAncientVersions {
		findings = append(findings, model.Finding{
			Category:    "API Versioning",
			Severity:    model.SeverityHigh,
			Title:       fmt.Sprintf("Ancient API versions (v0/v1) still accessible while current is v%d", versionInfo.currentVersion),
			Description: fmt.Sprintf("The current API version is v%d, but very old versions (v0/v1) are still active and responding. These ancient versions are highly unlikely to receive security updates and may contain multiple known vulnerabilities that were fixed in subsequent releases.", versionInfo.currentVersion),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   "",
			Evidence:    model.Evidence{RequestRaw: testedVersions[0].exchange.RequestRaw, ResponseRaw: testedVersions[0].exchange.ResponseRaw, Notes: fmt.Sprintf("Ancient versions detected while current is v%d. Gap: %d versions.", versionInfo.currentVersion, versionInfo.currentVersion-1)},
			Remediation: "Immediately deprecate and disable ancient API versions. These should have been sunset long ago. Set up version sunset policy: versions older than N-2 (current-2) should be disabled within 6-12 months of being superseded.",
		})
	}

	// 3. Inconsistent security headers across versions
	if len(analysis.missingSecurityHeaders) > 0 {
		findings = append(findings, model.Finding{
			Category:    "API Versioning",
			Severity:    model.SeverityMedium,
			Title:       fmt.Sprintf("Inconsistent security headers across API versions at %s", t.URL),
			Description: fmt.Sprintf("Security headers present in v%d are missing in older versions: %s. This indicates older versions may not have the same security controls as the current version.", versionInfo.currentVersion, strings.Join(analysis.missingSecurityHeaders, ", ")),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   "",
			Evidence:    model.Evidence{RequestRaw: testedVersions[0].exchange.RequestRaw, ResponseRaw: testedVersions[0].exchange.ResponseRaw, Notes: fmt.Sprintf("Security headers missing in old versions: %s", strings.Join(analysis.missingSecurityHeaders, ", "))},
			Remediation: "Ensure security controls (headers, authentication, input validation) are consistent across all active API versions, or deprecate old versions that cannot be secured.",
		})
	}

	// 4. No deprecation warnings on old versions
	if len(analysis.olderActiveVersions) > 0 && !analysis.hasDeprecationWarnings {
		findings = append(findings, model.Finding{
			Category:    "API Versioning",
			Severity:    model.SeverityLow,
			Title:       fmt.Sprintf("No deprecation warnings on legacy API versions at %s", t.URL),
			Description: fmt.Sprintf("Older API versions (v%s) are still active but do not return any deprecation warnings (via headers or response body). API consumers have no indication these versions are legacy and should migrate.", strings.Join(versionsToStrings(analysis.olderActiveVersions), ", ")),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   "",
			Evidence:    model.Evidence{RequestRaw: testedVersions[0].exchange.RequestRaw, ResponseRaw: testedVersions[0].exchange.ResponseRaw, Notes: "No Deprecated, Warning, Sunset, or X-API-Warn headers found in legacy versions"},
			Remediation: "Add deprecation warnings to legacy API versions: 1) 'Deprecated: true' header. 2) 'Sunset: YYYY-MM-DD' header with shutdown date. 3) 'Warning: 299 - \"Deprecated API version\"' header. 4) Include deprecation notice in response body or documentation.",
		})
	}

	return findings
}

// versionInfo holds detected API version information
type versionInfo struct {
	currentVersion int
	versionPattern *regexp.Regexp
	replacement    string
	description    string
}

// detectVersioning analyzes URL to detect API versioning scheme
func detectVersioning(url string) versionInfo {
	for _, pattern := range apiVersionPatterns {
		matches := pattern.pattern.FindStringSubmatch(url)
		if len(matches) >= 2 {
			var version int
			fmt.Sscanf(matches[1], "%d", &version)
			return versionInfo{
				currentVersion: version,
				versionPattern: pattern.pattern,
				replacement:    pattern.replacement,
				description:    pattern.description,
			}
		}
	}
	return versionInfo{}
}

// testedVersion holds results of testing one API version
type testedVersion struct {
	version  int
	exchange *httpclient.Exchange
	active   bool
}

// testOtherVersions tests different versions of the same endpoint
func testOtherVersions(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, info versionInfo) []testedVersion {
	var results []testedVersion

	// Test versions 0 through maxVersionsToTest
	for v := 0; v <= maxVersionsToTest; v++ {
		if v == info.currentVersion {
			continue // Skip current version
		}

		// Generate URL for this version
		versionedURL := generateVersionedURL(t.URL, info, v)
		if versionedURL == "" {
			continue
		}

		// Test this version
		versionedTarget := t
		versionedTarget.URL = versionedURL
		ex := sendWithPayload(ctx, lim, cli, versionedTarget, "", "")

		// Check if version is active (not 404/410)
		active := false
		if ex.Err == nil && ex.Response != nil {
			if ex.Response.StatusCode != 404 && ex.Response.StatusCode != 410 && ex.Response.StatusCode != 501 {
				active = true
			}
		}

		results = append(results, testedVersion{
			version:  v,
			exchange: ex,
			active:   active,
		})
	}

	return results
}

// generateVersionedURL replaces the version in URL
func generateVersionedURL(url string, info versionInfo, newVersion int) string {
	return info.versionPattern.ReplaceAllString(url, fmt.Sprintf(info.replacement, newVersion))
}

// versionAnalysis holds analysis results
type versionAnalysis struct {
	olderActiveVersions       []int
	hasAncientVersions        bool
	hasSignificantDifferences bool
	differencesSummary        string
	missingSecurityHeaders    []string
	hasDeprecationWarnings    bool
}

// analyzeVersionDifferences compares different API versions against the
// already-fetched current-version baseline.
func analyzeVersionDifferences(currentInfo versionInfo, baselineEx *httpclient.Exchange, tested []testedVersion) versionAnalysis {
	analysis := versionAnalysis{}

	var differences []string

	for _, tv := range tested {
		if !tv.active {
			continue
		}

		// Check if this is an older version
		if tv.version < currentInfo.currentVersion {
			analysis.olderActiveVersions = append(analysis.olderActiveVersions, tv.version)

			// Check if ancient (v0, v1)
			if tv.version <= 1 {
				analysis.hasAncientVersions = true
			}
		}

		if tv.exchange == nil || tv.exchange.Response == nil {
			continue
		}

		// Compare with baseline
		if baselineEx != nil && baselineEx.Response != nil {
			// Status code differences
			if tv.exchange.Response.StatusCode != baselineEx.Response.StatusCode {
				differences = append(differences, fmt.Sprintf("v%d has status %d (current: %d)", tv.version, tv.exchange.Response.StatusCode, baselineEx.Response.StatusCode))
				analysis.hasSignificantDifferences = true
			}

			// Response length differences (might indicate different behavior)
			if abs(len(tv.exchange.Body)-len(baselineEx.Body)) > 100 {
				differences = append(differences, fmt.Sprintf("v%d has significantly different response size", tv.version))
				analysis.hasSignificantDifferences = true
			}

			// Security headers missing in old version
			securityHeaders := []string{"X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy"}
			for _, header := range securityHeaders {
				if baselineEx.Response.Header.Get(header) != "" && tv.exchange.Response.Header.Get(header) == "" {
					if !contains(analysis.missingSecurityHeaders, header) {
						analysis.missingSecurityHeaders = append(analysis.missingSecurityHeaders, header)
					}
				}
			}
		}

		// Check for deprecation warnings
		deprecationHeaders := []string{"Deprecated", "Sunset", "Warning", "X-API-Warn", "X-API-Deprecated"}
		for _, header := range deprecationHeaders {
			if tv.exchange.Response.Header.Get(header) != "" {
				analysis.hasDeprecationWarnings = true
				break
			}
		}
		if strings.Contains(strings.ToLower(tv.exchange.Body), "deprecated") {
			analysis.hasDeprecationWarnings = true
		}
	}

	analysis.differencesSummary = strings.Join(differences, "; ")
	if analysis.differencesSummary == "" {
		analysis.differencesSummary = "No significant differences detected"
	}

	return analysis
}

// Helper functions

func versionsToStrings(versions []int) []string {
	result := make([]string, len(versions))
	for i, v := range versions {
		result[i] = fmt.Sprintf("%d", v)
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
