package scanner

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"ssghost666/internal/model"
)

// CheckPassive runs every passive (no-extra-request-required) check over
// responses already captured during crawling/discovery. Security-header
// and server-banner checks are reported once per host (they're normally
// set globally by a server/middleware, so repeating them per page would
// just be noise); error-disclosure and directory-listing checks run on
// every page, since those are genuinely page-specific.
func CheckPassive(captured []model.CapturedResponse) []model.Finding {
	var findings []model.Finding
	headerChecked := map[string]bool{}

	for _, cr := range captured {
		if cr.StatusCode == 0 {
			continue
		}
		host := hostOf(cr.URL)
		if !headerChecked[host] {
			headerChecked[host] = true
			findings = append(findings, checkSecurityHeaders(cr)...)
			findings = append(findings, checkServerBanner(cr)...)
		}
		findings = append(findings, checkVerboseErrors(cr)...)
		findings = append(findings, checkDirectoryListing(cr)...)
		findings = append(findings, checkMixedContent(cr)...)
		findings = append(findings, checkVulnerableJSLibraries(cr)...)
	}
	return findings
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

type headerCheck struct {
	name     string
	severity model.Severity
	why      string
}

var securityHeaders = []headerCheck{
	{"Content-Security-Policy", model.SeverityLow, "CSP is a key defense-in-depth control against XSS and data-injection attacks."},
	{"X-Content-Type-Options", model.SeverityLow, "Without \"nosniff\", browsers may MIME-sniff responses in ways that enable some content-type-confusion attacks."},
	{"X-Frame-Options", model.SeverityLow, "Without this (or an equivalent frame-ancestors CSP directive), the page may be embeddable in a clickjacking iframe."},
	{"Referrer-Policy", model.SeverityInfo, "Without this, the full URL (potentially including sensitive query params) may be leaked via the Referer header on outbound links."},
}

func checkSecurityHeaders(cr model.CapturedResponse) []model.Finding {
	var findings []model.Finding
	for _, h := range securityHeaders {
		if headerVal(cr.Headers, h.name) == "" {
			findings = append(findings, model.Finding{
				Category:    "Passive",
				Severity:    h.severity,
				Title:       "Missing security header: " + h.name,
				Description: h.why,
				URL:         cr.URL,
				Method:      cr.Method,
				Evidence:    model.Evidence{RequestRaw: cr.RequestRaw, Notes: "Response headers seen: " + headerKeys(cr.Headers)},
				Remediation: "Add the " + h.name + " response header with an appropriate policy for this application.",
			})
		}
	}
	if strings.HasPrefix(strings.ToLower(cr.URL), "https://") && headerVal(cr.Headers, "Strict-Transport-Security") == "" {
		findings = append(findings, model.Finding{
			Category:    "Passive",
			Severity:    model.SeverityMedium,
			Title:       "Missing security header: Strict-Transport-Security",
			Description: "Without HSTS, a user who types or follows an http:// link can be downgraded to a plaintext connection before any redirect to HTTPS happens.",
			URL:         cr.URL,
			Method:      cr.Method,
			Evidence:    model.Evidence{RequestRaw: cr.RequestRaw},
			Remediation: "Add Strict-Transport-Security (e.g. \"max-age=31536000; includeSubDomains\") on all HTTPS responses.",
		})
	}
	return findings
}

func checkServerBanner(cr model.CapturedResponse) []model.Finding {
	var findings []model.Finding
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		v := headerVal(cr.Headers, h)
		if v == "" {
			continue
		}
		if regexp.MustCompile(`\d`).MatchString(v) { // only flag when it includes a version number, not a bare generic value
			findings = append(findings, model.Finding{
				Category:    "Passive",
				Severity:    model.SeverityLow,
				Title:       fmt.Sprintf("%s header discloses version info: %q", h, v),
				Description: "Revealing specific software/version information makes it easier for an attacker to look up known vulnerabilities for that exact version.",
				URL:         cr.URL,
				Method:      cr.Method,
				Evidence:    model.Evidence{RequestRaw: cr.RequestRaw, Notes: h + ": " + v},
				Remediation: "Suppress or generalize this header at the server/proxy level (e.g. ServerTokens Prod on Apache, server_tokens off on nginx).",
			})
		}
	}
	return findings
}

var verboseErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Traceback \(most recent call last\)`),
	regexp.MustCompile(`(?i)Fatal error:.*? in .*? on line \d+`),
	regexp.MustCompile(`(?i)Warning:.*? in .*? on line \d+`),
	regexp.MustCompile(`at [\w.$]+\([\w. ]+\.java:\d+\)`),
	regexp.MustCompile(`Exception in thread`),
	regexp.MustCompile(`System\.(Exception|NullReferenceException|Web\.HttpException)`),
	regexp.MustCompile(`(?i)Microsoft \.NET Framework`),
	regexp.MustCompile(`(?i)Unhandled exception`),
	regexp.MustCompile(`(?i)stack trace:`),
	regexp.MustCompile(`panic:.*?goroutine \d+`),
}

func checkVerboseErrors(cr model.CapturedResponse) []model.Finding {
	for _, re := range verboseErrorPatterns {
		if m := re.FindString(cr.Body); m != "" {
			return []model.Finding{{
				Category:    "Passive",
				Severity:    model.SeverityMedium,
				Title:       "Verbose error / stack trace disclosed",
				Description: "The response contains what looks like a raw application stack trace or debug error page, which can reveal file paths, framework/library versions, and internal logic.",
				URL:         cr.URL,
				Method:      cr.Method,
				Evidence:    model.Evidence{RequestRaw: cr.RequestRaw, ResponseRaw: truncate(cr.Body, 4000), Notes: "Matched: " + m},
				Remediation: "Disable debug/verbose error output in production and show a generic error page instead.",
			}}
		}
	}
	return nil
}

func checkDirectoryListing(cr model.CapturedResponse) []model.Finding {
	body := cr.Body
	if strings.Contains(body, "Index of /") && (strings.Contains(body, "Parent Directory") || strings.Contains(body, "[DIR]")) {
		return []model.Finding{{
			Category:    "Passive",
			Severity:    model.SeverityMedium,
			Title:       "Directory listing enabled",
			Description: "The server returned an auto-generated directory index instead of a normal page, exposing the raw file/folder structure.",
			URL:         cr.URL,
			Method:      cr.Method,
			Evidence:    model.Evidence{RequestRaw: cr.RequestRaw, ResponseRaw: truncate(cr.Body, 2000)},
			Remediation: "Disable directory listing/autoindex on the web server for this path.",
		}}
	}
	return nil
}

func checkMixedContent(cr model.CapturedResponse) []model.Finding {
	if !strings.HasPrefix(strings.ToLower(cr.URL), "https://") {
		return nil
	}
	re := regexp.MustCompile(`(?i)(?:src|href)=["']http://[^"'/][^"']*`)
	if m := re.FindString(cr.Body); m != "" {
		return []model.Finding{{
			Category:    "Passive",
			Severity:    model.SeverityLow,
			Title:       "Mixed content: HTTPS page loads a plain-HTTP resource",
			Description: "An HTTPS page references at least one resource over plain HTTP, which browsers may block or warn on, and which can be tampered with in transit.",
			URL:         cr.URL,
			Method:      cr.Method,
			Evidence:    model.Evidence{RequestRaw: cr.RequestRaw, Notes: "Example reference: " + m},
			Remediation: "Serve every subresource (scripts, stylesheets, images, etc.) over HTTPS too.",
		}}
	}
	return nil
}

func headerVal(h map[string][]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func headerKeys(h map[string][]string) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... [truncated]"
}
