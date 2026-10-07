package scanner

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"ssghost666/internal/model"
)

// jsLibVuln is one known-vulnerable version range for a client-side JS
// library. MajorVersion, when non-zero, restricts the match to that major
// line only — needed for libraries like Bootstrap that run two
// independently-numbered major lines (3.x and 4.x) with different fixed
// versions for the same issue. The entries below are deliberately
// conservative, well-documented, long-public CVEs (the same class of
// entries any JS-library vulnerability scanner — retire.js, Mozilla
// Observatory, npm audit — ships) rather than anything obscure, and the
// version comparison is a simple major.minor.patch check, not a full
// semver range engine, so treat a hit as "worth checking", not a
// courtroom-grade verdict.
type jsLibVuln struct {
	Library      string
	MajorVersion int // 0 = no constraint
	FixedVersion string
	CVE          string
	Description  string
	Severity     model.Severity
}

var knownVulnJSLibs = []jsLibVuln{
	{"jQuery", 0, "1.9.0", "CVE-2012-6708",
		"jQuery's selector/HTML handling before 1.9.0 can confuse a selector string for HTML, enabling XSS.", model.SeverityMedium},
	{"jQuery", 0, "3.4.0", "CVE-2019-11358",
		"jQuery before 3.4.0: $.extend(true, {}, ...) can be tricked into polluting Object.prototype.", model.SeverityMedium},
	{"jQuery", 0, "3.5.0", "CVE-2020-11022, CVE-2020-11023",
		"jQuery before 3.5.0: passing HTML from an untrusted source to .html()/.append()/etc. (even after sanitizing) may execute attacker-controlled script.", model.SeverityHigh},
	{"jQuery UI", 0, "1.13.0", "CVE-2021-41182, CVE-2021-41183, CVE-2021-41184",
		"jQuery UI before 1.13.0: XSS in the Datepicker, *option(), and checkboxradio/controlgroup widgets via crafted values.", model.SeverityMedium},
	{"Bootstrap", 3, "3.4.1", "CVE-2019-8331 (and earlier CVE-2018-14040/14041/14042, CVE-2018-20676/20677, CVE-2016-10735)",
		"Bootstrap 3.x before 3.4.1: multiple XSS issues via data-template/data-target/data-viewport/data-container attributes on tooltip/popover/affix/collapse components.", model.SeverityMedium},
	{"Bootstrap", 4, "4.3.1", "CVE-2019-8331",
		"Bootstrap 4.x before 4.3.1: XSS in the tooltip/popover data-template attribute.", model.SeverityMedium},
	{"Lodash", 0, "4.17.12", "CVE-2019-10744",
		"lodash before 4.17.12: defaultsDeep can be tricked into polluting Object.prototype.", model.SeverityHigh},
	{"Lodash", 0, "4.17.19", "CVE-2020-8203",
		"lodash before 4.17.19: pick/set/setWith/update/updateWith/zipObjectDeep can be tricked into polluting Object.prototype via user-supplied property identifiers.", model.SeverityHigh},
	{"Lodash", 0, "4.17.21", "CVE-2021-23337",
		"lodash before 4.17.21: the template function allows command injection via a crafted template option.", model.SeverityHigh},
	{"Moment.js", 0, "2.29.4", "CVE-2022-31129",
		"moment.js before 2.29.4: parsing a long, crafted date string (RFC2822 path) has quadratic complexity — a ReDoS if attacker input reaches it.", model.SeverityMedium},
	{"Handlebars", 0, "4.3.0", "CVE-2019-19919",
		"Handlebars before 4.3.0: compiling an attacker-influenced template can pollute Object.prototype, up to remote code execution.", model.SeverityHigh},
	{"Underscore.js", 0, "1.12.1", "CVE-2021-23358",
		"Underscore.js before 1.12.1: the template function allows arbitrary code injection via a crafted variable-name option.", model.SeverityHigh},
	{"AngularJS", 0, "", "N/A — end of life",
		"AngularJS (1.x) reached end of life in January 2022 and no longer receives security patches, regardless of version.", model.SeverityLow},
}

// libVersionPatterns match a library's conventional version-banner text
// (the comment header most of these libraries ship at the top of both
// their minified and unminified builds), each with exactly one capture
// group for the version number.
var libVersionPatterns = []struct {
	Library string
	Pattern *regexp.Regexp
}{
	{"jQuery UI", regexp.MustCompile(`jQuery\s*UI\s*[-–]?\s*v?(\d+\.\d+\.\d+)`)},
	{"jQuery", regexp.MustCompile(`jQuery\s*(?:JavaScript Library)?\s*v?(\d+\.\d+\.\d+)`)},
	{"Bootstrap", regexp.MustCompile(`Bootstrap\s*v?(\d+\.\d+\.\d+)`)},
	{"Lodash", regexp.MustCompile(`[Ll]odash\s*(?:lodash\.com[^\n]{0,15})?\s*v?\(?(\d+\.\d+\.\d+)`)},
	{"Moment.js", regexp.MustCompile(`[Mm]oment\.js\s*v?(\d+\.\d+\.\d+)`)},
	{"Handlebars", regexp.MustCompile(`[Hh]andlebars(?:\.js)?\s*v?(\d+\.\d+\.\d+)`)},
	{"Underscore.js", regexp.MustCompile(`[Uu]nderscore\.js\s*(\d+\.\d+\.\d+)`)},
	{"AngularJS", regexp.MustCompile(`AngularJS\s*v?(\d+\.\d+\.\d+)`)},
}

// filenameLibAliases maps the lowercase name a library commonly appears
// as in a URL/filename (jquery-3.4.1.min.js, bootstrap.bundle.min.js) to
// its canonical display name used in knownVulnJSLibs.
var filenameLibAliases = map[string]string{
	"jquery-ui": "jQuery UI", "jqueryui": "jQuery UI",
	"jquery": "jQuery", "jq": "jQuery",
	"bootstrap": "Bootstrap",
	"lodash":    "Lodash", "lodash.min": "Lodash",
	"moment":     "Moment.js",
	"handlebars": "Handlebars",
	"underscore": "Underscore.js",
	"angular":    "AngularJS",
}

var filenameVersionPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9.]*?)[-.]v?(\d+\.\d+\.\d+)(?:\.min)?\.js$`)

type detectedLib struct {
	Library string
	Version string
}

// detectJSLibraries scans one JS file's URL and content for a
// library+version signature, trying the content banner first (more
// reliable — survives being served from a different filename than
// upstream ships) and falling back to the filename pattern.
func detectJSLibraries(fileURL, content string) []detectedLib {
	var out []detectedLib
	seen := map[string]bool{}

	// Only look at the first slice of the file: version banners are
	// always at the very top, and skipping the rest avoids an expensive
	// regex sweep over a multi-megabyte bundle.
	head := content
	if len(head) > 2000 {
		head = head[:2000]
	}
	for _, lp := range libVersionPatterns {
		if m := lp.Pattern.FindStringSubmatch(head); m != nil {
			key := lp.Library + "@" + m[1]
			if !seen[key] {
				seen[key] = true
				out = append(out, detectedLib{Library: lp.Library, Version: m[1]})
			}
		}
	}

	base := strings.ToLower(path.Base(fileURL))
	if m := filenameVersionPattern.FindStringSubmatch(base); m != nil {
		name := strings.TrimSuffix(strings.ToLower(m[1]), ".min")
		if canonical, ok := filenameLibAliases[name]; ok {
			key := canonical + "@" + m[2]
			if !seen[key] {
				seen[key] = true
				out = append(out, detectedLib{Library: canonical, Version: m[2]})
			}
		}
	}
	return out
}

// checkVulnerableJSLibraries is the passive check entry point: run over
// every JS file captured during crawling, it flags any detected
// library+version that matches a known-vulnerable range. AngularJS's
// entry has no FixedVersion (it's simply EOL), so it always matches once
// any version is detected.
func checkVulnerableJSLibraries(cr model.CapturedResponse) []model.Finding {
	if !strings.HasSuffix(strings.ToLower(strings.SplitN(cr.URL, "?", 2)[0]), ".js") &&
		!strings.Contains(headerVal(cr.Headers, "Content-Type"), "javascript") {
		return nil
	}
	libs := detectJSLibraries(cr.URL, cr.Body)
	var findings []model.Finding
	for _, lib := range libs {
		major := majorOf(lib.Version)
		for _, v := range knownVulnJSLibs {
			if v.Library != lib.Library {
				continue
			}
			if v.MajorVersion != 0 && v.MajorVersion != major {
				continue
			}
			vulnerable := v.FixedVersion == "" || versionLess(lib.Version, v.FixedVersion)
			if !vulnerable {
				continue
			}
			title := fmt.Sprintf("%s %s may be vulnerable (%s)", lib.Library, lib.Version, v.CVE)
			if v.FixedVersion == "" {
				title = fmt.Sprintf("%s %s is unmaintained/end-of-life", lib.Library, lib.Version)
			}
			findings = append(findings, model.Finding{
				Category:    "Passive",
				Severity:    v.Severity,
				Title:       title,
				Description: v.Description,
				URL:         cr.URL,
				Method:      cr.Method,
				Evidence:    model.Evidence{RequestRaw: cr.RequestRaw, Notes: fmt.Sprintf("Detected %s version %s; fixed in %s.", lib.Library, lib.Version, nonEmpty(v.FixedVersion, "N/A"))},
				Remediation: upgradeAdvice(lib.Library, v.FixedVersion),
			})
		}
	}
	return findings
}

func upgradeAdvice(lib, fixed string) string {
	if fixed == "" {
		return fmt.Sprintf("Migrate off %s — it no longer receives security fixes regardless of version.", lib)
	}
	return fmt.Sprintf("Upgrade %s to %s or later.", lib, fixed)
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// versionLess reports whether a < b for plain major.minor.patch version
// strings (no pre-release/build-metadata handling — real-world library
// version banners essentially never carry those).
func versionLess(a, b string) bool {
	pa, pb := parseVersion(a), parseVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func majorOf(v string) int {
	return parseVersion(v)[0]
}

func parseVersion(v string) [3]int {
	var out [3]int
	parts := strings.SplitN(v, ".", 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}
