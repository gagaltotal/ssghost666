package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

// bq is a literal backtick, used to also match JS template-literal strings
// (`...`) without fighting Go raw-string syntax (a raw string can't
// contain a backtick).
const bq = "`"

var (
	reAbsoluteURL = regexp.MustCompile(`https?://[^\s"'` + bq + `<>\\\)]{4,}`)

	// Quoted strings that look like an API-ish relative path: start with
	// "/", at least one more path segment or a recognizable API prefix,
	// to keep noise down (plain "/" or single words rarely matter).
	reRelativePath = regexp.MustCompile(`["'` + bq + `](/(?:api|v[0-9]+|graphql|rest|internal|admin|service)?[A-Za-z0-9_\-{}./]*)["'` + bq + `?]`)
)

// extractJSEndpoints applies LinkFinder-style heuristics to one JS file's
// source text and returns absolute URLs worth adding to the crawl queue.
// This is static analysis only (no JS execution), so it is cheap and
// works even without -js-render, though it will miss routes that are
// built up dynamically (string concatenation, computed paths) rather than
// appearing as literal strings.
func extractJSEndpoints(base *url.URL, src string) []string {
	seen := map[string]bool{}
	var out []string

	add := func(raw string) {
		abs, ok := normalizeURL(base, raw)
		if !ok || isStaticAsset(abs) {
			return
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}

	for _, m := range reAbsoluteURL.FindAllString(src, -1) {
		add(strings.TrimRight(m, `.,;'"`+bq))
	}
	for _, m := range reRelativePath.FindAllStringSubmatch(src, -1) {
		if len(m) > 1 && len(m[1]) > 1 {
			add(m[1])
		}
	}
	return out
}
