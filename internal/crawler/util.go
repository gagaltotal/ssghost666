package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

// normalizeURL resolves ref against base and filters out schemes/targets
// that are never worth crawling (mailto:, javascript:, data:, in-page
// anchors, etc). It also strips the fragment, since #foo never changes
// what the server returns.
func normalizeURL(base *url.URL, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return "", false
	}
	lower := strings.ToLower(ref)
	for _, bad := range []string{"javascript:", "mailto:", "tel:", "data:", "vbscript:", "about:", "file:"} {
		if strings.HasPrefix(lower, bad) {
			return "", false
		}
	}
	u, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false
	}
	abs.Fragment = ""
	return abs.String(), true
}

// staticAssetExt lists extensions that are essentially never interesting
// as scan targets, used to cut down on crawl/discovery noise.
var staticAssetExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".css": true, ".map": true, ".webp": true, ".avif": true, ".mp4": true,
	".mp3": true, ".pdf.map": true,
}

func isStaticAsset(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	for ext := range staticAssetExt {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// sameHost reports whether candidate is on the same host as root (no
// subdomain/port games unless the user widened -scope).
func sameHost(root, candidate *url.URL) bool {
	return strings.EqualFold(root.Host, candidate.Host)
}

// InScope builds a predicate from the user's -scope/-exclude regexes,
// defaulting scope to "same host as the seed URL" when -scope is empty.
func InScope(seed *url.URL, scopeRe, excludeRe string) (func(string) bool, error) {
	var scopeRx, excludeRx *regexp.Regexp
	var err error
	if scopeRe != "" {
		scopeRx, err = regexp.Compile(scopeRe)
		if err != nil {
			return nil, err
		}
	}
	if excludeRe != "" {
		excludeRx, err = regexp.Compile(excludeRe)
		if err != nil {
			return nil, err
		}
	}
	return func(candidate string) bool {
		if excludeRx != nil && excludeRx.MatchString(candidate) {
			return false
		}
		if scopeRx != nil {
			return scopeRx.MatchString(candidate)
		}
		cu, err := url.Parse(candidate)
		if err != nil {
			return false
		}
		return sameHost(seed, cu)
	}, nil
}
