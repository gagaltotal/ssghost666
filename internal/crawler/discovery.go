package crawler

import (
	"context"
	_ "embed"
	"encoding/xml"
	"math/rand"
	"net/url"
	"strings"
	"sync"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/ratelimiter"
)

//go:embed wordlist_default.txt
var defaultWordlist string

// DefaultWordlist returns the small built-in path list used when the user
// does not supply -wordlist. It is intentionally compact; point -wordlist
// at a SecLists-style file for a more thorough sweep.
func DefaultWordlist() []string {
	lines := strings.Split(defaultWordlist, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// DiscoveredPath is one hit from wordlist brute forcing.
type DiscoveredPath struct {
	URL        string
	StatusCode int
	Exchange   *httpclient.Exchange
}

// interestingStatus reports whether a brute-force response status is
// worth keeping. 2xx/3xx mean something is there; 401/403 mean something
// is there but access-controlled, which is itself worth surfacing; 5xx
// means something is there and broke — often the most interesting case
// of all, since it's exactly where a verbose stack trace tends to leak
// (the passive checks get a chance at every captured 5xx body too).
func interestingStatus(code int) bool {
	switch {
	case code >= 200 && code < 400:
		return true
	case code == 401 || code == 403:
		return true
	case code >= 500 && code < 600:
		return true
	default:
		return false
	}
}

// calibrateSoft404 probes a couple of almost-certainly-nonexistent paths
// up front to learn what this server's "nothing here" response looks
// like. Many apps/frameworks route unknown paths to a catch-all page
// (soft 404) that still answers 200, which would otherwise make every
// single wordlist entry look like a hit. Returns the (status, body
// length) signatures seen; BruteForce filters any result matching one of
// them exactly.
func calibrateSoft404(cli *httpclient.Client, base *url.URL) map[[2]int]bool {
	sig := map[[2]int]bool{}
	for i := 0; i < 2; i++ {
		probe := base.ResolveReference(&url.URL{Path: "/ssghost666-nonexistent-" + randToken() + "-check"})
		ex := cli.Get(probe.String())
		if ex.Err == nil && ex.Response != nil {
			sig[[2]int{ex.Response.StatusCode, len(ex.Body)}] = true
		}
	}
	return sig
}

func randToken() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// BruteForce fetches base+"/"+word for every entry in words, respecting
// the shared rate limiter, and returns every path that produced an
// "interesting" status code (see interestingStatus) AND doesn't match
// this server's calibrated soft-404 signature. Callers from main.go also
// use each returned Exchange to feed the passive-check phase.
func BruteForce(ctx context.Context, cli *httpclient.Client, lim *ratelimiter.Limiter, base *url.URL, words []string, onProgress func(found DiscoveredPath)) []DiscoveredPath {
	soft404 := calibrateSoft404(cli, base)
	var mu sync.Mutex
	var found []DiscoveredPath
	var wg sync.WaitGroup

	for _, w := range words {
		w := strings.TrimPrefix(w, "/")
		target := base.ResolveReference(&url.URL{Path: "/" + w})
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			if !lim.Acquire(ctx) {
				return
			}
			defer lim.Release()
			ex := cli.Get(target)
			if ex.Err != nil || ex.Response == nil {
				return
			}
			if soft404[[2]int{ex.Response.StatusCode, len(ex.Body)}] {
				return // matches the calibrated "nothing here" response, not a real hit
			}
			if interestingStatus(ex.Response.StatusCode) {
				d := DiscoveredPath{URL: target, StatusCode: ex.Response.StatusCode, Exchange: ex}
				mu.Lock()
				found = append(found, d)
				mu.Unlock()
				if onProgress != nil {
					onProgress(d)
				}
			}
		}(target.String())
	}
	wg.Wait()
	return found
}

// FetchRobots retrieves /robots.txt and extracts every Disallow/Allow path
// and Sitemap URL. Disallowed paths are classic recon value: operators
// often use robots.txt to hide exactly the paths worth checking.
func FetchRobots(cli *httpclient.Client, base *url.URL) (paths []string, sitemaps []string) {
	ex := cli.Get(base.ResolveReference(&url.URL{Path: "/robots.txt"}).String())
	if ex.Err != nil || ex.Response == nil || ex.Response.StatusCode != 200 {
		return nil, nil
	}
	for _, line := range strings.Split(ex.Body, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "disallow:"), strings.HasPrefix(lower, "allow:"):
			p := strings.TrimSpace(line[strings.Index(line, ":")+1:])
			if p != "" && p != "/" {
				if abs, ok := normalizeURL(base, p); ok {
					paths = append(paths, abs)
				}
			}
		case strings.HasPrefix(lower, "sitemap:"):
			s := strings.TrimSpace(line[strings.Index(line, ":")+1:])
			if abs, ok := normalizeURL(base, s); ok {
				sitemaps = append(sitemaps, abs)
			}
		}
	}
	return paths, sitemaps
}

type xmlURLSet struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// FetchSitemap retrieves a sitemap.xml (or sitemap index) and returns the
// page URLs it lists. Nested sitemap-index files are expanded one level
// deep, which covers the vast majority of real-world sitemaps without
// risking unbounded recursion into a huge sitemap tree.
func FetchSitemap(cli *httpclient.Client, sitemapURL string) []string {
	var out []string
	ex := cli.Get(sitemapURL)
	if ex.Err != nil || ex.Response == nil || ex.Response.StatusCode != 200 {
		// Fall back to the conventional location if a discovered/guessed
		// sitemap URL 404s.
		return out
	}
	var set xmlURLSet
	if err := xml.Unmarshal([]byte(ex.Body), &set); err != nil {
		return out
	}
	for _, u := range set.URLs {
		if u.Loc != "" {
			out = append(out, u.Loc)
		}
	}
	for _, s := range set.Sitemaps {
		if s.Loc == "" {
			continue
		}
		ex2 := cli.Get(s.Loc)
		if ex2.Err != nil || ex2.Response == nil || ex2.Response.StatusCode != 200 {
			continue
		}
		var inner xmlURLSet
		if err := xml.Unmarshal([]byte(ex2.Body), &inner); err == nil {
			for _, u := range inner.URLs {
				if u.Loc != "" {
					out = append(out, u.Loc)
				}
			}
		}
	}
	return out
}
