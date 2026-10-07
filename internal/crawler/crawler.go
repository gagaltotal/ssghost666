package crawler

import (
	"context"
	"net/url"
	"strings"
	"sync"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// Result is everything the crawl phase produced, handed off to the
// scanner (Targets), the passive checker (Captured) and the terminal
// summary (VisitedCount).
type Result struct {
	Targets      []model.Target
	Captured     []model.CapturedResponse
	VisitedCount int
}

// Options configures one Crawl run.
type Options struct {
	Depth    int
	MaxPages int // hard cap on pages visited by the static/BFS crawl, independent of the global request cap
	InScope  func(string) bool
	OnVisit  func(url string) // progress callback, called once per page fetched
	OnJSFile func(url string) // progress callback for discovered JS files
	OnRobots func(paths int)  // progress callback after robots.txt parsing
}

// Crawl performs a breadth-first crawl of seed up to Options.Depth,
// extracting links/forms from HTML pages and endpoint-like strings from
// linked JS files. It does not brute-force hidden paths (see BruteForce)
// or execute JavaScript (see RenderJS) — those are separate, composable
// phases that main.go merges together.
func Crawl(ctx context.Context, cli *httpclient.Client, lim *ratelimiter.Limiter, seed *url.URL, opt Options) *Result {
	if opt.MaxPages <= 0 {
		opt.MaxPages = 300
	}

	res := &Result{}
	visited := map[string]bool{}
	var visitedMu sync.Mutex

	addTarget := func(t model.Target) {
		res.Targets = append(res.Targets, t)
	}

	// Seed the frontier with the start URL plus anything robots.txt /
	// sitemap.xml reveal, since those often point at pages normal
	// crawling would never link to.
	frontier := []string{seed.String()}
	if robotsPaths, sitemaps := FetchRobots(cli, seed); robotsPaths != nil || sitemaps != nil {
		frontier = append(frontier, robotsPaths...)
		if opt.OnRobots != nil {
			opt.OnRobots(len(robotsPaths))
		}
		for _, sm := range sitemaps {
			frontier = append(frontier, FetchSitemap(cli, sm)...)
		}
	} else {
		// robots.txt didn't exist or had no sitemap directive; still try
		// the conventional /sitemap.xml location, it's extremely common.
		frontier = append(frontier, FetchSitemap(cli, seed.ResolveReference(&url.URL{Path: "/sitemap.xml"}).String())...)
	}

	for d := 0; d <= opt.Depth && len(frontier) > 0; d++ {
		var toVisit []string
		for _, u := range frontier {
			visitedMu.Lock()
			already := visited[u]
			tooMany := len(visited) >= opt.MaxPages
			if !already && !tooMany && opt.InScope(u) && !isStaticAsset(u) {
				visited[u] = true
				toVisit = append(toVisit, u)
			}
			visitedMu.Unlock()
		}
		if len(toVisit) == 0 {
			break
		}

		type pageOut struct {
			page pageExtract
			base *url.URL
		}
		results := make([]pageOut, len(toVisit))
		var wg sync.WaitGroup
		for i, u := range toVisit {
			wg.Add(1)
			go func(i int, rawURL string) {
				defer wg.Done()
				if !lim.Acquire(ctx) {
					return
				}
				ex := cli.Get(rawURL)
				lim.Release()
				if ex.Err != nil || ex.Response == nil {
					return
				}
				if opt.OnVisit != nil {
					opt.OnVisit(rawURL)
				}
				pu, _ := url.Parse(rawURL)
				res.Captured = append(res.Captured, toCaptured(ex, rawURL))

				// Every crawled GET page becomes a scan target, not just
				// ones with a query string: a parameter-less JSON API
				// endpoint (say /api/account) can't be fuzzed for
				// SQLi/XSS, but it absolutely still needs the auth-check
				// phase (CORS, broken access control) run against it —
				// skipping it here would silently exempt exactly the
				// kind of bare API endpoint that check exists to catch.
				if pu != nil {
					addTarget(queryTarget(rawURL))
				}

				ct := ex.Response.Header.Get("Content-Type")
				if strings.Contains(ct, "html") || ct == "" {
					results[i] = pageOut{page: extractPage(pu, ex.Body), base: pu}
				}
			}(i, u)
		}
		wg.Wait()

		var nextLinks []string
		var jsFiles []string
		for _, r := range results {
			if r.base == nil {
				continue
			}
			nextLinks = append(nextLinks, r.page.Links...)
			jsFiles = append(jsFiles, r.page.JSFiles...)
			for _, f := range r.page.Forms {
				addTarget(formToTarget(f))
			}
		}

		// JS files are fetched and mined for endpoints at every depth
		// level; discovered endpoints are folded into the *next* frontier
		// so they get crawled like any other link, and the files
		// themselves are kept as captured evidence (e.g. for the
		// known-vulnerable-library passive check).
		jsEndpoints, jsCaptured := fetchAndMineJS(ctx, cli, lim, jsFiles, opt.OnJSFile)
		nextLinks = append(nextLinks, jsEndpoints...)
		res.Captured = append(res.Captured, jsCaptured...)

		frontier = dedupeInScope(nextLinks, opt.InScope)
	}

	visitedMu.Lock()
	res.VisitedCount = len(visited)
	visitedMu.Unlock()
	return res
}

func dedupeInScope(urls []string, inScope func(string) bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		if seen[u] || !inScope(u) || isStaticAsset(u) {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// fetchAndMineJS fetches every JS file once, mines it for endpoint-like
// strings (extractJSEndpoints), and also returns each file as a
// CapturedResponse — the library-version passive check needs the actual
// file content, not just the endpoints extracted from it, so a JS file
// fetched here is first-class evidence, not a throwaway intermediate.
func fetchAndMineJS(ctx context.Context, cli *httpclient.Client, lim *ratelimiter.Limiter, jsFiles []string, onJS func(string)) ([]string, []model.CapturedResponse) {
	seenJS := map[string]bool{}
	var unique []string
	for _, j := range jsFiles {
		if !seenJS[j] {
			seenJS[j] = true
			unique = append(unique, j)
		}
	}
	var mu sync.Mutex
	var endpoints []string
	var captured []model.CapturedResponse
	var wg sync.WaitGroup
	for _, j := range unique {
		wg.Add(1)
		go func(jsURL string) {
			defer wg.Done()
			if !lim.Acquire(ctx) {
				return
			}
			ex := cli.Get(jsURL)
			lim.Release()
			if ex.Err != nil || ex.Response == nil {
				return
			}
			if onJS != nil {
				onJS(jsURL)
			}
			pu, _ := url.Parse(jsURL)
			found := extractJSEndpoints(pu, ex.Body)
			mu.Lock()
			endpoints = append(endpoints, found...)
			captured = append(captured, toCaptured(ex, jsURL))
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	return endpoints, captured
}

// queryTarget builds a Target from a URL that already carries query
// parameters, e.g. discovered as /search?q=foo&category=books.
func queryTarget(rawURL string) model.Target {
	u, err := url.Parse(rawURL)
	t := model.Target{Method: "GET", URL: rawURL, Source: "crawl"}
	if err != nil {
		return t
	}
	for k, vals := range u.Query() {
		sample := ""
		if len(vals) > 0 {
			sample = vals[0]
		}
		t.Params = append(t.Params, model.Param{Name: k, Location: model.LocQuery, Sample: sample})
	}
	return t
}

func toCaptured(ex *httpclient.Exchange, rawURL string) model.CapturedResponse {
	cr := model.CapturedResponse{
		Method:     "GET",
		URL:        rawURL,
		RequestRaw: ex.RequestRaw,
		ElapsedMS:  ex.ElapsedMS,
	}
	if ex.Response != nil {
		cr.StatusCode = ex.Response.StatusCode
		cr.Headers = map[string][]string(ex.Response.Header)
		cr.Body = ex.Body
		cr.Cookies = ex.Response.Header.Values("Set-Cookie")
	}
	return cr
}
