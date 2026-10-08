// SSGhost666 is a CLI web security scanner focused on evidence-gathering
// against web applications you own or are explicitly authorized to test.
// See README.md for usage. Run `ssghost666 -h` for the full flag list.
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ssghost666/internal/crawler"
	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/openapi"
	"ssghost666/internal/options"
	"ssghost666/internal/ratelimiter"
	"ssghost666/internal/report"
	"ssghost666/internal/scanner"
)

func main() {
	cfg := options.Parse(os.Args[1:])
	term := report.NewTerminal(cfg.NoColor)
	start := time.Now()

	seed, err := url.Parse(cfg.TargetURL)
	if err != nil || (seed.Scheme != "http" && seed.Scheme != "https") {
		fmt.Fprintf(os.Stderr, "error: -url must be a full http(s) URL, e.g. https://app.example.com\n")
		os.Exit(2)
	}

	checks := scanner.ParseChecks(cfg.Checks)
	term.Banner(options.Banner(), cfg.TargetURL, cfg.Depth, checksLabel(checks))
	fmt.Fprintln(os.Stderr, "Only scan applications you own or are explicitly authorized to test.")

	// Load external JS library vulnerability databases if specified
	if cfg.JSLibsDB != "" {
		if err := scanner.LoadDatabaseFromDirectory(cfg.JSLibsDB); err != nil {
			term.Warn("Failed to load JS library database from %s: %v", cfg.JSLibsDB, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cli, err := httpclient.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	inScope, err := crawler.InScope(seed, cfg.Scope, cfg.Exclude)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: invalid -scope/-exclude regex:", err)
		os.Exit(1)
	}

	lim := ratelimiter.New(cfg.RatePerSec, cfg.Concurrency, cfg.MaxRequests)
	lim.OnLimitReached(func() {
		term.Warn("reached -max-requests (%d); stopping further requests. Raise it with -max-requests if you need a larger scan.", cfg.MaxRequests)
	})

	var allTargets []model.Target
	var allCaptured []model.CapturedResponse

	// --- Phase 1: crawl --------------------------------------------------
	term.Section("crawling")
	cres := crawler.Crawl(ctx, cli, lim, seed, crawler.Options{
		Depth:   cfg.Depth,
		InScope: inScope,
		OnVisit: func(u string) {
			if cfg.Verbose {
				term.Info("visited %s", u)
			}
		},
		OnJSFile: func(u string) {
			if cfg.Verbose {
				term.Info("mined JS file %s", u)
			}
		},
		OnRobots: func(n int) {
			if n > 0 {
				term.Info("robots.txt revealed %d path(s)", n)
			}
		},
	})
	allTargets = append(allTargets, cres.Targets...)
	allCaptured = append(allCaptured, cres.Captured...)
	term.Info("crawled %d page(s), found %d scannable target(s) so far", cres.VisitedCount, len(allTargets))

	// --- Phase 1b: headless-Chrome JS-route discovery ---------------------
	if cfg.JSRender {
		term.Section("js rendering")
		renderURLs := pickRenderCandidates(seed.String(), allCaptured, 6)
		term.Info("rendering %d page(s) with headless Chrome (this can take a while)...", len(renderURLs))
		links, jsTargets := crawler.RenderMany(ctx, cfg.ChromePath, renderURLs, 4*time.Second, func(pageURL string, newLinks, newRequests int, rerr error) {
			if rerr != nil {
				term.Warn("js-render %s: %v", pageURL, rerr)
				return
			}
			term.Info("%s -> %d link(s), %d JS request(s)", pageURL, newLinks, newRequests)
		})
		allTargets = append(allTargets, jsTargets...)
		for _, l := range dedupeStrings(links) {
			if u, err := url.Parse(l); err == nil && u.RawQuery != "" && inScope(l) {
				allTargets = append(allTargets, queryTargetPublic(l))
			}
		}
		term.Info("js-render added %d request-derived target(s)", len(jsTargets))
	}

	// --- Phase 1c: wordlist-based hidden endpoint discovery ----------------
	if !cfg.NoDiscover {
		term.Section("discovery")
		words := crawler.DefaultWordlist()
		if cfg.Wordlist != "" {
			if custom, err := loadWordlist(cfg.Wordlist); err != nil {
				term.Warn("couldn't read -wordlist %s: %v (using built-in list)", cfg.Wordlist, err)
			} else {
				words = custom
			}
		}
		term.Info("probing %d candidate path(s)...", len(words))
		found := crawler.BruteForce(ctx, cli, lim, seed, words, func(d crawler.DiscoveredPath) {
			term.Info("[%d] %s", d.StatusCode, d.URL)
			if d.Exchange != nil && d.Exchange.Response != nil {
				allCaptured = append(allCaptured, model.CapturedResponse{
					Method: "GET", URL: d.URL, StatusCode: d.StatusCode,
					Headers: map[string][]string(d.Exchange.Response.Header), Body: d.Exchange.Body,
					RequestRaw: d.Exchange.RequestRaw, Cookies: d.Exchange.Response.Header.Values("Set-Cookie"),
				})
				// A hidden endpoint found this way deserves the
				// auth-check phase (CORS, broken access control) too —
				// finding a stray /admin or /internal-api and then
				// never checking whether it enforces auth would defeat
				// half the point of discovering it.
				if d.StatusCode >= 200 && d.StatusCode < 300 {
					allTargets = append(allTargets, queryTargetPublic(d.URL))
				}
			}
		})
		term.Info("discovery found %d interesting path(s)", len(found))
	}

	// --- Phase 1d: OpenAPI / Swagger import --------------------------------
	if cfg.OpenAPIPath != "" {
		term.Section("openapi import")
		apiTargets, err := openapi.Load(cli, cfg.OpenAPIPath, cfg.TargetURL)
		if err != nil {
			term.Warn("OpenAPI import failed: %v", err)
		} else {
			allTargets = append(allTargets, apiTargets...)
			term.Info("imported %d operation(s) from %s", len(apiTargets), cfg.OpenAPIPath)
		}
	}

	// --- Phase 2: scan -----------------------------------------------------
	term.Section("scanning")
	hasAuth := cfg.Cookie != "" || cfg.Bearer != ""

	var jwtFindings []model.Finding
	if checks.Auth && cfg.Bearer != "" {
		jwtFindings = scanner.DecodeJWT(cfg.Bearer)
		for i := range jwtFindings {
			jwtFindings[i].URL = cfg.TargetURL
			jwtFindings[i].ID = fmt.Sprintf("SSG-JWT-%d", i+1)
			term.FindingLive(jwtFindings[i])
		}
	}

	// Start SSRF listener if SSRF checks are enabled and listener is not disabled
	var ssrfListener *scanner.SSRFListener
	if checks.SSRF && cfg.EnableSSRFListener {
		listener, err := scanner.NewSSRFListener(0) // Port 0 = auto-select
		if err == nil {
			addr, err := listener.Start()
			if err == nil {
				ssrfListener = listener
				term.Info("SSRF callback listener started at http://%s", addr)
				defer func() {
					if err := listener.Stop(); err != nil {
						term.Warn("failed to stop SSRF listener: %v", err)
					}
				}()
			} else {
				term.Warn("failed to start SSRF listener: %v (using external callback only)", err)
			}
		} else {
			term.Warn("failed to create SSRF listener: %v (using external callback only)", err)
		}
	}

	findings := scanner.Run(ctx, cli, lim, allTargets, allCaptured, scanner.Options{
		Checks:         checks,
		HasAuth:        hasAuth,
		SSRFCallback:   cfg.SSRFCallback,
		SSRFListener:   ssrfListener,
		BrowserConfirm: cfg.JSRender,
		DOMXSSCheck:    cfg.DOMXSSCheck,
		ChromePath:     cfg.ChromePath,
		OnFinding:      func(f model.Finding) { term.FindingLive(f) },
		OnProgress: func(s string) {
			if cfg.Verbose {
				term.Info("%s", s)
			}
		},
	})
	findings = append(jwtFindings, findings...)

	// --- Summary + report ----------------------------------------------------
	term.Summary(findings, cres.VisitedCount, int(lim.Count()))

	if cfg.OutReport != "" {
		err := report.WriteFile(findings, report.Meta{
			Target:        cfg.TargetURL,
			Duration:      time.Since(start),
			VisitedPages:  cres.VisitedCount,
			TotalRequests: int(lim.Count()),
			ChecksRun:     checksLabel(checks),
			Redact:        !cfg.NoRedact,
		}, cfg.OutReport)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error writing report:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\nHTML report written to %s\n", cfg.OutReport)
	}
}

func checksLabel(e scanner.Enabled) string {
	if e.SQLi && e.XSS && e.CmdI && e.SSRF && e.Auth && e.Passive {
		return "all"
	}
	var on []string
	for name, v := range map[string]bool{"sqli": e.SQLi, "xss": e.XSS, "cmdi": e.CmdI, "ssrf": e.SSRF, "auth": e.Auth, "passive": e.Passive} {
		if v {
			on = append(on, name)
		}
	}
	if len(on) == 0 {
		return "none"
	}
	return strings.Join(on, ",")
}

func pickRenderCandidates(seed string, captured []model.CapturedResponse, max int) []string {
	out := []string{seed}
	seen := map[string]bool{seed: true}
	for _, c := range captured {
		if len(out) >= max {
			break
		}
		if !seen[c.URL] && c.StatusCode >= 200 && c.StatusCode < 300 {
			seen[c.URL] = true
			out = append(out, c.URL)
		}
	}
	return out
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func loadWordlist(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

// queryTargetPublic builds a GET target from a URL that carries a query
// string (used for query-bearing links surfaced by JS rendering). It
// mirrors crawler's internal queryTarget but lives here since that one is
// unexported.
func queryTargetPublic(rawURL string) model.Target {
	u, err := url.Parse(rawURL)
	t := model.Target{Method: "GET", URL: rawURL, Source: "dynamic"}
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
