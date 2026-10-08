package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// Enabled is which check categories a run should execute, derived from
// the -checks flag.
type Enabled struct {
	SQLi, XSS, CmdI, SSRF, Auth, Passive bool
}

// ParseChecks turns "all" or a comma list like "sqli,xss,passive" into an
// Enabled set.
func ParseChecks(spec string) Enabled {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" || spec == "all" {
		return Enabled{true, true, true, true, true, true}
	}
	var e Enabled
	for _, c := range strings.Split(spec, ",") {
		switch strings.TrimSpace(c) {
		case "sqli":
			e.SQLi = true
		case "xss":
			e.XSS = true
		case "cmdi":
			e.CmdI = true
		case "ssrf":
			e.SSRF = true
		case "auth":
			e.Auth = true
		case "passive":
			e.Passive = true
		}
	}
	return e
}

// Options configures one Run.
type Options struct {
	Checks         Enabled
	HasAuth        bool // true if -cookie or -bearer was set, enables the broken-access-control check
	SSRFCallback   string
	SSRFListener   *SSRFListener       // local callback listener for in-band SSRF detection
	BrowserConfirm bool                // true if -js-render was set: attempt real-browser XSS execution confirmation
	DOMXSSCheck    bool                // true to enable DOM-based XSS detection
	ChromePath     string              // optional explicit Chrome/Chromium binary path
	OnFinding      func(model.Finding) // progress callback, called as each finding is confirmed
	OnProgress     func(string)
}

// Run actively tests every target's parameters (plus a handful of
// target-level auth checks) and runs passive checks over every captured
// response, with the given concurrency/rate limit. It returns a
// deduplicated, worst-first-sorted finding list.
func Run(ctx context.Context, cli *httpclient.Client, lim *ratelimiter.Limiter, targets []model.Target, captured []model.CapturedResponse, opt Options) []model.Finding {
	targets = dedupeTargets(targets)

	var mu sync.Mutex
	var findings []model.Finding
	dedup := map[string]bool{}

	add := func(fs []model.Finding) {
		if len(fs) == 0 {
			return
		}
		mu.Lock()
		for _, f := range fs {
			f.Timestamp = time.Now()
			key := f.Category + "|" + f.Method + " " + f.URL + "|" + f.Parameter + "|" + f.Title
			if dedup[key] {
				continue
			}
			dedup[key] = true
			if f.ID == "" {
				f.ID = fmt.Sprintf("SSG-%04d", len(findings)+1)
			}
			findings = append(findings, f)
			if opt.OnFinding != nil {
				opt.OnFinding(f)
			}
		}
		mu.Unlock()
	}

	if opt.Checks.Passive {
		add(CheckPassive(captured))
	}

	// Every actual HTTP call made below — baseline fetches, each fuzz
	// payload, CORS probes, the unauthenticated access-control re-request
	// — goes through sendWithPayload/CheckCORS/CheckBrokenAccessControl,
	// which each acquire the shared limiter around the single request
	// they send. That means -rate and -concurrency are enforced at the
	// wire level regardless of how many checks happen to be in flight, so
	// it's safe to just fire off all this work as goroutines below and
	// let the limiter do the actual pacing.
	var wg sync.WaitGroup
	for _, t := range targets {
		t := t
		baseline := sendWithPayload(ctx, lim, cli, t, "", "")
		if opt.OnProgress != nil {
			opt.OnProgress(fmt.Sprintf("baseline %s %s -> %v", t.Method, t.URL, statusOf(baseline)))
		}

		if opt.Checks.Auth {
			wg.Add(1)
			go func() {
				defer wg.Done()
				add(CheckCORS(ctx, lim, cli, t))
				if opt.HasAuth {
					add(CheckBrokenAccessControl(ctx, lim, cli, t, baseline))
				}
			}()
		}

		for _, p := range fuzzableParams(t) {
			p := p
			if opt.Checks.SQLi {
				wg.Add(1)
				go func() {
					defer wg.Done()
					add(CheckSQLi(ctx, lim, cli, baseline, t, p))
				}()
			}
			if opt.Checks.XSS {
				wg.Add(1)
				go func() {
					defer wg.Done()
					add(CheckXSS(ctx, lim, cli, t, p, opt.BrowserConfirm, opt.ChromePath))
				}()
			}
			if opt.Checks.CmdI {
				wg.Add(1)
				go func() {
					defer wg.Done()
					add(CheckCmdInjection(ctx, lim, cli, baseline, t, p))
				}()
			}
			if opt.Checks.SSRF && looksLikeURLParam(p.Name) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					add(CheckSSRF(ctx, lim, cli, t, p, opt.SSRFCallback, opt.SSRFListener))
				}()
			}
		}
	}
	wg.Wait()

	if opt.Checks.Auth {
		add(CheckCookieFlags(captured))
	}

	// DOM-based XSS check on unique URLs
	if opt.Checks.XSS && opt.DOMXSSCheck {
		testedURLs := make(map[string]bool)
		for _, t := range targets {
			// Only test each unique URL once (without query params)
			baseURL := strings.Split(t.URL, "?")[0]
			if testedURLs[baseURL] {
				continue
			}
			testedURLs[baseURL] = true

			if opt.OnProgress != nil {
				opt.OnProgress(fmt.Sprintf("checking DOM XSS: %s", baseURL))
			}
			add(CheckDOMXSS(ctx, baseURL, opt.ChromePath))
		}
	}

	sortFindings(findings)
	return findings
}

func statusOf(ex *httpclient.Exchange) string {
	if ex == nil || ex.Response == nil {
		if ex != nil && ex.Err != nil {
			return "error: " + ex.Err.Error()
		}
		return "no response"
	}
	return ex.Response.Status
}

func dedupeTargets(targets []model.Target) []model.Target {
	seen := map[string]bool{}
	var out []model.Target
	for _, t := range targets {
		k := t.Key()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, t)
	}
	return out
}

func sortFindings(f []model.Finding) {
	// simple insertion sort: finding counts here are small (tens to low
	// hundreds), so this stays fast while avoiding another import.
	for i := 1; i < len(f); i++ {
		j := i
		for j > 0 && f[j-1].Severity.Rank() > f[j].Severity.Rank() {
			f[j-1], f[j] = f[j], f[j-1]
			j--
		}
	}
}
