package scanner

import (
	"context"
	"fmt"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// CheckXSS tests one parameter for reflected XSS in two stages. First,
// HTTP-level reflection: a unique marker is wrapped in a handful of
// common breakout payloads, sent, and the raw response is checked for the
// payload appearing byte-for-byte unescaped — enough on its own to catch
// the overwhelming majority of real reflected-XSS bugs without needing a
// browser.
//
// Second, when browserConfirm is true (the user passed -js-render, so
// spinning up headless Chrome is already something they've opted into)
// and the hit is a GET request reflected through a query or path
// parameter, SSGhost666 goes further: it navigates a real headless
// Chrome tab to the exact URL that triggered the reflection and checks
// whether the page's own JavaScript execution actually set a marker
// variable (see xss_confirm.go) — real proof of exploitability, not just
// a text match, which also means it silently fixes false positives the
// text-match alone could produce (e.g. a payload that reflects inside an
// HTML comment or an already-escaped attribute).
func CheckXSS(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, p model.Param, browserConfirm bool, chromePath string) []model.Finding {
	marker := Marker()
	for _, payload := range xssPayloads(marker) {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		ct := ex.Response.Header.Get("Content-Type")
		if ct != "" && !strings.Contains(ct, "html") && !strings.Contains(ct, "xml") {
			// JSON/plain-text APIs that merely echo input back aren't a
			// browser-rendered XSS sink; skip to avoid a misleading finding.
			continue
		}
		if !strings.Contains(ex.Body, payload) {
			continue
		}

		finding := model.Finding{
			Category:    "Cross-Site Scripting (XSS)",
			Severity:    model.SeverityHigh,
			Title:       "Reflected XSS in parameter \"" + p.Name + "\" (unconfirmed — reflection only)",
			Description: fmt.Sprintf("The payload %q was reflected back in the response body completely unescaped, meaning a browser would execute it. Content-Type was %q.", payload, ct),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   p.Name,
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Marker used: " + marker},
			Remediation: "HTML-escape (or use a templating engine that auto-escapes) any user input rendered into HTML output. Consider a Content-Security-Policy as defense in depth.",
		}

		canConfirm := browserConfirm && t.Method == "GET" && strings.Contains(payload, "window[") &&
			(p.Location == model.LocQuery || p.Location == model.LocPath)
		if canConfirm {
			confirmed, err := confirmXSSInBrowser(ctx, chromePath, ex.Request.URL.String(), marker)
			switch {
			case err != nil:
				finding.Evidence.Notes += " | Browser confirmation attempted but failed: " + err.Error()
			case confirmed:
				finding.Severity = model.SeverityCritical
				finding.Title = "Confirmed XSS in parameter \"" + p.Name + "\" (executed in browser)"
				finding.Description += " Confirmed by actually loading the page in headless Chrome and observing the injected script execute — this is not just a text match."
			default:
				finding.Evidence.Notes += " | Browser confirmation ran but the script did NOT execute (e.g. landed inside a comment or an already-neutralized context) — likely not exploitable as-is, kept here as a lower-confidence signal."
				finding.Severity = model.SeverityMedium
			}
		}

		return []model.Finding{finding}
	}
	return nil
}
