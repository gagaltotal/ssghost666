package scanner

import (
	"context"
	"fmt"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// CheckSQLi tests one parameter for SQL injection using three techniques,
// tried in order from fastest/cheapest to slowest, each only attempted if
// the previous one found nothing for this parameter:
//
//  1. Error-based: send syntax-breaking strings and look for a leaked
//     database error signature that wasn't present in the baseline
//     response (a handful of single/double quotes, no destructive
//     statements).
//  2. Boolean-based blind: send a (true-condition, false-condition) payload
//     pair and compare responses — a true payload should behave like the
//     original input, a false payload should behave differently, with
//     neither producing a visible error. Two independent pairs must agree
//     before this is reported, to filter out pages that just vary a bit
//     between requests for unrelated reasons.
//  3. Time-based blind: send payloads that ask the database to sleep, and
//     only report a finding if the delay reproduces on a second,
//     independent request — a plain single slow response is noise, not a
//     finding.
//
// All three are read-only probes; nothing here attempts to modify data.
func CheckSQLi(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param) []model.Finding {
	var findings []model.Finding
	baselineErr := ""
	if baseline != nil {
		baselineErr = matchSQLError(baseline.Body)
	}

	for _, payload := range sqliErrorPayloads {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		if sig := matchSQLError(ex.Body); sig != "" && sig != baselineErr {
			findings = append(findings, model.Finding{
				Category:    "SQL Injection",
				Severity:    model.SeverityHigh,
				Title:       "Possible error-based SQL injection in parameter \"" + p.Name + "\"",
				Description: fmt.Sprintf("Sending %q caused a database error message to appear in the response (matched signature: %q). This suggests user input is concatenated into a SQL query without proper parameterization/escaping.", payload, sig),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched error signature: " + sig},
				Remediation: "Use parameterized queries / prepared statements (or a vetted ORM) instead of building SQL by string concatenation, and disable verbose database error output in production.",
			})
			return findings // one confirmed error-based hit is enough for this param
		}
	}

	if f := checkSQLiBoolean(ctx, lim, cli, baseline, t, p); f != nil {
		return append(findings, *f)
	}

	// Time-based is tried last: it's the slowest technique (each attempt
	// costs a deliberate multi-second delay), so it only runs once the
	// two faster techniques have both found nothing.
	for _, payload := range sqliTimePayloads() {
		ex1 := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex1.Err != nil || ex1.Response == nil {
			continue
		}
		threshold := int64(sqliDelaySeconds*1000) - 1200 // tolerate some jitter/undershoot
		if ex1.ElapsedMS < threshold {
			continue
		}
		// Confirm: an unrelated slow network blip shouldn't reproduce twice in a row.
		time.Sleep(300 * time.Millisecond)
		ex2 := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex2.Err != nil || ex2.Response == nil || ex2.ElapsedMS < threshold {
			continue
		}
		findings = append(findings, model.Finding{
			Category:    "SQL Injection",
			Severity:    model.SeverityHigh,
			Title:       "Possible time-based blind SQL injection in parameter \"" + p.Name + "\"",
			Description: fmt.Sprintf("Sending %q made the response consistently take about %dms and %dms (two independent requests), versus a normal baseline — consistent with a database sleep/delay executing from injected input.", payload, ex1.ElapsedMS, ex2.ElapsedMS),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   p.Name,
			Evidence:    model.Evidence{RequestRaw: ex2.RequestRaw, ResponseRaw: ex2.ResponseRaw, Notes: fmt.Sprintf("Confirmation request 1: %dms, request 2: %dms, baseline: %dms", ex1.ElapsedMS, ex2.ElapsedMS, safeElapsed(baseline))},
			Remediation: "Use parameterized queries / prepared statements instead of building SQL by string concatenation.",
		})
		return findings
	}

	return findings
}

// checkSQLiBoolean implements boolean-based blind SQLi detection. For
// each (true, false) payload pair it checks that the true-response
// resembles the baseline (same status, near-identical body length) while
// the false-response is clearly different — and requires two independent
// pairs to show this same pattern before returning a finding, since any
// single comparison could just be page noise (ads, timestamps, a CSRF
// token embedded in the page).
func checkSQLiBoolean(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param) *model.Finding {
	if baseline == nil || baseline.Response == nil || len(baseline.Body) < 10 {
		return nil // too little to compare against reliably
	}

	confirmed := 0
	var lastTrue, lastFalse *httpclient.Exchange
	var lastPair sqliBoolPair

	for _, pair := range sqliBooleanPairs() {
		trueEx := sendWithPayload(ctx, lim, cli, t, p.Name, pair.True)
		falseEx := sendWithPayload(ctx, lim, cli, t, p.Name, pair.False)
		if trueEx.Err != nil || falseEx.Err != nil || trueEx.Response == nil || falseEx.Response == nil {
			continue
		}
		// Neither half of a boolean-blind pair should itself leak a SQL
		// error — that's the error-based technique's signal, not this one,
		// and treating it as a boolean match here would just double up
		// with (and potentially outrun) the error-based check.
		if matchSQLError(trueEx.Body) != "" || matchSQLError(falseEx.Body) != "" {
			continue
		}

		trueMatchesBaseline := trueEx.Response.StatusCode == baseline.Response.StatusCode &&
			similarLength(len(baseline.Body), len(trueEx.Body)) >= 0.95
		falseDiffers := trueEx.Response.StatusCode != falseEx.Response.StatusCode ||
			similarLength(len(trueEx.Body), len(falseEx.Body)) < 0.90

		if trueMatchesBaseline && falseDiffers {
			confirmed++
			lastTrue, lastFalse, lastPair = trueEx, falseEx, pair
			if confirmed >= 2 {
				break
			}
		}
	}

	if confirmed < 2 {
		return nil
	}
	return &model.Finding{
		Category: "SQL Injection",
		Severity: model.SeverityHigh,
		Title:    "Possible boolean-based blind SQL injection in parameter \"" + p.Name + "\"",
		Description: fmt.Sprintf(
			"Two independent true/false payload pairs showed the expected pattern: a \"true\" condition (%q) produced a response matching the normal baseline (%d bytes), while the matching \"false\" condition (%q) produced a clearly different response (%d bytes) — consistent with the input being evaluated inside a SQL WHERE clause.",
			lastPair.True, len(lastTrue.Body), lastPair.False, len(lastFalse.Body)),
		URL:       t.URL,
		Method:    t.Method,
		Parameter: p.Name,
		Evidence: model.Evidence{
			RequestRaw:  lastFalse.RequestRaw,
			ResponseRaw: lastFalse.ResponseRaw,
			Notes:       fmt.Sprintf("Baseline: %d bytes (status %d). True payload: %d bytes (status %d). False payload: %d bytes (status %d).", len(baseline.Body), baseline.Response.StatusCode, len(lastTrue.Body), lastTrue.Response.StatusCode, len(lastFalse.Body), lastFalse.Response.StatusCode),
		},
		Remediation: "Use parameterized queries / prepared statements instead of building SQL by string concatenation.",
	}
}

func safeElapsed(ex *httpclient.Exchange) int64 {
	if ex == nil {
		return 0
	}
	return ex.ElapsedMS
}
