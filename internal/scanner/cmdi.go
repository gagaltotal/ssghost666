package scanner

import (
	"context"
	"fmt"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// CheckCmdInjection tests one parameter for OS command injection using
// time-based blind detection: shell metacharacters chain a `sleep N`
// onto whatever command the server might be building from this input.
// Like the SQLi time-based check, a hit must reproduce on an independent
// second request before being reported, to filter out ordinary network
// jitter. No payload here attempts anything beyond sleeping.
func CheckCmdInjection(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param) []model.Finding {
	threshold := int64(cmdiDelaySeconds*1000) - 1200

	for _, payload := range cmdiTimePayloads() {
		ex1 := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex1.Err != nil || ex1.Response == nil || ex1.ElapsedMS < threshold {
			continue
		}
		time.Sleep(300 * time.Millisecond)
		ex2 := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex2.Err != nil || ex2.Response == nil || ex2.ElapsedMS < threshold {
			continue
		}
		return []model.Finding{{
			Category:    "OS Command Injection",
			Severity:    model.SeverityCritical,
			Title:       "Possible OS command injection in parameter \"" + p.Name + "\"",
			Description: fmt.Sprintf("Sending %q made the response consistently take about %dms and %dms (two independent requests), consistent with a `sleep %d` shell command executing from injected input.", payload, ex1.ElapsedMS, ex2.ElapsedMS, cmdiDelaySeconds),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   p.Name,
			Evidence:    model.Evidence{RequestRaw: ex2.RequestRaw, ResponseRaw: ex2.ResponseRaw, Notes: fmt.Sprintf("Confirmation request 1: %dms, request 2: %dms, baseline: %dms", ex1.ElapsedMS, ex2.ElapsedMS, safeElapsed(baseline))},
			Remediation: "Never build shell commands from user input. Use language APIs that take argument arrays (not a shell string), and/or an allowlist of permitted values.",
		}}
	}
	return nil
}
