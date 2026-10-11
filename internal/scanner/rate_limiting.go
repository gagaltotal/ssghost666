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

// rateLimitTestConfig defines parameters for rate limit testing.
//
// Burst sizes are deliberately conservative and depend on how safe it is
// to repeat the method: idempotent/safe methods (GET/HEAD/OPTIONS) get a
// larger burst, while state-changing methods (POST/PUT/PATCH) get a
// smaller one that still reuses the target's *baseline* body (never an
// attack payload). DELETE is never burst at all — repeating a DELETE
// would be destructive, which this tool explicitly avoids.
const (
	rateLimitSafeBurst          = 25 // GET/HEAD/OPTIONS
	rateLimitStateChangingBurst = 12 // POST/PUT/PATCH
	rateLimitTestWindow         = 5 * time.Second
)

// expensiveEndpointIndicators are URL/method patterns for endpoints likely to be resource-intensive
var expensiveEndpointIndicators = []struct {
	pattern     string
	description string
}{
	{"upload", "File upload endpoint"},
	{"import", "Data import endpoint"},
	{"export", "Data export endpoint"},
	{"report", "Report generation endpoint"},
	{"generate", "Content generation endpoint"},
	{"search", "Search endpoint"},
	{"query", "Query endpoint"},
	{"download", "Download endpoint"},
	{"convert", "Conversion endpoint"},
	{"process", "Processing endpoint"},
	{"analyze", "Analysis endpoint"},
	{"calculate", "Calculation endpoint"},
}

// CheckRateLimiting tests for missing or inadequate rate limiting on API endpoints
func CheckRateLimiting(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target) []model.Finding {
	var findings []model.Finding

	// Only test modifying endpoints or expensive operations
	if !shouldTestRateLimit(t) {
		return nil
	}

	// Choose a burst size that matches how safe it is to repeat the method.
	burst := rateLimitBurstFor(t)

	// Perform burst test - send multiple requests quickly. This
	// deliberately bypasses our own rate limiter (see performBurstTest)
	// so the measured behaviour is the target's, not ours.
	results := performBurstTest(ctx, cli, t, burst)

	if len(results) == 0 {
		return nil
	}

	// Analyze results for rate limiting
	analysis := analyzeRateLimitResults(results)

	// Check if endpoint lacks rate limiting
	if analysis.successRate > 0.9 { // More than 90% of requests succeeded
		if analysis.hasRateLimitHeaders {
			// Headers present but not enforced
			findings = append(findings, model.Finding{
				Category:    "Rate Limiting",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Weak rate limiting on %s %s", t.Method, t.URL),
				Description: fmt.Sprintf("%d rapid requests were sent to this endpoint. %d%% succeeded despite rate limit headers being present. The rate limiting appears to be either too permissive or not properly enforced. Average response time: %dms.", len(results), int(analysis.successRate*100), analysis.avgResponseTime),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   "",
				Evidence:    model.Evidence{RequestRaw: results[0].RequestRaw, ResponseRaw: results[0].ResponseRaw, Notes: fmt.Sprintf("Burst test: %d requests, %d succeeded, %d rate-limited. Headers: %v", len(results), analysis.successCount, analysis.rateLimitedCount, analysis.rateLimitHeaders)},
				Remediation: "Implement or strengthen rate limiting. Use token bucket or sliding window algorithms. Enforce limits at application and infrastructure (API gateway) layers. Return 429 Too Many Requests with Retry-After header.",
			})
		} else {
			// No rate limiting detected
			severity := model.SeverityMedium
			if isExpensiveEndpoint(t) {
				severity = model.SeverityHigh
			}

			findings = append(findings, model.Finding{
				Category:    "Rate Limiting",
				Severity:    severity,
				Title:       fmt.Sprintf("Missing rate limiting on %s %s", t.Method, t.URL),
				Description: fmt.Sprintf("%d rapid requests were sent to this endpoint within %v. %d%% succeeded with no rate limiting detected. %s This endpoint is vulnerable to resource exhaustion attacks (DoS). Average response time: %dms.", len(results), rateLimitTestWindow, int(analysis.successRate*100), getEndpointExpenseDescription(t), analysis.avgResponseTime),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   "",
				Evidence:    model.Evidence{RequestRaw: results[0].RequestRaw, ResponseRaw: results[len(results)-1].ResponseRaw, Notes: fmt.Sprintf("Burst test: %d requests, %d succeeded, no rate limit headers found", len(results), analysis.successCount)},
				Remediation: "Implement rate limiting using token bucket or sliding window algorithms. Set appropriate limits based on endpoint cost (e.g., 10 req/min for expensive operations, 100 req/min for reads). Return 429 with Retry-After header. Consider using API gateway or middleware like express-rate-limit, django-ratelimit, or cloud-based solutions.",
			})
		}
	} else if analysis.successRate > 0.4 && analysis.successRate <= 0.9 {
		// Partial rate limiting - some requests blocked but many still succeed
		findings = append(findings, model.Finding{
			Category:    "Rate Limiting",
			Severity:    model.SeverityLow,
			Title:       fmt.Sprintf("Potentially inadequate rate limiting on %s %s", t.Method, t.URL),
			Description: fmt.Sprintf("%d rapid requests were sent to this endpoint. %d%% succeeded and %d%% were rate-limited. The rate limit might be too permissive for this type of endpoint.", len(results), int(analysis.successRate*100), int((1-analysis.successRate)*100)),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   "",
			Evidence:    model.Evidence{RequestRaw: results[0].RequestRaw, ResponseRaw: results[len(results)-1].ResponseRaw, Notes: fmt.Sprintf("Burst test: %d requests, %d succeeded, %d blocked", len(results), analysis.successCount, analysis.rateLimitedCount)},
			Remediation: "Review and potentially tighten rate limiting thresholds based on endpoint criticality and resource cost. Monitor for abuse patterns.",
		})
	}

	// Check for endpoints without protection on expensive operations
	if isExpensiveEndpoint(t) && analysis.successRate > 0.7 {
		if analysis.avgResponseTime > 2000 { // Slow responses (>2s) without rate limiting
			findings = append(findings, model.Finding{
				Category:    "Rate Limiting",
				Severity:    model.SeverityHigh,
				Title:       fmt.Sprintf("Resource exhaustion risk: expensive operation without adequate rate limiting on %s %s", t.Method, t.URL),
				Description: fmt.Sprintf("This endpoint (%s) has slow response times (avg %dms) and lacks adequate rate limiting. %d rapid requests succeeded. This combination makes it highly vulnerable to resource exhaustion DoS attacks.", getEndpointExpenseDescription(t), analysis.avgResponseTime, analysis.successCount),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   "",
				Evidence:    model.Evidence{RequestRaw: results[0].RequestRaw, ResponseRaw: results[len(results)-1].ResponseRaw, Notes: fmt.Sprintf("Expensive endpoint: avg response %dms, %d/%d requests succeeded", analysis.avgResponseTime, analysis.successCount, len(results))},
				Remediation: "Implement aggressive rate limiting for expensive operations. Consider: per-user quotas, queue-based processing, async job handling, CAPTCHA for expensive operations, and monitoring for abuse patterns. Set stricter limits (e.g., 5-10 requests per hour).",
			})
		}
	}

	return findings
}

// shouldTestRateLimit determines if an endpoint should be tested for rate limiting
func shouldTestRateLimit(t model.Target) bool {
	method := strings.ToUpper(t.Method)

	// DELETE is intentionally excluded: bursting a DELETE would repeatedly
	// destroy resources, which this tool must never do.
	// POST/PUT/PATCH reuse the request's *baseline* body (never an attack
	// payload), so repeating them is idempotent in practice for most APIs.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	case "GET", "HEAD", "OPTIONS":
		// Only burst safe read methods when they look expensive.
		return isExpensiveEndpoint(t)
	}

	return false
}

// rateLimitBurstFor returns how many requests to send for a given target,
// erring on the side of caution for state-changing methods.
func rateLimitBurstFor(t model.Target) int {
	switch strings.ToUpper(t.Method) {
	case "GET", "HEAD", "OPTIONS":
		return rateLimitSafeBurst
	default:
		return rateLimitStateChangingBurst
	}
}

// isExpensiveEndpoint checks if endpoint is likely resource-intensive
func isExpensiveEndpoint(t model.Target) bool {
	urlLower := strings.ToLower(t.URL)
	for _, indicator := range expensiveEndpointIndicators {
		if strings.Contains(urlLower, indicator.pattern) {
			return true
		}
	}
	return false
}

// getEndpointExpenseDescription returns description of why endpoint is expensive
func getEndpointExpenseDescription(t model.Target) string {
	urlLower := strings.ToLower(t.URL)
	for _, indicator := range expensiveEndpointIndicators {
		if strings.Contains(urlLower, indicator.pattern) {
			return indicator.description
		}
	}
	return "Endpoint"
}

// performBurstTest sends multiple requests rapidly to test rate limiting.
// It deliberately bypasses the shared client-side rate limiter so the
// burst reflects the *target's* throttling rather than our own politeness
// pacing (which would otherwise mask a missing server-side limit).
func performBurstTest(ctx context.Context, cli *httpclient.Client, t model.Target, count int) []*httpclient.Exchange {
	var mu sync.Mutex
	results := make([]*httpclient.Exchange, 0, count)

	// Send requests concurrently for a realistic burst scenario.
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ex := sendWithPayloadNoLimit(cli, t, "", "")
			mu.Lock()
			results = append(results, ex)
			mu.Unlock()
		}()

		// Small delay to spread requests across the time window instead of
		// blasting them all in a single instant.
		select {
		case <-ctx.Done():
			wg.Wait()
			return results
		case <-time.After(rateLimitTestWindow / time.Duration(count)):
		}
	}

	wg.Wait()
	return results
}

// rateLimitAnalysis holds the results of analyzing rate limit test
type rateLimitAnalysis struct {
	successCount        int
	rateLimitedCount    int
	errorCount          int
	successRate         float64
	avgResponseTime     int64
	hasRateLimitHeaders bool
	rateLimitHeaders    map[string]string
}

// analyzeRateLimitResults analyzes the results of burst testing
func analyzeRateLimitResults(results []*httpclient.Exchange) rateLimitAnalysis {
	analysis := rateLimitAnalysis{
		rateLimitHeaders: make(map[string]string),
	}

	var totalResponseTime int64
	validResults := 0

	for _, ex := range results {
		if ex.Err != nil || ex.Response == nil {
			analysis.errorCount++
			continue
		}

		validResults++
		totalResponseTime += ex.ElapsedMS

		// Check for rate limiting indicators
		if ex.Response.StatusCode == 429 { // Too Many Requests
			analysis.rateLimitedCount++
			analysis.hasRateLimitHeaders = true

			// Capture rate limit headers
			if retryAfter := ex.Response.Header.Get("Retry-After"); retryAfter != "" {
				analysis.rateLimitHeaders["Retry-After"] = retryAfter
			}
			if limit := ex.Response.Header.Get("X-RateLimit-Limit"); limit != "" {
				analysis.rateLimitHeaders["X-RateLimit-Limit"] = limit
			}
			if remaining := ex.Response.Header.Get("X-RateLimit-Remaining"); remaining != "" {
				analysis.rateLimitHeaders["X-RateLimit-Remaining"] = remaining
			}
		} else if ex.Response.StatusCode >= 200 && ex.Response.StatusCode < 300 {
			analysis.successCount++

			// Check if rate limit headers are present even on success
			if ex.Response.Header.Get("X-RateLimit-Limit") != "" {
				analysis.hasRateLimitHeaders = true
				analysis.rateLimitHeaders["X-RateLimit-Limit"] = ex.Response.Header.Get("X-RateLimit-Limit")
			}
		} else {
			// Other errors (not rate limiting)
			analysis.errorCount++
		}
	}

	if validResults > 0 {
		analysis.successRate = float64(analysis.successCount) / float64(validResults)
		analysis.avgResponseTime = totalResponseTime / int64(validResults)
	}

	return analysis
}
