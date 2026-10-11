package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// prototypePollutionPayloads contains test payloads for detecting prototype pollution
// These payloads attempt to pollute Object.prototype with a test property
var prototypePollutionPayloads = []struct {
	name        string
	payload     string
	testKey     string // the key we're trying to pollute with
	description string
}{
	{
		name:        "__proto__ (JSON)",
		payload:     `{"__proto__":{"ssghost666polluted":"true"}}`,
		testKey:     "ssghost666polluted",
		description: "__proto__ pollution via JSON body",
	},
	{
		name:        "constructor.prototype (JSON)",
		payload:     `{"constructor":{"prototype":{"ssghost666polluted":"true"}}}`,
		testKey:     "ssghost666polluted",
		description: "constructor.prototype pollution via JSON body",
	},
	{
		name:        "__proto__ (query param)",
		payload:     "__proto__[ssghost666polluted]=true",
		testKey:     "ssghost666polluted",
		description: "__proto__ pollution via query parameter",
	},
	{
		name:        "constructor.prototype (query param)",
		payload:     "constructor[prototype][ssghost666polluted]=true",
		testKey:     "ssghost666polluted",
		description: "constructor.prototype pollution via query parameter",
	},
}

// CheckPrototypePollution tests for prototype pollution vulnerabilities
// in JavaScript applications (both client-side and Node.js)
func CheckPrototypePollution(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, p model.Param) []model.Finding {
	var findings []model.Finding

	// Skip non-JSON endpoints for JSON payloads, unless parameter name suggests object/deep merge
	if !looksLikeObjectParam(p.Name) && t.ContentType != "application/json" {
		return nil
	}

	// Baseline request to see normal behavior
	baseline := sendWithPayload(ctx, lim, cli, t, p.Name, p.Sample)
	if baseline.Err != nil || baseline.Response == nil {
		return nil
	}

	for _, probe := range prototypePollutionPayloads {
		var ex *httpclient.Exchange

		// For JSON payloads, send as body; for query params, send as a raw
		// query fragment so the injected key is a *new* parameter (e.g.
		// ?__proto__[x]=true) rather than the value of an existing one.
		if strings.Contains(probe.payload, "{") && strings.Contains(probe.payload, "}") {
			// JSON payload - send in body
			if t.ContentType == "application/json" || p.Location == model.LocBody {
				ex = sendJSONPayload(ctx, lim, cli, t, probe.payload)
			} else {
				continue // Skip JSON payloads for non-JSON endpoints
			}
		} else {
			// Query parameter style payload
			if p.Location == model.LocQuery {
				ex = sendQueryFragment(ctx, lim, cli, t, probe.payload)
			} else {
				continue // Skip query payloads for non-query params
			}
		}

		if ex.Err != nil || ex.Response == nil {
			continue
		}

		// Check for signs of prototype pollution in the response
		evidence := []string{}

		// 1. Check if our pollution key appears in the response
		if strings.Contains(ex.Body, probe.testKey) {
			evidence = append(evidence, fmt.Sprintf("Pollution key %q reflected in response", probe.testKey))
		}

		// 2. Check for JavaScript errors related to prototype pollution
		errorSignatures := []string{
			"Cannot add property",
			"Cannot set property",
			"__proto__",
			"constructor.prototype",
			"prototype pollution",
			"Object.prototype",
		}
		for _, sig := range errorSignatures {
			if strings.Contains(strings.ToLower(ex.Body), strings.ToLower(sig)) {
				evidence = append(evidence, fmt.Sprintf("Error signature found: %q", sig))
				break
			}
		}

		// 3. Try to detect behavioral changes by sending a follow-up request
		// If pollution succeeded, newly created objects should inherit our property
		followup := sendWithPayload(ctx, lim, cli, t, p.Name, p.Sample)
		if followup.Err == nil && followup.Response != nil {
			// Check if the polluted property persists in subsequent requests
			if strings.Contains(followup.Body, probe.testKey) && !strings.Contains(baseline.Body, probe.testKey) {
				evidence = append(evidence, fmt.Sprintf("Polluted property %q persists in subsequent request (not in baseline)", probe.testKey))
			}
		}

		// 4. Check for JSON responses that include unexpected properties
		if strings.Contains(ex.Response.Header.Get("Content-Type"), "application/json") {
			var responseData map[string]interface{}
			if err := json.Unmarshal([]byte(ex.Body), &responseData); err == nil {
				// Check if our pollution key appears at unexpected places in the response
				if checkNestedKey(responseData, probe.testKey) {
					evidence = append(evidence, fmt.Sprintf("Polluted property %q found in JSON response structure", probe.testKey))
				}
			}
		}

		// 5. Check for timing differences (pollution might cause additional processing)
		if ex.ElapsedMS > baseline.ElapsedMS*2 && baseline.ElapsedMS > 0 {
			evidence = append(evidence, fmt.Sprintf("Significant timing difference: %dms vs baseline %dms", ex.ElapsedMS, baseline.ElapsedMS))
		}

		// If we have multiple pieces of evidence, report the finding
		if len(evidence) >= 2 {
			findings = append(findings, model.Finding{
				Category:    "Prototype Pollution",
				Severity:    model.SeverityHigh,
				Title:       fmt.Sprintf("Potential Prototype Pollution via %s in parameter %q", probe.name, p.Name),
				Description: fmt.Sprintf("Testing %s payload in parameter %q shows signs of prototype pollution: %s. This vulnerability allows attackers to inject properties into Object.prototype, potentially leading to authentication bypass, privilege escalation, or RCE in Node.js applications.", probe.description, p.Name, strings.Join(evidence, "; ")),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Evidence: " + strings.Join(evidence, "; ")},
				Remediation: "Avoid using deep merge functions on user input without proper sanitization. Use Object.create(null) for creating objects without prototype, validate input keys against a whitelist, freeze Object.prototype in Node.js apps, and use Map instead of plain objects for user-controlled data.",
			})
		} else if len(evidence) == 1 {
			// Single piece of evidence - report as lower confidence
			findings = append(findings, model.Finding{
				Category:    "Prototype Pollution",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Possible Prototype Pollution via %s in parameter %q — manual verification recommended", probe.name, p.Name),
				Description: fmt.Sprintf("Testing %s payload in parameter %q shows one indicator of prototype pollution: %s. Manual verification recommended to confirm exploitability.", probe.description, p.Name, evidence[0]),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Evidence: " + evidence[0]},
				Remediation: "Avoid using deep merge functions on user input. Validate and sanitize all object keys, use Object.create(null), and prefer Map over plain objects for user data.",
			})
		}
	}

	return findings
}

// looksLikeObjectParam checks if a parameter name suggests it accepts object/nested data
func looksLikeObjectParam(name string) bool {
	name = strings.ToLower(name)
	objectIndicators := []string{
		"object", "data", "json", "payload", "config", "settings", "options",
		"params", "properties", "attributes", "metadata", "user", "profile",
	}
	for _, ind := range objectIndicators {
		if strings.Contains(name, ind) {
			return true
		}
	}
	return false
}

// checkNestedKey recursively checks if a key exists anywhere in a nested map structure
func checkNestedKey(data map[string]interface{}, key string) bool {
	if _, exists := data[key]; exists {
		return true
	}
	for _, v := range data {
		if nested, ok := v.(map[string]interface{}); ok {
			if checkNestedKey(nested, key) {
				return true
			}
		}
	}
	return false
}

// sendJSONPayload sends a raw JSON payload as the request body, acquiring
// the shared rate limiter exactly like every other scanner request.
func sendJSONPayload(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, jsonPayload string) *httpclient.Exchange {
	return sendRawBody(ctx, lim, cli, t, t.Method, "application/json", jsonPayload)
}
