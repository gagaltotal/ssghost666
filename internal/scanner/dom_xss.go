package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ssghost666/internal/browser"
	"ssghost666/internal/model"

	"github.com/chromedp/chromedp"
)

// DOM XSS sinks - JavaScript functions and properties that can execute code
var domSinks = []string{
	"innerHTML",
	"outerHTML",
	"document.write",
	"document.writeln",
	"eval(",
	"setTimeout(",
	"setInterval(",
	"Function(",
	"execScript(",
	"location.href",
	"location.assign",
	"location.replace",
	".html(",
	".append(",
	".after(",
	".before(",
}

// DOM XSS sources - where attacker-controlled data can come from
var domSources = []string{
	"location.hash",
	"location.search",
	"location.href",
	"document.URL",
	"document.documentURI",
	"document.referrer",
	"window.name",
	"postMessage",
}

// CheckDOMXSS performs DOM-based XSS detection using headless Chrome.
// It injects payloads into URL fragments and monitors for dangerous sink usage.
func CheckDOMXSS(ctx context.Context, targetURL, chromePath string) []model.Finding {
	var findings []model.Finding

	// DOM XSS payloads that will be injected via URL hash
	payloads := []string{
		"<img src=x onerror=alert(document.domain)>",
		"<svg/onload=alert(1)>",
		"javascript:alert(document.domain)",
		"'><script>alert(1)</script>",
		"\"><img src=x onerror=alert(1)>",
	}

	for _, payload := range payloads {
		// Test via URL hash (most common DOM XSS vector)
		testURL := targetURL + "#" + payload

		// Also test via URL parameters if the URL supports it
		if strings.Contains(targetURL, "?") {
			testURL = targetURL + "&xss=" + payload
		} else if !strings.Contains(targetURL, "#") {
			testURL = targetURL + "?xss=" + payload
		}

		sinks, executed := detectDOMXSS(ctx, testURL, chromePath, payload)

		if executed {
			findings = append(findings, model.Finding{
				Category:    "XSS",
				Severity:    model.SeverityCritical,
				Title:       "Confirmed DOM-based XSS",
				Description: fmt.Sprintf("DOM-based XSS detected with payload %q. The application reads from a DOM source and writes to a dangerous sink without proper sanitization. This allows client-side code execution.", payload),
				URL:         targetURL,
				Method:      "GET",
				Parameter:   "URL fragment/hash",
				Evidence:    model.Evidence{Notes: fmt.Sprintf("Payload executed. Sinks detected: %s", strings.Join(sinks, ", "))},
				Remediation: "Avoid reading from DOM sources (location.hash, location.search, etc.) and writing to dangerous sinks. If necessary, use textContent instead of innerHTML, properly encode/escape output, implement Content Security Policy (CSP), and validate/sanitize all client-side data flow.",
			})
			break // One confirmation is enough
		} else if len(sinks) > 0 {
			findings = append(findings, model.Finding{
				Category:    "XSS",
				Severity:    model.SeverityMedium,
				Title:       "Potential DOM-based XSS (dangerous sinks detected)",
				Description: fmt.Sprintf("The page uses dangerous DOM sinks that could lead to XSS. Detected sinks: %s. Manual verification recommended to confirm if user-controlled data reaches these sinks.", strings.Join(sinks, ", ")),
				URL:         targetURL,
				Method:      "GET",
				Parameter:   "DOM manipulation",
				Evidence:    model.Evidence{Notes: fmt.Sprintf("Dangerous sinks found: %s. Payload: %q", strings.Join(sinks, ", "), payload)},
				Remediation: "Review the JavaScript code for data flow from DOM sources to these sinks. Ensure proper sanitization is in place.",
			})
			break // Only report once
		}
	}

	return findings
}

// detectDOMXSS launches a browser, navigates to the URL with payload, and checks for XSS execution
func detectDOMXSS(ctx context.Context, testURL, chromePath, payload string) ([]string, bool) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	browserCtx, cancelBrowser := browser.NewTab(timeoutCtx, chromePath, 10*time.Second)
	if browserCtx == nil {
		return nil, false
	}
	defer cancelBrowser()

	// Inject detection script to monitor dangerous sinks and check for alert
	detectedSinks := []string{}
	dialogDetected := false

	detectionScript := `
		(function() {
			window.__ssghost_sinks = [];
			window.__ssghost_alert_fired = false;
			
			// Override alert to detect XSS
			const originalAlert = window.alert;
			window.alert = function() {
				window.__ssghost_alert_fired = true;
				// Don't actually show alert
			};
			
			// Monitor innerHTML writes
			const originalInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
			if (originalInnerHTMLDesc && originalInnerHTMLDesc.set) {
				Object.defineProperty(Element.prototype, 'innerHTML', {
					set: function(value) {
						window.__ssghost_sinks.push('innerHTML');
						return originalInnerHTMLDesc.set.call(this, value);
					}
				});
			}
			
			// Monitor document.write
			const originalWrite = document.write;
			document.write = function() {
				window.__ssghost_sinks.push('document.write');
				return originalWrite.apply(this, arguments);
			};
			
			// Monitor eval
			const originalEval = window.eval;
			window.eval = function() {
				window.__ssghost_sinks.push('eval');
				return originalEval.apply(this, arguments);
			};
			
			// Monitor location.href writes
			const originalHrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
			if (originalHrefDesc && originalHrefDesc.set) {
				Object.defineProperty(Location.prototype, 'href', {
					set: function(value) {
						window.__ssghost_sinks.push('location.href');
						return originalHrefDesc.set.call(this, value);
					}
				});
			}
		})();
	`

	// Navigate and inject script
	var pageSource string
	var sinksJSON string
	var alertFired bool

	err := chromedp.Run(browserCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.EvaluateAsDevTools(detectionScript, nil).Do(ctx)
		}),
		chromedp.Navigate(testURL),
		chromedp.Sleep(1*time.Second),
		chromedp.Evaluate(`JSON.stringify(window.__ssghost_sinks || [])`, &sinksJSON),
		chromedp.Evaluate(`window.__ssghost_alert_fired || false`, &alertFired),
		chromedp.OuterHTML("html", &pageSource),
	)

	if err != nil {
		return nil, false
	}

	dialogDetected = alertFired

	// Parse sinks JSON
	if sinksJSON != "" {
		sinksJSON = strings.Trim(sinksJSON, `"`)
		if strings.HasPrefix(sinksJSON, "[") && strings.HasSuffix(sinksJSON, "]") {
			sinksJSON = strings.Trim(sinksJSON, "[]")
			if sinksJSON != "" {
				parts := strings.Split(sinksJSON, ",")
				for _, p := range parts {
					p = strings.Trim(strings.TrimSpace(p), `"`)
					if p != "" {
						detectedSinks = append(detectedSinks, p)
					}
				}
			}
		}
	}

	// Check if payload is reflected in dangerous context
	if strings.Contains(pageSource, payload) {
		detectedSinks = append(detectedSinks, "payload-reflection")
	}

	return detectedSinks, dialogDetected
}
