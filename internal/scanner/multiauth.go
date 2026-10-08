package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ssghost666/internal/browser"
	"ssghost666/internal/httpclient"

	"github.com/chromedp/chromedp"
)

// AuthStep represents a single step in a multi-step authentication flow
type AuthStep struct {
	Name        string            // Human-readable name for this step
	URL         string            // URL to submit to
	Method      string            // HTTP method (GET, POST)
	FormData    map[string]string // Form fields to submit
	Extractors  []TokenExtractor  // Rules to extract tokens/cookies from response
	WaitForJS   bool              // Whether to wait for JavaScript execution
	SuccessText string            // Text that indicates success
}

// TokenExtractor defines how to extract a token or value from a response
type TokenExtractor struct {
	Name     string // Token name (e.g., "csrf_token", "session_id")
	Type     string // "cookie", "header", "json", "regex", "input"
	Pattern  string // For regex: pattern to match; for json: JSONPath; for input: field name
	StoreAs  string // Variable name to store for next steps
	Required bool   // Whether this token is mandatory
}

// AuthFlow represents a complete multi-step authentication sequence
type AuthFlow struct {
	Steps      []AuthStep
	ChromePath string
	HTTPClient *httpclient.Client
	Tokens     map[string]string // Extracted tokens shared across steps
}

// NewAuthFlow creates a new authentication flow
func NewAuthFlow(chromePath string, httpClient *httpclient.Client) *AuthFlow {
	return &AuthFlow{
		Steps:      []AuthStep{},
		ChromePath: chromePath,
		HTTPClient: httpClient,
		Tokens:     make(map[string]string),
	}
}

// AddStep adds an authentication step to the flow
func (af *AuthFlow) AddStep(step AuthStep) {
	af.Steps = append(af.Steps, step)
}

// Execute runs the complete authentication flow and returns the final session state
func (af *AuthFlow) Execute(ctx context.Context) (*AuthResult, error) {
	result := &AuthResult{
		Cookies: make(map[string]string),
		Headers: make(map[string]string),
		Tokens:  make(map[string]string),
	}

	for i, step := range af.Steps {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("context cancelled: %w", err)
		}

		// Replace tokens in form data with extracted values
		formData := af.interpolateTokens(step.FormData)

		var stepResult *StepResult
		var err error

		if step.WaitForJS {
			// Use headless browser for JavaScript-heavy steps
			stepResult, err = af.executeBrowserStep(ctx, step, formData)
		} else {
			// Use HTTP client for simple form submissions
			stepResult, err = af.executeHTTPStep(ctx, step, formData)
		}

		if err != nil {
			return nil, fmt.Errorf("step %d (%s) failed: %w", i+1, step.Name, err)
		}

		// Extract tokens from response
		for _, extractor := range step.Extractors {
			value, err := af.extractToken(stepResult, extractor)
			if err != nil && extractor.Required {
				return nil, fmt.Errorf("step %d: failed to extract required token %s: %w", i+1, extractor.Name, err)
			}
			if value != "" {
				af.Tokens[extractor.StoreAs] = value
				result.Tokens[extractor.StoreAs] = value
			}
		}

		// Merge cookies and headers
		for k, v := range stepResult.Cookies {
			result.Cookies[k] = v
		}
		for k, v := range stepResult.Headers {
			result.Headers[k] = v
		}

		// Check for success indicator
		if step.SuccessText != "" && !strings.Contains(stepResult.Body, step.SuccessText) {
			return nil, fmt.Errorf("step %d: success text %q not found in response", i+1, step.SuccessText)
		}

		result.Steps = append(result.Steps, *stepResult)
	}

	result.Success = true
	return result, nil
}

// executeHTTPStep performs an HTTP-based authentication step
func (af *AuthFlow) executeHTTPStep(ctx context.Context, step AuthStep, formData map[string]string) (*StepResult, error) {
	var body io.Reader
	if step.Method == "POST" {
		form := url.Values{}
		for k, v := range formData {
			form.Add(k, v)
		}
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(ctx, step.Method, step.URL, body)
	if err != nil {
		return nil, err
	}

	if step.Method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Add previously extracted tokens as cookies/headers
	for name, value := range af.Tokens {
		if strings.HasPrefix(name, "cookie_") {
			req.AddCookie(&http.Cookie{Name: strings.TrimPrefix(name, "cookie_"), Value: value})
		} else if strings.HasPrefix(name, "header_") {
			req.Header.Set(strings.TrimPrefix(name, "header_"), value)
		}
	}

	resp, err := af.HTTPClient.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	result := &StepResult{
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		Cookies:    make(map[string]string),
		Headers:    make(map[string]string),
	}

	for _, cookie := range resp.Cookies() {
		result.Cookies[cookie.Name] = cookie.Value
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			result.Headers[k] = v[0]
		}
	}

	return result, nil
}

// executeBrowserStep performs a browser-based authentication step with JavaScript support
func (af *AuthFlow) executeBrowserStep(ctx context.Context, step AuthStep, formData map[string]string) (*StepResult, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	browserCtx, cancelBrowser := browser.NewTab(timeoutCtx, af.ChromePath, 15*time.Second)
	defer cancelBrowser()

	result := &StepResult{
		StatusCode: 200, // Browser doesn't expose status code easily
		Cookies:    make(map[string]string),
		Headers:    make(map[string]string),
	}

	var pageBody string
	var cookieJSON string

	// Build tasks for filling form and submitting
	var tasks []chromedp.Action
	tasks = append(tasks, chromedp.Navigate(step.URL))
	tasks = append(tasks, chromedp.Sleep(1*time.Second))

	// Fill form fields
	for field, value := range formData {
		// Try multiple selectors
		selectors := []string{
			fmt.Sprintf(`input[name="%s"]`, field),
			fmt.Sprintf(`#%s`, field),
			fmt.Sprintf(`input[id="%s"]`, field),
		}

		for _, sel := range selectors {
			tasks = append(tasks, chromedp.SetValue(sel, value, chromedp.ByQuery))
		}
	}

	// Submit form - try form submit first, then button click
	tasks = append(tasks,
		chromedp.Evaluate(`
			var form = document.querySelector('form');
			if (form) { 
				form.submit(); 
			} else { 
				var btn = document.querySelector('button[type="submit"]') || document.querySelector('input[type="submit"]');
				if (btn) btn.click();
			}
		`, nil),
		chromedp.Sleep(2*time.Second),
		chromedp.OuterHTML("html", &pageBody),
		chromedp.Evaluate(`JSON.stringify(document.cookie.split('; ').map(c => { var p = c.split('='); return {name: p[0], value: p.slice(1).join('=')}; }))`, &cookieJSON),
	)

	err := chromedp.Run(browserCtx, tasks...)
	if err != nil {
		return nil, fmt.Errorf("browser step failed: %w", err)
	}

	result.Body = pageBody

	// Parse cookies
	if cookieJSON != "" {
		var cookies []map[string]string
		if err := json.Unmarshal([]byte(cookieJSON), &cookies); err == nil {
			for _, c := range cookies {
				if name, ok := c["name"]; ok {
					if value, ok := c["value"]; ok {
						result.Cookies[name] = value
					}
				}
			}
		}
	}

	return result, nil
}

// extractToken extracts a token from the step result based on the extractor configuration
func (af *AuthFlow) extractToken(result *StepResult, extractor TokenExtractor) (string, error) {
	switch extractor.Type {
	case "cookie":
		if val, ok := result.Cookies[extractor.Pattern]; ok {
			return val, nil
		}
		return "", fmt.Errorf("cookie %s not found", extractor.Pattern)

	case "header":
		if val, ok := result.Headers[extractor.Pattern]; ok {
			return val, nil
		}
		return "", fmt.Errorf("header %s not found", extractor.Pattern)

	case "regex":
		re, err := regexp.Compile(extractor.Pattern)
		if err != nil {
			return "", fmt.Errorf("invalid regex: %w", err)
		}
		matches := re.FindStringSubmatch(result.Body)
		if len(matches) > 1 {
			return matches[1], nil
		}
		return "", fmt.Errorf("regex pattern not matched")

	case "json":
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(result.Body), &data); err != nil {
			return "", fmt.Errorf("invalid JSON: %w", err)
		}
		// Simple JSONPath support (dot notation)
		keys := strings.Split(extractor.Pattern, ".")
		var current interface{} = data
		for _, key := range keys {
			if m, ok := current.(map[string]interface{}); ok {
				current = m[key]
			} else {
				return "", fmt.Errorf("key %s not found in JSON", key)
			}
		}
		return fmt.Sprintf("%v", current), nil

	case "input":
		// Extract value from HTML input field
		pattern := fmt.Sprintf(`<input[^>]*name=["]?%s["]?[^>]*value=["]?([^">]+)`, regexp.QuoteMeta(extractor.Pattern))
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(result.Body)
		if len(matches) > 1 {
			return matches[1], nil
		}
		return "", fmt.Errorf("input field %s not found", extractor.Pattern)

	default:
		return "", fmt.Errorf("unknown extractor type: %s", extractor.Type)
	}
}

// interpolateTokens replaces {{token_name}} placeholders with actual token values
func (af *AuthFlow) interpolateTokens(data map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range data {
		// Replace {{token}} with actual values
		for tokenName, tokenValue := range af.Tokens {
			placeholder := fmt.Sprintf("{{%s}}", tokenName)
			v = strings.ReplaceAll(v, placeholder, tokenValue)
		}
		result[k] = v
	}
	return result
}

// StepResult holds the result of a single authentication step
type StepResult struct {
	StatusCode int
	Body       string
	Cookies    map[string]string
	Headers    map[string]string
}

// AuthResult holds the complete result of an authentication flow
type AuthResult struct {
	Success bool
	Steps   []StepResult
	Cookies map[string]string
	Headers map[string]string
	Tokens  map[string]string
}

// ToCookieHeader formats cookies as an HTTP Cookie header value
func (ar *AuthResult) ToCookieHeader() string {
	var parts []string
	for name, value := range ar.Cookies {
		parts = append(parts, fmt.Sprintf("%s=%s", name, value))
	}
	return strings.Join(parts, "; ")
}
