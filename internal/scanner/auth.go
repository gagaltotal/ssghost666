package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// CheckCookieFlags inspects every Set-Cookie header seen during crawling
// for missing Secure/HttpOnly/SameSite attributes. Session-looking cookie
// names (session, auth, token, sid, ...) are flagged Medium; others Low,
// since a missing flag on a pure preference cookie is a much smaller deal
// than on a session cookie.
func CheckCookieFlags(captured []model.CapturedResponse) []model.Finding {
	var findings []model.Finding
	seen := map[string]bool{} // dedupe by cookie name, first sighting wins
	for _, cr := range captured {
		for _, raw := range cr.Cookies {
			name := strings.SplitN(raw, "=", 2)[0]
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true

			lower := strings.ToLower(raw)
			var missing []string
			if !strings.Contains(lower, "secure") {
				missing = append(missing, "Secure")
			}
			if !strings.Contains(lower, "httponly") {
				missing = append(missing, "HttpOnly")
			}
			if !strings.Contains(lower, "samesite") {
				missing = append(missing, "SameSite")
			}
			if len(missing) == 0 {
				continue
			}

			sev := model.SeverityLow
			if looksLikeSessionCookie(name) {
				sev = model.SeverityMedium
			}
			findings = append(findings, model.Finding{
				Category:    "Auth / Session",
				Severity:    sev,
				Title:       fmt.Sprintf("Cookie %q missing %s", name, strings.Join(missing, ", ")),
				Description: "A cookie was set without one or more recommended security attributes. Missing HttpOnly lets client-side JS (e.g. via XSS) read the cookie; missing Secure allows it over plain HTTP; missing SameSite weakens CSRF protection.",
				URL:         cr.URL,
				Method:      cr.Method,
				Parameter:   name,
				Evidence:    model.Evidence{ResponseRaw: raw, RequestRaw: cr.RequestRaw},
				Remediation: "Set Secure, HttpOnly, and an explicit SameSite (Lax or Strict) on session/auth cookies.",
			})
		}
	}
	return findings
}

func looksLikeSessionCookie(name string) bool {
	low := strings.ToLower(name)
	for _, h := range []string{"sess", "auth", "token", "sid", "login", "jwt", "csrf"} {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// CheckCORS probes a target with an attacker-controlled Origin header and
// flags reflected-origin-plus-credentials, the classic CORS
// misconfiguration that lets any website read authenticated responses.
func CheckCORS(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target) []model.Finding {
	if !lim.Acquire(ctx) {
		return nil
	}
	evilOrigin := "https://ssghost666-cors-check.invalid"
	ex := cli.Do(firstNonEmpty(t.Method, "GET"), t.URL, nil, map[string]string{"Origin": evilOrigin})
	lim.Release()
	if ex.Err != nil || ex.Response == nil {
		return nil
	}
	acao := ex.Response.Header.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(ex.Response.Header.Get("Access-Control-Allow-Credentials"), "true")
	if acao == evilOrigin && acac {
		return []model.Finding{{
			Category:    "Auth / Session",
			Severity:    model.SeverityHigh,
			Title:       "CORS misconfiguration: arbitrary origin allowed with credentials",
			Description: fmt.Sprintf("Sending Origin: %s got back Access-Control-Allow-Origin: %s together with Access-Control-Allow-Credentials: true. Any website can make a credentialed request on behalf of a logged-in user and read the response.", evilOrigin, acao),
			URL:         t.URL,
			Method:      t.Method,
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw},
			Remediation: "Only reflect an Origin from an explicit allowlist, and never combine a reflected/wildcard origin with Access-Control-Allow-Credentials: true.",
		}}
	}
	if acao == "*" && acac {
		// Non-compliant combination browsers reject, but still worth a
		// low-severity note since it signals a misunderstanding of CORS.
		return []model.Finding{{
			Category:    "Auth / Session",
			Severity:    model.SeverityLow,
			Title:       "CORS: wildcard origin combined with Allow-Credentials",
			Description: "Access-Control-Allow-Origin: * was sent together with Access-Control-Allow-Credentials: true. Browsers ignore the credentials flag in this combination, but it signals the CORS policy wasn't deliberately configured.",
			URL:         t.URL,
			Method:      t.Method,
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw},
			Remediation: "Use an explicit origin allowlist rather than *, especially on any endpoint that also sets Allow-Credentials.",
		}}
	}
	return nil
}

// CheckBrokenAccessControl re-sends a target with no credentials at all
// and compares it to the authenticated baseline. A near-identical
// response with a 2xx status suggests the endpoint doesn't actually
// enforce authentication. Only meaningful (and only run by the engine)
// when the scan itself is authenticated, i.e. -cookie or -bearer was set.
func CheckBrokenAccessControl(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, baseline *httpclient.Exchange) []model.Finding {
	if baseline == nil || baseline.Response == nil || baseline.Response.StatusCode < 200 || baseline.Response.StatusCode >= 300 {
		return nil // baseline itself wasn't a successful authenticated response; nothing to compare
	}
	if !looksAuthWorthy(t, baseline) {
		// Most pages on a normally-authenticated scan (the homepage, a
		// search form, a product page) are *meant* to work without
		// credentials too — that's not broken access control, it's a
		// public page. Flagging every one of those would bury the real
		// signal in noise, so this only runs where there's a concrete
		// reason to expect auth was supposed to matter.
		return nil
	}
	if !lim.Acquire(ctx) {
		return nil
	}
	unauth := cli.DoWithoutAuth(firstNonEmpty(t.Method, "GET"), t.URL, nil)
	lim.Release()
	if unauth.Err != nil || unauth.Response == nil {
		return nil
	}
	if unauth.Response.StatusCode < 200 || unauth.Response.StatusCode >= 300 {
		return nil // correctly rejected
	}
	lenRatio := similarLength(len(baseline.Body), len(unauth.Body))
	if lenRatio < 0.8 {
		return nil // bodies differ enough that this is probably a different (e.g. generic/public) page, not the same protected data
	}
	return []model.Finding{{
		Category:    "Auth / Session",
		Severity:    model.SeverityHigh,
		Title:       "Possible broken access control / missing authentication check",
		Description: fmt.Sprintf("Removing all credentials still returned HTTP %d with a response body about the same size as the authenticated one (%d vs %d bytes). The endpoint may not actually be checking authentication/authorization.", unauth.Response.StatusCode, len(unauth.Body), len(baseline.Body)),
		URL:         t.URL,
		Method:      t.Method,
		Evidence:    model.Evidence{RequestRaw: unauth.RequestRaw, ResponseRaw: unauth.ResponseRaw, Notes: "Compare against the authenticated baseline response captured for this target."},
		Remediation: "Confirm this endpoint requires authentication/authorization server-side for every request, not just when a session happens to be absent client-side.",
	}}
}

// authSensitivePathHints are path keywords rarely used for pages that are
// legitimately public — deliberately narrower than ssrfParamHints-style
// lists, since a false positive here is a whole noisy finding, not just
// an extra request.
var authSensitivePathHints = []string{"admin", "internal", "private", "dashboard", "account-settings", "billing"}

// looksAuthWorthy decides whether a target is worth the broken-access-
// -control check at all. The strongest signal is explicit: the OpenAPI
// doc said this operation needs auth, or the response is API-shaped
// (JSON/XML) rather than a normal browsable HTML page — real sensitive
// data overwhelmingly lives behind API responses, not static markup. A
// narrow path-keyword list catches the rest (an HTML admin panel, say).
func looksAuthWorthy(t model.Target, baseline *httpclient.Exchange) bool {
	if t.RequiresAuth {
		return true
	}
	if baseline != nil && baseline.Response != nil {
		ct := baseline.Response.Header.Get("Content-Type")
		if strings.Contains(ct, "json") || strings.Contains(ct, "xml") {
			return true
		}
	}
	low := strings.ToLower(t.URL)
	for _, h := range authSensitivePathHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

func similarLength(a, b int) float64 {
	if a == 0 && b == 0 {
		return 1
	}
	max := a
	if b > max {
		max = b
	}
	if max == 0 {
		return 1
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	return 1 - float64(diff)/float64(max)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// DecodeJWT decodes (without verifying) a bearer token that looks like a
// JWT and flags structurally risky configurations. This only reads a
// token the user themselves supplied via -bearer for their own
// authenticated session — it does not attempt to forge, crack or bypass
// anything with it.
func DecodeJWT(token string) []model.Finding {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	headerJSON, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payloadJSON, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return nil
	}
	var header, payload map[string]interface{}
	if json.Unmarshal(headerJSON, &header) != nil || json.Unmarshal(payloadJSON, &payload) != nil {
		return nil
	}

	notes := fmt.Sprintf("header: %s\npayload: %s", string(headerJSON), string(payloadJSON))
	alg, _ := header["alg"].(string)

	if strings.EqualFold(alg, "none") {
		return []model.Finding{{
			Category:    "Auth / Session",
			Severity:    model.SeverityCritical,
			Title:       "Bearer token is a JWT using alg=\"none\"",
			Description: "The supplied JWT's header declares alg=\"none\", meaning the token carries no signature at all. If the server actually accepts tokens like this, anyone can forge arbitrary claims.",
			Evidence:    model.Evidence{Notes: notes},
			Remediation: "Reject alg=\"none\" tokens server-side and pin the expected signing algorithm explicitly rather than trusting the token's own \"alg\" header.",
		}}
	}

	var findings []model.Finding
	if _, hasExp := payload["exp"]; !hasExp {
		findings = append(findings, model.Finding{
			Category:    "Auth / Session",
			Severity:    model.SeverityLow,
			Title:       "Bearer JWT has no \"exp\" (expiry) claim",
			Description: "This token does not set an expiry, so — if the server doesn't enforce one some other way — it may remain valid indefinitely once issued.",
			Evidence:    model.Evidence{Notes: notes},
			Remediation: "Issue tokens with a reasonable \"exp\" claim and enforce it server-side.",
		})
	}
	return findings
}
