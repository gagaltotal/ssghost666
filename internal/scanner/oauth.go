package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- OAuth 2.0 / OIDC flow testing -----------------------------------------
//
// Anything that looks like an authorization endpoint (a URL carrying
// client_id / redirect_uri / response_type, or a well-known authorize path)
// is probed for the handful of mistakes that break OAuth flows in practice:
//
//   - redirect_uri validation: an attacker-controlled redirect_uri that the
//     endpoint happily redirects to (or even just reflects) leaks
//     authorization codes to the attacker.
//   - Missing/weak `state`: if the endpoint issues an authorization code
//     without requiring state at all, the flow is open to login-CSRF.
//   - Missing PKCE: if the endpoint proceeds without code_challenge, public
//     clients (SPAs, mobile apps) can't rely on PKCE to stop code
//     interception.
//   - Token leakage: tokens/codes surfacing in the URL fragment or in a
//     Referer-able location.
//
// The probes are read-only GETs against the authorization endpoint. SSGhost666
// deliberately never exchanges an authorization code for a token, never
// submits credentials and never completes a login: the goal is to observe
// how the endpoint *validates its inputs*, not to obtain real access.

// oauthAuthorizeHints are path fragments that strongly suggest an OAuth/OIDC
// authorization endpoint.
var oauthAuthorizeHints = []string{
	"/oauth/authorize", "/oauth2/authorize", "/authorize", "/oidc/authorize",
	"/connect/authorize", "/oauth/authorize/", "/openid-connect/auth",
	"/as/authorization", "/authorization", "/oauth2/auth", "/auth/authorize",
}

// oauthParamHints are query parameters only an OAuth/OIDC endpoint uses.
var oauthParamHints = []string{"redirect_uri", "response_type", "client_id", "code_challenge", "scope"}

// oauthCandidate is one discovered authorization endpoint plus the params it
// already carried when we found it.
type oauthCandidate struct {
	base  *url.URL
	query url.Values
	url   string
}

// findOAuthEndpoints scans every discovered target URL for authorization
// endpoints, generalising the query so a candidate can be re-probed with
// substituted values.
func findOAuthEndpoints(targets []model.Target) []oauthCandidate {
	seen := map[string]bool{}
	var out []oauthCandidate
	for _, t := range targets {
		u, err := url.Parse(t.URL)
		if err != nil || u.Host == "" {
			continue
		}
		q := u.Query()
		hasOAuthParam := false
		for _, h := range oauthParamHints {
			if q.Get(h) != "" {
				hasOAuthParam = true
				break
			}
		}
		pathHit := false
		lowPath := strings.ToLower(u.Path)
		for _, h := range oauthAuthorizeHints {
			if strings.Contains(lowPath, h) {
				pathHit = true
				break
			}
		}
		if !hasOAuthParam && !pathHit {
			continue
		}
		key := u.Scheme + "://" + u.Host + u.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, oauthCandidate{base: u, query: q, url: t.URL})
		if len(out) >= 5 {
			break // a service has very few authorization endpoints; more than this is noise
		}
	}
	return out
}

// oauthRequest issues one authorization-endpoint request with the given
// query overrides applied, without following any redirect.
func oauthRequest(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, c oauthCandidate, overrides map[string]string) *httpclient.Exchange {
	if !lim.Acquire(ctx) {
		return nil
	}
	defer lim.Release()

	u := *c.base
	q := url.Values{}
	for k, vs := range c.query {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	for k, v := range overrides {
		if v == "" {
			q.Del(k)
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	ex := cli.Do("GET", u.String(), nil, nil)
	observeForAdaptive(lim, ex)
	return ex
}

// oauthRedirectTarget extracts the Location a response points at, if any.
func oauthRedirectTarget(ex *httpclient.Exchange) string {
	if ex == nil || ex.Response == nil {
		return ""
	}
	return ex.Response.Header.Get("Location")
}

// oauthLooksLikeLoginPage decides whether the endpoint answered with a login
// / consent screen (meaning it can't be judged for redirect_uri behaviour
// because it never got as far as validating the request).
func oauthLooksLikeLoginPage(ex *httpclient.Exchange) bool {
	if ex == nil || ex.Response == nil {
		return true
	}
	if ex.Response.StatusCode >= 300 && ex.Response.StatusCode < 400 {
		return false // a redirect means the request was processed
	}
	body := strings.ToLower(ex.Body)
	for _, h := range []string{"sign in", "signin", "log in", "login", "password", "consent", "authorize this application", "grant access"} {
		if strings.Contains(body, h) {
			return true
		}
	}
	return false
}

// CheckOAuthOIDC probes discovered OAuth/OIDC authorization endpoints for the
// misconfigurations described at the top of this file.
func CheckOAuthOIDC(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, targets []model.Target) []model.Finding {
	candidates := findOAuthEndpoints(targets)
	if len(candidates) == 0 {
		return nil
	}

	// An attacker-controlled origin we never actually resolve: we only ever
	// look at where the server *wants* to send the browser.
	const evil = "https://ssghost666-oauth-check.invalid"

	var findings []model.Finding
	for _, c := range candidates {
		original := c.query.Get("redirect_uri")
		if original == "" {
			original = c.query.Get("redirect_url")
		}
		if original == "" {
			continue // without a redirect_uri there is nothing to validate
		}

		baseline := oauthRequest(ctx, lim, cli, c, nil)
		if oauthLooksLikeLoginPage(baseline) {
			// The endpoint demands a session before validating anything, so
			// redirect_uri behaviour can't be observed without logging in —
			// which SSGhost666 never does.
			continue
		}

		// --- redirect_uri validation ------------------------------------
		for _, probe := range redirectURIBypasses(original, evil) {
			ex := oauthRequest(ctx, lim, cli, c, map[string]string{"redirect_uri": probe.value})
			if ex == nil || ex.Response == nil || ex.Err != nil {
				continue
			}
			loc := oauthRedirectTarget(ex)
			if loc == "" {
				// Some servers reflect the *unvalidated* redirect_uri into
				// the body instead of a Location header; that's still a
				// weakened-validation signal worth keeping.
				if strings.Contains(ex.Body, evil) {
					findings = append(findings, model.Finding{
						Category:    "OAuth/OIDC",
						Severity:    model.SeverityHigh,
						Title:       "OAuth redirect_uri reflected without validation",
						Description: fmt.Sprintf("The authorization endpoint echoed the attacker-controlled redirect_uri (%s) back into the response body (%s variant). If this value is later used to deliver the authorization code/token, codes can be stolen.", evil, probe.label),
						URL:         c.url,
						Method:      "GET",
						Parameter:   "redirect_uri",
						Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Probe variant: " + probe.label + " | original redirect_uri: " + original},
						Remediation: "Validate redirect_uri server-side against an exact-match allowlist registered for the client; never reflect it into output or use a client-supplied value directly as a redirect target.",
					})
					break
				}
				continue
			}
			if oauthRedirectPointsAt(loc, evil) {
				findings = append(findings, model.Finding{
					Category:    "OAuth/OIDC",
					Severity:    model.SeverityCritical,
					Title:       "OAuth redirect_uri validation bypass (attacker-controlled redirect accepted)",
					Description: fmt.Sprintf("The authorization endpoint accepted a redirect_uri (%s, via the %s technique) that resolves to an attacker-controlled host and answered with a redirect there. An authorization code delivered to this URL hands the attacker full access to the victim's account.", probe.value, probe.label),
					URL:         c.url,
					Method:      "GET",
					Parameter:   "redirect_uri",
					Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("Probe variant: %s | forged redirect_uri: %s | original: %s", probe.label, probe.value, original)},
					Remediation: "Require redirect_uri to exactly match a pre-registered value (full string comparison, no prefix/substring/`@`/subdomain matching), and reject anything else before issuing a code.",
				})
				break
			}
		}
		if len(findings) > 0 {
			continue // one confirmed redirect_uri problem per endpoint is enough
		}

		// --- missing `state` (login CSRF) --------------------------------
		if c.query.Get("state") == "" {
			ex := oauthRequest(ctx, lim, cli, c, map[string]string{"state": "", "response_type": "code"})
			if ex != nil && ex.Response != nil {
				loc := oauthRedirectTarget(ex)
				codeIssued := loc != "" && (strings.Contains(loc, "code=") || strings.Contains(loc, "?code") || strings.Contains(loc, "&code"))
				if codeIssued {
					findings = append(findings, model.Finding{
						Category:    "OAuth/OIDC",
						Severity:    model.SeverityMedium,
						Title:       "OAuth authorization endpoint issues codes without requiring `state`",
						Description: fmt.Sprintf("Requesting an authorization code with no state parameter was accepted (the endpoint redirected to %q carrying a code). Without a mandated state (or PKCE) the flow is open to login-CSRF / code-injection attacks.", loc),
						URL:         c.url,
						Method:      "GET",
						Parameter:   "state",
						Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Probe omitted the state parameter entirely."},
						Remediation: "Require and validate a cryptographically random per-session state parameter, and reject authorization requests that omit it.",
					})
				}
			}
		}

		// --- missing PKCE -------------------------------------------------
		if c.query.Get("code_challenge") == "" {
			ex := oauthRequest(ctx, lim, cli, c, map[string]string{"response_type": "code", "code_challenge": ""})
			if ex != nil && ex.Response != nil {
				loc := oauthRedirectTarget(ex)
				codeIssued := loc != "" && strings.Contains(loc, "code=")
				if codeIssued {
					findings = append(findings, model.Finding{
						Category:    "OAuth/OIDC",
						Severity:    model.SeverityLow,
						Title:       "OAuth authorization endpoint does not require PKCE",
						Description: "An authorization code was issued without any code_challenge value, so the endpoint does not enforce Proof Key for Code Exchange. Public clients (SPAs, mobile/desktop apps) then rely only on redirect_uri validation to prevent authorization-code interception.",
						URL:         c.url,
						Method:      "GET",
						Parameter:   "code_challenge",
						Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Probe omitted code_challenge."},
						Remediation: "Require PKCE (S256) for public clients and preferably for confidential clients too, and reject authorization requests without a code_challenge.",
					})
				}
			}
		}
	}

	return dedupeOAuthFindings(findings)
}

// redirectURIBypass is one way of trying to sneak an attacker host past
// redirect_uri validation.
type redirectURIBypass struct {
	label string
	value string
}

// redirectURIBypasses builds the classic redirect_uri validation-bypass
// payloads around an observed redirect_uri. They are ordered from the most
// reliable technique to the most situational.
func redirectURIBypasses(original, evil string) []redirectURIBypass {
	orig, err := url.Parse(original)
	if err != nil {
		return nil
	}
	evilHost := strings.TrimPrefix(strings.TrimPrefix(evil, "https://"), "http://")
	// Host of the legitimate redirect (sans a leading "."), for subdomain tricks.
	legitHost := strings.TrimPrefix(orig.Hostname(), ".")

	return []redirectURIBypass{
		{"full replacement", evil},
		{"full replacement with code path", evil + "/callback"},
		{"suffix append (attacker as path)", strings.TrimRight(original, "/") + "/" + evilHost},
		{"suffix append with @ separator", strings.TrimRight(original, "/") + "@" + evilHost},
		{"userinfo @ trick", "https://" + evilHost + "@" + legitHost + "/callback"},
		{"subdomain of attacker as parent", "https://" + legitHost + "." + evilHost + "/callback"},
		{"scheme-relative (//)", "//" + evilHost + "/callback"},
		{"backslash separator", "https://" + legitHost + "\\@" + evilHost},
		{"path traversal escape", strings.TrimRight(original, "/") + "/../" + evilHost},
		{"localhost confusion", "http://" + evilHost + ":" + orig.Port() + "/callback"},
	}
}

// oauthRedirectPointsAt reports whether a Location header actually sends the
// browser to our attacker host — using the URL parser rather than a naive
// substring test so the `@`-in-userinfo and `//`-scheme-relative tricks are
// judged the way a browser would treat them.
func oauthRedirectPointsAt(location, evil string) bool {
	evilHost := strings.TrimPrefix(strings.TrimPrefix(evil, "https://"), "http://")

	loc := strings.TrimSpace(location)
	if loc == "" {
		return false
	}
	// Try as absolute first, then as scheme-relative (//host/...).
	var u *url.URL
	var err error
	if strings.HasPrefix(loc, "//") {
		u, err = url.Parse("https:" + loc)
	} else {
		u, err = url.Parse(loc)
	}
	if err == nil && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		return host == evilHost || strings.HasSuffix(host, "."+evilHost)
	}
	return strings.Contains(strings.ToLower(loc), evilHost)
}

func dedupeOAuthFindings(in []model.Finding) []model.Finding {
	seen := map[string]bool{}
	var out []model.Finding
	for _, f := range in {
		key := f.Title + "|" + f.URL + "|" + f.Parameter
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}
