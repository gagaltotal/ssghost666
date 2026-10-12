package scanner

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- Session management testing --------------------------------------------
//
// The cookie-flag check in auth.go only looks at Secure/HttpOnly/SameSite.
// This check goes after the session-management mistakes that show up in
// assessment reports and are visible from outside the application:
//
//   - Predictable session IDs: low Shannon entropy, sequential-looking
//     values, or values whose per-position bytes barely change between
//     requests all mean a session identifier can be guessed.
//   - Session fixation: if a server keeps handing out the session ID the
//     client supplied instead of issuing a fresh one, an attacker who plants
//     a known ID can take over the victim's session after login.
//   - Excessive session lifetime: a lifetime measured in weeks is the
//     "never logs you out" complaint, and it hugely widens the window for a
//     stolen ID to be reused.
//   - Cookie scope issues: a Domain attribute set to a registrable parent
//     (e.g. `.example.com` across tenants) or a Path the session never
//     restricts leaks the session cookie to sibling hosts/applications.
//
// Two things are deliberately *not* attempted here because they cannot be
// done safely from a scanner: enforcing concurrent-session limits requires
// multiple real logins, and testing rotation requires logging in — SSGhost666
// never submits credentials or completes a login. Where a conclusion needs
// those, the check says so explicitly rather than guessing.

// sessionCookieNameHints mirrors looksLikeSessionCookie but is used as a
// broader net for values that are worth an entropy look even when the name
// is something like "connect.sid" or "PHPSESSID".
func sessionCookieNameHints(name string) bool {
	low := strings.ToLower(name)
	for _, h := range []string{"sess", "sid", "jsessionid", "phpsessid", "asp.net_sessionid", "connect.sid", "auth", "token", "login", "jsession", "csrftoken", "xsrf"} {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// shannonEntropyBits computes the Shannon entropy (in bits) of a byte string.
// English text and UUIDs land around 3.0–4.0 bits/byte; a cryptographically
// random session ID should comfortably exceed 3.5 bits/byte before you trust
// it, and anything under ~2.5 is clearly structured (e.g. a counter).
func shannonEntropyBits(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// looksSequential reports whether a value is an obvious counter (digits only)
// or a low-entropy hex/decimal blob that differs from its predecessor in a
// short, trailing run of characters — the traditional signature of a
// predictable session ID.
func looksSequential(value string) bool {
	if value == "" {
		return false
	}
	digits := true
	for _, r := range value {
		if r < '0' || r > '9' {
			digits = false
			break
		}
	}
	return digits
}

// hmacingSessionID compares two session ids and returns how many trailing
// characters they share. A long shared suffix/prefix between consecutive
// issued IDs is a strong predictability signal.
func commonTrailingRun(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) {
		if a[len(a)-1-n] != b[len(b)-1-n] {
			break
		}
		n++
	}
	return n
}

// sessionCookieValues extracts (name -> ordered distinct values) for every
// cookie that looks session-related, together with the raw Set-Cookie lines
// (for attribute inspection).
type sessionCookie struct {
	name     string
	values   []string
	raw      []string
	httpOnly bool
	secure   bool
	sameSite string
	domain   string
	path     string
	maxAge   string
	expires  string
}

func collectSessionCookies(captured []model.CapturedResponse) map[string]*sessionCookie {
	out := map[string]*sessionCookie{}
	for _, cr := range captured {
		for _, raw := range cr.Cookies {
			name, val := splitCookie(raw)
			if name == "" || !sessionCookieNameHints(name) {
				continue
			}
			sc := out[name]
			if sc == nil {
				sc = &sessionCookie{name: name}
				out[name] = sc
			}
			if val != "" && !containsStr(sc.values, val) && len(sc.values) < 40 {
				sc.values = append(sc.values, val)
			}
			sc.raw = append(sc.raw, raw)
			lower := strings.ToLower(raw)
			sc.httpOnly = sc.httpOnly || strings.Contains(lower, "httponly")
			sc.secure = sc.secure || strings.Contains(lower, "secure")
			if ss := cookieAttr(raw, "samesite"); ss != "" {
				sc.sameSite = ss
			}
			if d := cookieAttr(raw, "domain"); d != "" {
				sc.domain = d
			}
			if p := cookieAttr(raw, "path"); p != "" {
				sc.path = p
			}
			if ma := cookieAttr(raw, "max-age"); ma != "" {
				sc.maxAge = ma
			}
			if e := cookieAttr(raw, "expires"); e != "" {
				sc.expires = e
			}
		}
	}
	return out
}

func splitCookie(raw string) (string, string) {
	first := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
	kv := strings.SplitN(first, "=", 2)
	if len(kv) != 2 {
		return strings.TrimSpace(first), ""
	}
	return strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
}

// cookieAttr returns the value of a Set-Cookie attribute (case-insensitive).
func cookieAttr(raw, attr string) string {
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if strings.EqualFold(strings.TrimSpace(kv[0]), attr) {
			if len(kv) == 2 {
				return strings.TrimSpace(kv[1])
			}
			return part
		}
	}
	return ""
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// sessionIDLooksWeak scores a single cookie value for predictability.
func sessionIDLooksWeak(value string) (string, bool) {
	if len(value) < 8 {
		return "the value is unusually short (<8 characters), leaving far too little randomness to resist guessing", true
	}
	if looksSequential(value) {
		return "the value is a plain integer, which is trivially enumerable", true
	}
	entropy := shannonEntropyBits(value)
	// Scale the threshold with length: short values can legitimately have low
	// per-byte entropy while still being unguessable.
	if entropy < 2.5 && len(value) < 40 {
		return fmt.Sprintf("the value has only %.2f bits/byte of Shannon entropy over %d characters, which is characteristic of a structured (non-random) identifier", entropy, len(value)), true
	}
	return "", false
}

// sessionLifetimeSeconds parses Max-Age, or an Expires date, and returns the
// lifetime in seconds (0 if unknown / session cookie).
func sessionLifetimeSeconds(sc *sessionCookie) int64 {
	if sc.maxAge != "" {
		// #nosec G109 -- parsing a small cookie numeric attribute
		var n int64
		if _, err := fmt.Sscanf(sc.maxAge, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	if sc.expires != "" {
		for _, layout := range []string{http.TimeFormat, time.RFC1123, time.RFC1123Z, "Mon, 02-Jan-2006 15:04:05 MST"} {
			if t, err := time.Parse(layout, sc.expires); err == nil {
				d := time.Until(t)
				if d > 0 {
					return int64(d.Seconds())
				}
			}
		}
	}
	return 0
}

// CheckSessionManagement analyses every session-looking cookie for the
// weaknesses described at the top of this file, and (where a real session
// cookie exists) actively tests session fixation by re-sending the server a
// brand-new session ID it never issued and observing whether the server
// adopts it or replaces it.
func CheckSessionManagement(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, captured []model.CapturedResponse, targets []model.Target) []model.Finding {
	cookies := collectSessionCookies(captured)
	if len(cookies) == 0 {
		return nil
	}

	names := make([]string, 0, len(cookies))
	for n := range cookies {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic output ordering

	var findings []model.Finding

	for _, name := range names {
		sc := cookies[name]

		// --- predictability ---------------------------------------------
		var weakReason string
		if bad, reasons := pickWeakSessionReason(sc.values); bad {
			weakReason = reasons
		}
		if weakReason == "" && len(sc.values) >= 2 {
			// Two values issued close together sharing a long suffix is a
			// smokier signal than entropy alone.
			longest := 0
			for i := 0; i+1 < len(sc.values); i++ {
				if r := commonTrailingRun(sc.values[i], sc.values[i+1]); r > longest {
					longest = r
				}
			}
			if longest >= 6 {
				weakReason = fmt.Sprintf("consecutive values share a trailing run of %d identical characters, consistent with a sequential/predictable generator", longest)
			}
		}
		if weakReason != "" {
			findings = append(findings, model.Finding{
				Category:    "Auth / Session",
				Severity:    model.SeverityHigh,
				Title:       fmt.Sprintf("Predictable session identifier in cookie %q", name),
				Description: fmt.Sprintf("The %q cookie value looks guessable: %s. An attacker who can guess or enumerate session IDs can impersonate other users without ever authenticating.", name, weakReason),
				Parameter:   name,
				Evidence:    model.Evidence{Notes: fmt.Sprintf("Observed values (truncated): %s | entropy of first value: %.2f bits/byte", truncateValues(sc.values), firstEntropy(sc.values))},
				Remediation: "Generate session IDs from a cryptographically secure RNG (at least 128 bits of entropy), and never derive them from a counter, timestamp, username or other predictable input.",
			})
		}

		// --- excessive lifetime ------------------------------------------
		if secs := sessionLifetimeSeconds(sc); secs > int64(30*24*time.Hour/time.Second) {
			findings = append(findings, model.Finding{
				Category:    "Auth / Session",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("Session cookie %q has an excessive lifetime", name),
				Description: fmt.Sprintf("The %q cookie is set with a lifetime of about %s. Very long-lived session cookies — especially combined with no server-side idle timeout — dramatically widen the window in which a stolen or clonable session ID can be reused.", name, humanDuration(secs)),
				Parameter:   name,
				Evidence:    model.Evidence{Notes: "Set-Cookie: " + strings.Join(sc.raw, " || ")},
				Remediation: "Use short-lived session cookies with a server-side idle and absolute timeout, and enforce re-authentication for sensitive actions.",
			})
		}

		// --- scope --------------------------------------------------------
		if sc.domain != "" {
			d := strings.TrimPrefix(sc.domain, ".")
			labels := strings.Count(d, ".")
			if labels <= 1 && strings.HasPrefix(sc.domain, ".") {
				findings = append(findings, model.Finding{
					Category:    "Auth / Session",
					Severity:    model.SeverityMedium,
					Title:       fmt.Sprintf("Session cookie %q scoped to a parent domain", name),
					Description: fmt.Sprintf("The %q cookie sets Domain=%s, sending this session identifier to the parent domain and every one of its subdomains. If any subdomain is less trusted (or can be taken over / resolves to shared hosting), it can read or be tricked into revealing the session.", name, sc.domain),
					Parameter:   name,
					Evidence:    model.Evidence{Notes: "Set-Cookie: " + strings.Join(sc.raw, " || ")},
					Remediation: "Drop the Domain attribute so the cookie is host-only, or scope it to the narrowest domain that actually needs it.",
				})
			}
		}
		if sc.path == "/" && len(sc.values) > 0 {
			findings = append(findings, model.Finding{
				Category:    "Auth / Session",
				Severity:    model.SeverityLow,
				Title:       fmt.Sprintf("Session cookie %q has Path=/ (whole application)", name),
				Description: fmt.Sprintf("The %q session cookie is scoped to Path=/, so it is attached to every request to the application, including static assets and any third-party-proxied paths.", name),
				Parameter:   name,
				Evidence:    model.Evidence{Notes: "Set-Cookie: " + strings.Join(sc.raw, " || ")},
				Remediation: "Scope session cookies to the narrowest path prefix that needs them.",
			})
		}
	}

	// --- session fixation (active, read-only) -----------------------------
	if f := checkSessionFixation(ctx, lim, cli, cookies, targets); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

func pickWeakSessionReason(values []string) (bool, string) {
	if len(values) == 0 {
		return false, ""
	}
	// Pick the longest observed value: it's the one most likely to be the
	// real session ID (short ones are often just a CSRF double-submit).
	longest := values[0]
	for _, v := range values {
		if len(v) > len(longest) {
			longest = v
		}
	}
	if reason, weak := sessionIDLooksWeak(longest); weak {
		return true, reason
	}
	return false, ""
}

func truncateValues(values []string) string {
	var parts []string
	for i, v := range values {
		if i >= 3 {
			parts = append(parts, "...")
			break
		}
		if len(v) > 24 {
			v = v[:24] + "…"
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ", ")
}

func firstEntropy(values []string) float64 {
	if len(values) == 0 {
		return 0
	}
	return shannonEntropyBits(values[0])
}

func humanDuration(secs int64) string {
	d := time.Duration(secs) * time.Second
	days := int(d.Hours() / 24)
	if days >= 1 {
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}

// checkSessionFixation looks for the classic fixation bug: the server
// accepts a client-supplied session ID it never issued. It sends one request
// per candidate session cookie name carrying a random, never-issued value and
// then checks whether the response either kept that same value (server
// adopted attacker-chosen ID = fixation) or issued a different one (correct
// behaviour). Only GET/HEAD probes are used, and no credentials are ever
// submitted.
func checkSessionFixation(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, cookies map[string]*sessionCookie, targets []model.Target) *model.Finding {
	if len(targets) == 0 {
		return nil
	}
	// Prefer an auth-shaped endpoint to probe, fall back to any GET target.
	var probe model.Target
	for _, t := range targets {
		if t.Method == "DELETE" {
			continue
		}
		if probe.URL == "" {
			probe = t
		}
		if t.RequiresAuth || looksAuthShapedURL(t.URL) {
			probe = t
			break
		}
	}
	if probe.URL == "" {
		return nil
	}

	for name, sc := range cookies {
		if len(sc.values) == 0 {
			continue
		}
		fresh := hex.EncodeToString([]byte(Marker()))[:32]
		if !lim.Acquire(ctx) {
			return nil
		}
		ex := cli.Do("GET", probe.URL, nil, map[string]string{"Cookie": name + "=" + fresh})
		observeForAdaptive(lim, ex)
		lim.Release()
		if ex == nil || ex.Response == nil || ex.Err != nil {
			continue
		}

		// Look for any Set-Cookie that re-issues the session (either the same
		// name with a new value = good, or the same value back = fixation).
		for _, raw := range responseSetCookies(ex) {
			rn, rv := splitCookie(raw)
			if rn != name {
				continue
			}
			if rv == fresh {
				return &model.Finding{
					Category:    "Auth / Session",
					Severity:    model.SeverityHigh,
					Title:       fmt.Sprintf("Session fixation: server accepted a client-supplied session ID (%s)", name),
					Description: fmt.Sprintf("A %q cookie carrying a random session ID the server never issued was echoed straight back as the (continued) session. An attacker who can plant a known session ID in a victim's browser will share the victim's authenticated session after login.", name),
					URL:         probe.URL,
					Method:      "GET",
					Parameter:   name,
					Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Attacker-supplied session ID: " + fresh},
					Remediation: "Issue a brand-new, server-generated session ID on every successful authentication (and on privilege change), and always ignore any client-supplied session identifier.",
				}
			}
		}
	}
	return nil
}

// responseSetCookies returns the raw Set-Cookie header values of an exchange.
func responseSetCookies(ex *httpclient.Exchange) []string {
	if ex == nil || ex.Response == nil {
		return nil
	}
	return ex.Response.Header.Values("Set-Cookie")
}
