package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- Context-aware fuzzing --------------------------------------------------
//
// Every other active check fuzzes a parameter with one fixed payload set
// that is blind to what the parameter actually means: a parameter called
// "email" and one called "file" both get handed the same XSS/SQLi probes.
// Context-aware fuzzing adds a thin semantic layer on top of that. It reads
// the *name* (and, where useful, the baseline *sample* value) of each
// parameter, infers what kind of input that parameter most plausibly
// accepts, and then sends only the probes that make sense for that kind:
//
//   - "file"/"path"/"download"/"image"... → path-traversal probes
//     (../../../../etc/passwd), confirmed by matching real file content.
//   - "id"/"uid"/"user_id"/"order"... (numeric baseline) → IDOR /
//     forced-browsing probes against neighbouring object ids, confirmed
//     against a deliberately-absent id so a catch-all endpoint can't
//     produce a false positive.
//   - "email"/"mail"/"recipient"... → email/header (CRLF) injection
//     probes, confirmed against a benign control address.
//   - "redirect"/"next"/"return"/"url"... → open-redirect probes whose
//     Location is checked against a canary host.
//
// It deliberately does NOT try to be another XSS/SQLi/SSRF engine — those
// checks already run over every parameter. This module only contributes the
// context-specific probes that would otherwise never be sent, which both
// widens coverage (a "file" param now gets a traversal payload) and reduces
// noise (an "email" param is not blanketed with URL payloads it can never
// act on).
//
// Safety: context-aware fuzzing is an *enrichment* layer, so it only ever
// fires against GET/HEAD targets. A PUT/PATCH/DELETE (or any other
// mutating) target is left untouched, preserving the tool's
// non-destructive guarantee. Every probe here is read-only.

// ParamKind is the inferred semantic kind of a fuzzable parameter, which
// decides which context-specific payloads CheckContextAwareFuzzing sends.
type ParamKind string

const (
	ParamGeneric   ParamKind = "generic"
	ParamFilePath  ParamKind = "file-path"
	ParamNumericID ParamKind = "numeric-id"
	ParamEmail     ParamKind = "email"
	ParamRedirect  ParamKind = "redirect"
	ParamURL       ParamKind = "url"
)

// Parameter-name fragments that indicate each kind. Matching is done on
// separator/camelCase-split fragments (so "user_id" → {user,id} and
// "redirectUri" → {redirect,uri}), plus a few explicit compound forms for
// names that never get split (e.g. "filepath"). More specific kinds are
// listed first in ClassifyParam so that, for example, "file" wins over the
// generic URL bucket.
var (
	fileKindHints = []string{
		"file", "filename", "filepath", "fileurl", "file_name", "file_path",
		"path", "download", "upload", "attachment", "attach", "document",
		"doc", "template", "theme", "include", "resource", "asset", "dir",
		"directory", "folder", "img", "image", "photo", "picture", "avatar",
		"src",
	}
	emailKindHints = []string{
		"email", "mail", "mailto", "e-mail", "mailaddress", "mail_address",
		"emailaddress", "email_address", "recipient", "newsletter",
	}
	redirectKindHints = []string{
		"redirect", "redirecturi", "redirect_uri", "redirecturl", "redirect_url",
		"returnurl", "return_url", "returnto", "return_to", "next", "continue",
		"goto", "redir", "dest", "destination", "callbackurl", "callback_url",
		"forward", "forwardurl", "targeturl", "backurl",
	}
	urlKindHints = []string{
		"url", "uri", "link", "href", "host", "domain", "site", "endpoint",
		"webhook", "callback", "proxy", "feed", "fetch", "target",
	}
	// numericIDKindHints only lead to a finding when the baseline sample is
	// numeric (or empty), so the short fragments here are safe.
	numericIDKindHints = []string{
		"id", "uid", "no", "num", "number", "index", "ref", "seq", "serial",
	}
)

var paramFragSplitter = regexp.MustCompile(`[^a-z0-9]+`)

// paramNameFragments splits a parameter name into lower-cased fragments at
// non-alphanumeric boundaries and at camelCase humps, so "userEmail",
// "user_email", "user-email" and "USEREMAIL" all decompose predictably.
func paramNameFragments(name string) []string {
	var b strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	var out []string
	for _, f := range paramFragSplitter.Split(strings.ToLower(b.String()), -1) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// matchesKindHint reports whether any of the name's fragments is one of the
// kind hints. Fragment equality (rather than substring) keeps a word like
// "profile" from matching the "file" hint.
func matchesKindHint(fragments []string, hints []string) bool {
	for _, f := range fragments {
		for _, h := range hints {
			if f == h {
				return true
			}
		}
	}
	return false
}

// isNumericLike reports whether a baseline sample is consistent with a
// numeric identifier. An empty sample returns true, because a parameter
// literally named "id" with no captured value still almost always expects a
// number.
func isNumericLike(sample string) bool {
	s := strings.TrimSpace(sample)
	if s == "" {
		return true
	}
	_, ok := parseIntStrict(s)
	return ok
}

// parseIntStrict parses a plain non-negative decimal integer, rejecting
// sign/whitespace/overflow and anything longer than 12 digits (which would
// never be a real object id and only risks int overflow).
func parseIntStrict(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 12 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ClassifyParam infers the most likely semantic kind of a fuzzable
// parameter from its name and baseline sample. The order of the checks is
// intentional: the more specific, more actionable kinds are resolved first.
func ClassifyParam(name, sample string) ParamKind {
	frags := paramNameFragments(name)
	switch {
	case matchesKindHint(frags, fileKindHints):
		return ParamFilePath
	case matchesKindHint(frags, emailKindHints):
		return ParamEmail
	case matchesKindHint(frags, redirectKindHints):
		return ParamRedirect
	case matchesKindHint(frags, numericIDKindHints) && isNumericLike(sample):
		return ParamNumericID
	case matchesKindHint(frags, urlKindHints):
		return ParamURL
	default:
		return ParamGeneric
	}
}

// CheckContextAwareFuzzing classifies p and, for the kinds that have
// dedicated contextual payloads, runs the matching probes. It returns at
// most one finding per parameter (the first kind-specific confirmation),
// and does nothing at all for mutating methods, preserving the tool's
// non-destructive guarantee.
func CheckContextAwareFuzzing(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param, mutate bool) []model.Finding {
	method := t.Method
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "HEAD" {
		// Active context probes only ever touch read-only methods.
		return nil
	}

	switch ClassifyParam(p.Name, p.Sample) {
	case ParamFilePath:
		return checkPathTraversal(ctx, lim, cli, baseline, t, p, mutate)
	case ParamNumericID:
		return checkIDOR(ctx, lim, cli, baseline, t, p)
	case ParamEmail:
		return checkEmailInjection(ctx, lim, cli, baseline, t, p)
	case ParamRedirect, ParamURL:
		return checkOpenRedirect(ctx, lim, cli, baseline, t, p)
	default:
		return nil
	}
}

// --- Path traversal ---------------------------------------------------------

// traversalPayloads are read-only file-read probes. Success is proven by
// the *content* of a known system file appearing in the response (matched by
// matchXXEFile), not merely by the payload being reflected — so a page that
// echoes the input back does not produce a false positive.
func traversalPayloads() []string {
	up := strings.Repeat("../", 6)
	return []string{
		up + "etc/passwd",
		strings.Repeat("..%2f", 6) + "etc/passwd",  // URL-encoded separators
		strings.Repeat("....//", 6) + "etc/passwd", // naive-strip filter dodge
		"/etc/passwd",                              // absolute path
		up + "windows/win.ini",
		strings.Repeat("..\\", 6) + "windows\\win.ini", // Windows separators
	}
}

func checkPathTraversal(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param, mutate bool) []model.Finding {
	baselineSig := ""
	if baseline != nil {
		baselineSig = matchXXEFile(baseline.Body)
	}

	for _, payload := range traversalPayloads() {
		ex, used, attempts := sendAdaptivePayload(mutate, payload, func(pl string) *httpclient.Exchange {
			return sendWithPayload(ctx, lim, cli, t, p.Name, pl)
		})
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		sig := matchXXEFile(ex.Body)
		if sig == "" || sig == baselineSig {
			continue
		}
		notes := "Matched local-file content marker: " + sig
		if n := mutationNote(attempts); n != "" {
			notes += " | " + n + " Payload that got through: " + used
		}
		return []model.Finding{{
			Category: "Path Traversal",
			Severity: model.SeverityCritical,
			Title:    "Path traversal / local file disclosure in parameter \"" + p.Name + "\"",
			Description: fmt.Sprintf(
				"Sending %q (a context-aware probe chosen because %q looks like a file/path parameter) caused the response to contain the contents of a local system file (matched %q). This confirms that the parameter is used to build a filesystem path without sanitising traversal sequences.",
				used, p.Name, sig),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   p.Name,
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: notes},
			Remediation: "Never build filesystem paths from user input. Resolve the requested name against a fixed allow-list or a canonical base directory, reject any input containing path separators or '..', and re-validate the resolved absolute path stays inside the intended directory.",
		}}
	}
	return nil
}

// --- IDOR / forced browsing -------------------------------------------------

// idorCandidates returns a small, bounded set of alternative object ids to
// try around the baseline id: the immediate neighbours plus a few common
// low ids. It never includes the baseline id itself.
func idorCandidates(base int) []int {
	raw := []int{base + 1}
	if base > 1 {
		raw = append(raw, base-1)
	}
	raw = append(raw, 1, 2, 100, 1000)

	out := make([]int, 0, len(raw))
	seen := map[int]bool{base: true}
	for _, v := range raw {
		if v <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// checkIDOR looks for horizontal object-enumeration flaws on a numeric-id
// parameter. To stay accurate it first fetches a deliberately-absent id as a
// control: if the endpoint answers a bogus id with a page the same shape as
// the real object, it is a catch-all and no conclusion is drawn. A finding
// is only raised when a neighbouring id returns a record-like response (same
// status class, comparable size, but not the catch-all page and not the
// original object verbatim).
func checkIDOR(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param) []model.Finding {
	if baseline == nil || baseline.Response == nil {
		return nil
	}
	if baseline.Response.StatusCode < 200 || baseline.Response.StatusCode >= 300 || len(baseline.Body) < 16 {
		return nil
	}
	baseID, ok := parseIntStrict(p.Sample)
	if !ok {
		return nil
	}

	// Control: an id that should not exist.
	absent := sendWithPayload(ctx, lim, cli, t, p.Name, strconv.Itoa(baseID+900000001))
	if absent.Err != nil || absent.Response == nil {
		return nil
	}
	if similarLength(len(absent.Body), len(baseline.Body)) >= 0.90 {
		// The endpoint returns essentially the same page for a bogus id, so
		// "a different body" here cannot be interpreted as a distinct object.
		return nil
	}

	var confirmed []int
	var lastEx *httpclient.Exchange
	lastID := 0
	for _, id := range idorCandidates(baseID) {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, strconv.Itoa(id))
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		if ex.Response.StatusCode < 200 || ex.Response.StatusCode >= 300 {
			continue
		}
		if ex.Body == baseline.Body {
			continue // identical object echoed back — no new access
		}
		if similarLength(len(ex.Body), len(absent.Body)) >= 0.85 {
			continue // this is just the not-found page
		}
		if similarLength(len(ex.Body), len(baseline.Body)) < 0.50 {
			continue // neither a record nor the not-found page
		}
		confirmed = append(confirmed, id)
		lastEx = ex
		lastID = id
		if len(confirmed) >= 2 {
			break
		}
	}
	if len(confirmed) == 0 || lastEx == nil {
		return nil
	}

	return []model.Finding{{
		Category: "Insecure Direct Object Reference (IDOR)",
		Severity: model.SeverityMedium,
		Title:    "Possible IDOR / object enumeration in parameter \"" + p.Name + "\"",
		Description: fmt.Sprintf(
			"Parameter %q looks like a numeric object id. Requesting id=%d returned a record-like response (status %d, %d bytes) that differs from both the original object and the response for a deliberately-absent id (%d bytes), while %d alternative id(s) behaved the same way. This is consistent with the endpoint looking objects up by a client-supplied id without an ownership/authorisation check — verify manually before reporting.",
			p.Name, lastID, lastEx.Response.StatusCode, len(lastEx.Body), len(absent.Body), len(confirmed)),
		URL:       t.URL,
		Method:    t.Method,
		Parameter: p.Name,
		Evidence: model.Evidence{
			RequestRaw:  lastEx.RequestRaw,
			ResponseRaw: lastEx.ResponseRaw,
			Notes: fmt.Sprintf("Baseline id=%s -> %d bytes; absent id=%s -> %d bytes (control). Alternative ids that returned a distinct record-like page: %s.",
				strings.TrimSpace(p.Sample), len(baseline.Body), strconv.Itoa(baseID+900000001), len(absent.Body), intsToStrings(confirmed)),
		},
		Remediation: "Enforce an authorisation check on every object access: verify the authenticated principal owns or may access the requested id, rather than trusting the id supplied by the client. Prefer unpredictable identifiers (UUIDs) and apply the same check on every HTTP verb.",
	}}
}

func intsToStrings(in []int) string {
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ", ")
}

// --- Email / header injection ----------------------------------------------

// emailInjectionProbes inject CRLF sequences plus extra mail headers into an
// email-looking parameter. Nothing here sends mail on its own; it only tries
// to make the *server-side* mail handling misbehave in a way the response
// reveals.
func emailInjectionProbes(marker string) []string {
	target := "ssg-" + marker + "@example.invalid"
	return []string{
		"probe@example.com\r\nCc: " + target,
		"probe@example.com\nCc: " + target,
		"probe@example.com%0d%0aBcc: " + target,
		"probe@example.com%0aX-Injected-" + marker + ": 1",
	}
}

var mailErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)invalid (e-?mail )?header`),
	regexp.MustCompile(`(?i)malformed (e-?mail )?address`),
	regexp.MustCompile(`(?i)header injection`),
	regexp.MustCompile(`(?i)unexpected (line|newline) in`),
	regexp.MustCompile(`(?i)address contains a (line|newline|control)`),
	regexp.MustCompile(`(?i)smtp.*(error|fault|reject|invalid)`),
	regexp.MustCompile(`(?i)(sendmail|postfix|exim|qmail).*(error|fatal|reject)`),
	regexp.MustCompile(`(?i)5\d\d 5\.\d\.\d`),
	regexp.MustCompile(`(?i)javax\.mail`),
	regexp.MustCompile(`(?i)System\.Net\.Mail`),
	regexp.MustCompile(`(?i)PHPMailer`),
	regexp.MustCompile(`(?i)AddressException`),
}

// matchMailError returns a matched mail-handling error signature, or "".
func matchMailError(body string) string {
	for _, re := range mailErrorPatterns {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// checkEmailInjection looks for CRLF/email-header injection. Because the
// mere reflection of an email parameter is normal behaviour (and therefore
// not evidence of anything), the signal here is a *mail-handling error*
// that the injected variants trigger but a benign control address carrying
// the same marker does not.
func checkEmailInjection(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param) []model.Finding {
	marker := Marker()

	baselineSig := ""
	if baseline != nil {
		baselineSig = matchMailError(baseline.Body)
	}
	// Control: a well-formed address with the same marker. Any error the
	// injected payloads produce must be absent here for it to be meaningful.
	control := sendWithPayload(ctx, lim, cli, t, p.Name, "ssg-"+marker+"@example.invalid")
	controlSig := ""
	if control != nil {
		controlSig = matchMailError(control.Body)
	}

	for _, payload := range emailInjectionProbes(marker) {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		sig := matchMailError(ex.Body)
		if sig == "" || sig == baselineSig || sig == controlSig {
			continue
		}
		return []model.Finding{{
			Category: "Email/Header Injection",
			Severity: model.SeverityMedium,
			Title:    "Possible email header injection in parameter \"" + p.Name + "\"",
			Description: fmt.Sprintf(
				"Parameter %q looks like an email field. Sending %q produced a mail-handling error (%q) that neither the baseline nor a benign control address with the same marker triggered — consistent with CRLF characters reaching a mail header. Depending on the backend this can enable spam relaying or header spoofing; confirm manually (e.g. with an out-of-band inbox) before reporting.",
				p.Name, payload, sig),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   p.Name,
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched mail error: " + sig + " (absent from baseline and from the benign control request)"},
			Remediation: "Reject any CR/LF characters in fields that reach a mail API, use a well-maintained mail library that forbids header folding from user input, and validate addresses against a strict e-mail regex before use.",
		}}
	}
	return nil
}

// --- Open redirect ----------------------------------------------------------

// openRedirectProbes return redirect-target payloads that all point at a
// unique, non-resolvable canary host, so a matching Location header can never
// be confused with a redirect to the application's own pages.
func openRedirectProbes(canaryHost string) []string {
	return []string{
		"https://" + canaryHost + "/",
		"//" + canaryHost + "/",
		"https://example.invalid@" + canaryHost + "/", // userinfo trick
		"/\\" + canaryHost + "/",                      // backslash trick
		"https:/" + canaryHost + "/",                  // single-slash trick
	}
}

var reMetaRefresh = regexp.MustCompile(`(?i)http-equiv\s*=\s*["']?refresh`)

// checkOpenRedirect tests a URL/redirect parameter for an open redirect by
// sending canary-host targets and inspecting both the Location header of a
// 3xx response and any HTML meta-refresh in the body.
func checkOpenRedirect(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param) []model.Finding {
	canaryHost := "ssg-redir-" + Marker() + ".example.invalid"

	for _, payload := range openRedirectProbes(canaryHost) {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		loc := ex.Response.Header.Get("Location")
		lowLoc := strings.ToLower(loc)
		if loc != "" && strings.Contains(lowLoc, canaryHost) {
			return []model.Finding{{
				Category: "Open Redirect",
				Severity: model.SeverityHigh,
				Title:    "Open redirect in parameter \"" + p.Name + "\"",
				Description: fmt.Sprintf(
					"Sending %q (a context-aware probe chosen because %q looks like a redirect/URL parameter) made the server answer with a redirect to the attacker-chosen canary host (%q in the Location header). This lets an attacker build trustworthy-looking links that bounce victims to an arbitrary site — commonly used in phishing and OAuth token theft.",
					payload, p.Name, loc),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Redirect Location points at the canary host: " + loc},
				Remediation: "Do not redirect to a URL taken directly from user input. Restrict redirect targets to a fixed allow-list, or to relative paths that cannot escape the current host, and reject absolute/protocol-relative URLs.",
			}}
		}
		// Fall back to an HTML meta-refresh redirect (some apps redirect via
		// markup rather than a Location header).
		if strings.Contains(strings.ToLower(ex.Body), canaryHost) && reMetaRefresh.MatchString(ex.Body) {
			return []model.Finding{{
				Category: "Open Redirect",
				Severity: model.SeverityHigh,
				Title:    "Open redirect (meta-refresh) in parameter \"" + p.Name + "\"",
				Description: fmt.Sprintf(
					"Sending %q made the response contain an HTML meta-refresh pointing at the attacker-chosen canary host %q, confirming an open redirect through markup rather than a Location header.",
					payload, canaryHost),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Body contains a meta-refresh to the canary host: " + canaryHost},
				Remediation: "Do not redirect to a URL taken directly from user input; restrict redirect targets to a fixed allow-list or to relative paths.",
			}}
		}
	}
	return nil
}
