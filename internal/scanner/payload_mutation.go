package scanner

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	"ssghost666/internal/httpclient"
)

// --- Automatic payload mutation (WAF / filter bypass) -----------------------
//
// When a check sends a payload and the target answers with something that
// looks like a WAF/filter block (a 403/406/429/501, or a known WAF error
// page), blindly moving on would under-report. Instead the payload is
// re-sent in a handful of equivalent encodings/obfuscations — full URL
// encoding, double URL encoding, unicode escapes, HTML hex entities, case
// variation and SQL comment injection — and the first variant that gets
// through is used for the actual detection logic.
//
// Everything here only ever transforms the *payload string*; no check
// becomes destructive as a result. Variant generation is bounded and each
// variant still goes through the shared rate limiter, so a WAF that blocks
// everything costs a small, fixed number of extra requests per payload.

// wafSignatures maps a lower-cased substring that commonly appears in a
// WAF's block page or headers to a friendly WAF/product name.
var wafSignatures = []struct {
	needle string
	name   string
}{
	{"cloudflare", "Cloudflare"},
	{"cf-ray", "Cloudflare"},
	{"attention required! | cloudflare", "Cloudflare"},
	{"aws waf", "AWS WAF"},
	{"awselb", "AWS ELB/WAF"},
	{"mod_security", "ModSecurity"},
	{"modsecurity", "ModSecurity"},
	{"not acceptable!", "ModSecurity"},
	{"sucuri", "Sucuri"},
	{"x-sucuri-id", "Sucuri"},
	{"incapsula", "Imperva Incapsula"},
	{"x-iinfo", "Imperva Incapsula"},
	{"akamai", "Akamai"},
	{"akamai ghost", "Akamai"},
	{"reference #18", "Akamai"},
	{"f5 networks", "F5 BIG-IP ASM"},
	{"the requested url was rejected", "F5 BIG-IP ASM"},
	{"barracuda", "Barracuda WAF"},
	{"wordfence", "Wordfence"},
	{"request rejected", "Generic WAF"},
	{"access denied", "Generic WAF"},
	{"web application firewall", "Generic WAF"},
	{"security policy", "Generic WAF"},
	{"blocked by", "Generic WAF"},
}

// wafBlockStatuses are HTTP status codes that, on their own, strongly
// suggest a request was rejected by a security filter rather than handled
// by the application.
var wafBlockStatuses = map[int]bool{
	403: true, 406: true, 419: true, 429: true, 501: true, 999: true,
}

// wafBlockReason reports whether an exchange looks like a WAF/filter
// rejection and, if so, a human-readable reason (used both to decide
// whether to mutate and to annotate the resulting evidence).
func wafBlockReason(ex *httpclient.Exchange) (string, bool) {
	if ex == nil || ex.Response == nil {
		return "", false
	}
	headerBlob := lowerHeaderBlob(ex.Response.Header)
	bodyBlob := strings.ToLower(ex.Body)

	for _, sig := range wafSignatures {
		if strings.Contains(headerBlob, sig.needle) {
			return fmt.Sprintf("WAF signature %q in response headers (%s)", sig.needle, sig.name), true
		}
	}
	// Only look at the body for known WAF markers when the status also
	// looks block-ish, to avoid flagging an app that merely mentions
	// "security policy" in legitimate content.
	if wafBlockStatuses[ex.Response.StatusCode] {
		for _, sig := range wafSignatures {
			if strings.Contains(bodyBlob, sig.needle) {
				return fmt.Sprintf("WAF signature %q in response body (%s)", sig.needle, sig.name), true
			}
		}
		return fmt.Sprintf("request rejected with HTTP %d (likely WAF/filter)", ex.Response.StatusCode), true
	}
	return "", false
}

// lowerHeaderBlob flattens an http.Header into a single lower-cased string
// for substring WAF-signature matching (header names are already folded to
// lower case by net/http, values are lower-cased here too).
func lowerHeaderBlob(h http.Header) string {
	var sb strings.Builder
	for k, vals := range h {
		sb.WriteString(strings.ToLower(k))
		sb.WriteByte(':')
		for _, v := range vals {
			sb.WriteString(strings.ToLower(v))
			sb.WriteByte(' ')
		}
	}
	return sb.String()
}

// --- Payload send closures --------------------------------------------------

// sendAdaptivePayload sends basePayload and, if mutate is true and the
// response looks WAF/filter-blocked, retries with encoding/obfuscation
// variants until one is not blocked. It returns the exchange that should be
// inspected, the exact payload string that produced it, and the list of
// variant descriptions that were attempted (for evidence notes). When
// mutation is off, or nothing was blocked, it returns the original
// exchange and payload.
func sendAdaptivePayload(mutate bool, basePayload string, send func(payload string) *httpclient.Exchange) (*httpclient.Exchange, string, []string) {
	ex := send(basePayload)
	if !mutate || ex == nil {
		return ex, basePayload, nil
	}
	if _, blocked := wafBlockReason(ex); !blocked {
		return ex, basePayload, nil
	}

	var attempts []string
	variants := MutatePayload(basePayload)
	var lastEx *httpclient.Exchange
	var lastPayload string
	for _, v := range variants {
		v2 := send(v.payload)
		lastEx, lastPayload = v2, v.payload
		attempts = append(attempts, v.label)
		if v2 == nil || v2.Response == nil {
			continue
		}
		if _, stillBlocked := wafBlockReason(v2); !stillBlocked {
			// This encoding got past the filter; hand it back so the
			// caller's normal detection logic runs against a response the
			// filter didn't short-circuit.
			return v2, v.payload, attempts
		}
	}
	// Every variant was blocked too; return the last variant's exchange so
	// the caller still sees the most-recent evidence, plus the attempt list.
	if lastEx != nil {
		return lastEx, lastPayload, attempts
	}
	return ex, basePayload, attempts
}

// mutationNote renders a human-readable sentence describing which encoding
// variants were tried after a WAF/filter block, for inclusion in a
// finding's evidence notes. Empty when nothing was mutated.
func mutationNote(attempts []string) string {
	if len(attempts) == 0 {
		return ""
	}
	return "A WAF/filter blocked the original payload; automatic encoding/obfuscation variants were tried in order: " + strings.Join(attempts, ", ") + "."
}

// mutation is one named encoding/obfuscation variant of a payload.
type mutation struct {
	label   string
	payload string
}

// MutatePayload returns an ordered, bounded set of encoding/obfuscation
// variants for base. Ordering goes from least to most mangling: case
// variation first (usually still executable/interpretable as-is), then
// comment/whitespace evasion, then URL/HTML/unicode encodings. The list is
// deliberately small so a fully-blocked payload costs only a few extra
// requests.
func MutatePayload(base string) []mutation {
	var out []mutation
	add := func(label, p string) {
		if p != "" && p != base {
			out = append(out, mutation{label: label, payload: p})
		}
	}

	add("case variation", mutateCaseVariation(base))
	add("SQL comment whitespace", mutateSQLCommentWhitespace(base))
	add("full URL-encoding", mutateURLEncodeFull(base))
	add("double URL-encoding", mutateDoubleURLEncode(base))
	add("HTML hex entities", mutateHexEntities(base))
	add("unicode escapes", mutateUnicodeEscape(base))
	return out
}

// mutateCaseVariation randomly changes the case of alphabetic characters,
// which defeats naive case-sensitive keyword blocklists (SELECT → SeLeCt,
// <script> → <ScRiPt>). Control/structural characters are left untouched,
// so the payload keeps its meaning.
func mutateCaseVariation(in string) string {
	b := []byte(in)
	for i := range b {
		c := b[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			if rand.Intn(2) == 0 {
				b[i] = c ^ 0x20 // flip ASCII case
			}
		}
	}
	return string(b)
}

// mutateSQLCommentWhitespace replaces runs of spaces with a SQL block
// comment, the classic "UNION/**/SELECT" evasion that survives SQL parsing
// but trips filters that only look for "UNION SELECT".
func mutateSQLCommentWhitespace(in string) string {
	if !strings.Contains(in, " ") {
		return ""
	}
	return strings.ReplaceAll(in, " ", "/**/")
}

// mutateURLEncodeFull percent-encodes every byte of the payload. Servers
// that decode the query/body before applying their filter see the original
// payload again, while a signature filter scanning the raw request sees
// only %XX.
func mutateURLEncodeFull(in string) string {
	var sb strings.Builder
	for i := 0; i < len(in); i++ {
		fmt.Fprintf(&sb, "%%%02X", in[i])
	}
	return sb.String()
}

// mutateDoubleURLEncode URL-encodes the payload and then encodes the "%"
// signs again, so a filter that decodes exactly once still sees encoded
// input, while the application (which may decode twice) sees the payload.
func mutateDoubleURLEncode(in string) string {
	once := mutateURLEncodeFull(in)
	return strings.ReplaceAll(once, "%", "%25")
}

// mutateHexEntities converts the characters that matter for HTML/JS
// injection into numeric character references (&#x3C; etc). These are inert
// to a filter that only looks for literal < and " but a browser/parser that
// decodes entities will reconstitute them.
func mutateHexEntities(in string) string {
	repl := strings.NewReplacer(
		"<", "&#x3C;",
		">", "&#x3E;",
		"\"", "&#x22;",
		"'", "&#x27;",
		"(", "&#x28;",
		")", "&#x29;",
	)
	return repl.Replace(in)
}

// mutateUnicodeEscape escapes dangerous punctuation as \uXXXX sequences
// (e.g. ' becomes \u0027). Some application-layer filters match literal
// quotes but a downstream parser that processes \u escapes reconstitutes
// them, so this slips past signature-based filters.
func mutateUnicodeEscape(in string) string {
	var sb strings.Builder
	for _, r := range in {
		switch r {
		case '\'', '"', '<', '>', '(', ')', ';', ' ', '=', '/', '\\', '-', '*', '#', '$', '`', '|', '&':
			fmt.Fprintf(&sb, "\\u%04x", r)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
