package scanner

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

// Marker returns a short random token used as a unique, greppable
// canary for reflection-style checks (XSS, SSRF), so a hit can never be
// confused with content that was already on the page.
func Marker() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return "ssg" + string(b)
}

// --- SQL injection -----------------------------------------------------

// sqliDelaySeconds is the delay used by every time-based SQLi payload.
// Kept short enough to not hammer a target for long per request, long
// enough to be clearly distinguishable from normal network jitter.
const sqliDelaySeconds = 5

// sqliErrorPayloads are read-only, non-destructive probes meant to break
// a naively-built query and surface a database error message. Nothing
// here attempts to modify or delete data (no DROP/DELETE/UPDATE/INSERT).
var sqliErrorPayloads = []string{
	`'`,
	`''`,
	`"`,
	`\`,
	`' OR '1'='1`,
	`' AND '1'='2`,
	`1' ORDER BY 9999--`,
	`' UNION SELECT NULL--`,
}

// sqliBooleanPairs are (true-condition, false-condition) payload pairs
// for boolean-based blind detection: the true payload should make the
// query behave exactly like the original (valid) input, and the false
// payload should make it behave differently (empty/different result set),
// while neither one triggers a visible database error. Several syntactic
// contexts are covered (quoted string, numeric, parenthesized) since
// which one applies depends on how the target's query is built.
type sqliBoolPair struct{ True, False string }

func sqliBooleanPairs() []sqliBoolPair {
	return []sqliBoolPair{
		{`' AND '1'='1`, `' AND '1'='2`},
		{`" AND "1"="1`, `" AND "1"="2`},
		{`' OR '1'='1`, `' AND '1'='2`},
		{` AND 1=1`, ` AND 1=2`},
		{`) AND (1=1`, `) AND (1=2`},
		{`' AND 1=1-- -`, `' AND 1=2-- -`},
	}
}

func sqliTimePayloads() []string {
	d := sqliDelaySeconds
	return []string{
		fmt.Sprintf(`' OR SLEEP(%d)-- -`, d),
		fmt.Sprintf(`" OR SLEEP(%d)-- -`, d),
		fmt.Sprintf(`'; SELECT pg_sleep(%d)-- -`, d),
		fmt.Sprintf(`' OR pg_sleep(%d)-- -`, d),
		fmt.Sprintf(`'; WAITFOR DELAY '0:0:%d'-- `, d),
		fmt.Sprintf(`1) OR SLEEP(%d)-- -`, d),
	}
}

var sqlErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)you have an error in your sql syntax`),
	regexp.MustCompile(`(?i)warning:\s*mysql_`),
	regexp.MustCompile(`(?i)valid mysql result`),
	regexp.MustCompile(`(?i)mysqli?_fetch`),
	regexp.MustCompile(`(?i)unknown column '`),
	regexp.MustCompile(`(?i)pg_query\(\)`),
	regexp.MustCompile(`(?i)pg_exec\(\)`),
	regexp.MustCompile(`(?i)postgresql.*?error`),
	regexp.MustCompile(`(?i)sqlstate\[`),
	regexp.MustCompile(`(?i)ora-\d{4,5}`),
	regexp.MustCompile(`(?i)microsoft ole db provider`),
	regexp.MustCompile(`(?i)unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)System\.Data\.SqlClient`),
	regexp.MustCompile(`(?i)Npgsql\.`),
	regexp.MustCompile(`(?i)org\.hibernate\.`),
	regexp.MustCompile(`(?i)com\.mysql\.jdbc`),
	regexp.MustCompile(`(?i)sqlite3?\.(OperationalError|Error)`),
	regexp.MustCompile(`(?i)SQLITE_ERROR`),
	regexp.MustCompile(`(?i)ODBC (SQL Server|Driver)`),
	regexp.MustCompile(`(?i)JDBC Driver`),
}

// matchSQLError returns the matched snippet if body looks like a leaked
// database error, or "" if it doesn't.
func matchSQLError(body string) string {
	for _, re := range sqlErrorPatterns {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// --- XSS -----------------------------------------------------------------

// xssPayloads returns reflection-test payloads for marker. Execution
// payloads deliberately *assign* `window[marker]=1` rather than *call*
// `marker()`: a called-but-undefined function throws a ReferenceError and
// proves nothing, whereas an assignment is simple enough to survive
// inside an attribute, inside a script block, or after breaking out of
// one, and leaves a plain, unambiguous side effect — window[marker]
// becomes 1 — that CheckXSS's browser-confirmation step can read back
// after navigating a real page to the exact reflected URL.
func xssPayloads(marker string) []string {
	assign := `window["` + marker + `"]=1`
	return []string{
		// Execution-capable payloads go first: CheckXSS stops at the
		// first one that reflects, and an executable hit is both the
		// stronger piece of evidence and the only kind browser
		// confirmation (xss_confirm.go) can do anything with. The bare
		// tag last is a weaker fallback for the rare case where these
		// all get stripped but a plain custom tag still survives.
		`"><script>` + assign + `</script>`,
		`'><script>` + assign + `</script>`,
		`<script>` + assign + `</script>`,
		`<img src=x onerror='` + assign + `'>`,
		`<svg onload='` + assign + `'>`,
		`<` + marker + `x>`, // cheap "is it reflected at all" probe, no execution implied
	}
}

// --- Command injection -----------------------------------------------------

const cmdiDelaySeconds = 6

func cmdiTimePayloads() []string {
	d := cmdiDelaySeconds
	return []string{
		fmt.Sprintf(`;sleep %d`, d),
		fmt.Sprintf(`;sleep %d;`, d),
		fmt.Sprintf(`|sleep %d`, d),
		fmt.Sprintf(`||sleep %d`, d),
		fmt.Sprintf(`&&sleep %d`, d),
		fmt.Sprintf("`sleep %d`", d),
		fmt.Sprintf(`$(sleep %d)`, d),
		fmt.Sprintf(`%%0Asleep %d`, d), // newline-prefixed, useful in some shell contexts
	}
}

// --- SSRF -----------------------------------------------------------------

// ssrfParamHints are parameter-name substrings that commonly accept a
// URL the server itself fetches, which is where SSRF payloads belong.
// Fuzzing every param with a full URL payload is noisy and mostly
// meaningless on, say, a "username" field, so SSRF checks are targeted.
var ssrfParamHints = []string{
	"url", "uri", "link", "src", "path", "redirect", "return", "next",
	"continue", "callback", "webhook", "endpoint", "dest", "destination",
	"target", "out", "feed", "host", "domain", "site", "fetch", "proxy",
	"forward", "image", "avatar", "file", "load", "page",
}

func looksLikeURLParam(name string) bool {
	low := strings.ToLower(name)
	for _, hint := range ssrfParamHints {
		if strings.Contains(low, hint) {
			return true
		}
	}
	return false
}

// metadataMarkers are strings that only show up if a request genuinely
// reached a cloud metadata endpoint — used to confirm in-band SSRF
// without needing to parse (let alone use) whatever credentials it
// returned.
var metadataMarkers = []string{
	"ami-id", "instance-id", "iam/security-credentials",
	"computeMetadata", "project-id", "Metadata-Flavor",
	"instance/service-accounts",
}

func matchMetadataMarker(body string) string {
	for _, m := range metadataMarkers {
		if strings.Contains(body, m) {
			return m
		}
	}
	return ""
}
