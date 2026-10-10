package scanner

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OOBCallback is a lightweight marker-keyed callback server for checks
// whose confirmation is "the target made an outbound request we can
// observe" — blind XXE entity resolution, deserialization beacons, and
// similar out-of-band signals. It is deliberately simpler than
// SSRFListener: it only needs to record which markers fired and from
// where. Because these callbacks may be triggered by the target's own
// server (routable address rather than loopback), it advertises the
// machine's non-loopback IP.
type OOBCallback struct {
	Port     int
	addr     string
	server   *http.Server
	listener net.Listener
	hits     map[string]*OOBCallbackHit
	hitsMu   sync.RWMutex
	started  bool
}

// OOBCallbackHit is a single received callback.
type OOBCallbackHit struct {
	Marker    string
	Token     string
	Timestamp time.Time
	RemoteIP  string
	UserAgent string
	Method    string
	Path      string
	Query     string
}

// NewOOBCallback creates the callback server (not yet listening).
func NewOOBCallback(port int) (*OOBCallback, error) {
	return &OOBCallback{Port: port, hits: make(map[string]*OOBCallbackHit)}, nil
}

// Start begins listening and returns the routable host:port advertised in
// callback URLs.
func (o *OOBCallback) Start() (string, error) {
	if o.started {
		return "", fmt.Errorf("oob callback already started")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", o.handle)

	o.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", o.Port))
	if err != nil {
		return "", fmt.Errorf("failed to start OOB callback: %w", err)
	}
	o.listener = ln
	o.Port = ln.Addr().(*net.TCPAddr).Port
	o.started = true
	o.addr = fmt.Sprintf("%s:%d", getLocalIP(), o.Port)

	go func() {
		if err := o.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("OOB callback error: %v", err)
		}
	}()
	return o.addr, nil
}

// Addr returns the routable host:port, or the bind address if Start has
// not been called yet.
func (o *OOBCallback) Addr() string {
	if o.addr != "" {
		return o.addr
	}
	if o.listener != nil {
		return o.listener.Addr().String()
	}
	return ""
}

// handle records a callback. The marker is the first path segment and an
// optional per-injection token the second, e.g. /xxe-abc/def.
func (o *OOBCallback) handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 64*1024))
	_ = r.Body.Close()

	trimmed := strings.Trim(r.URL.Path, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	marker := parts[0]
	token := ""
	if len(parts) > 1 {
		token = parts[1]
	}
	if marker == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx > 0 {
		remoteIP = remoteIP[:idx]
	}

	o.hitsMu.Lock()
	o.hits[marker] = &OOBCallbackHit{
		Marker: marker, Token: token, Timestamp: time.Now(),
		RemoteIP: remoteIP, UserAgent: r.UserAgent(),
		Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
	}
	o.hitsMu.Unlock()

	w.Header().Set("Server", "SSGhost666-Callback")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "OK")
}

// CheckHit returns the recorded callback for a marker, or nil.
func (o *OOBCallback) CheckHit(marker string) *OOBCallbackHit {
	o.hitsMu.RLock()
	defer o.hitsMu.RUnlock()
	return o.hits[marker]
}

// Stop shuts the callback server down.
func (o *OOBCallback) Stop() error {
	if !o.started {
		return nil
	}
	o.started = false
	if o.server != nil {
		return o.server.Close()
	}
	return nil
}
