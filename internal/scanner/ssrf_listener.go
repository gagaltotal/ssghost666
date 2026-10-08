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

// SSRFListener is a local HTTP server that listens for callbacks from SSRF
// vulnerabilities. It records all incoming requests with their headers and
// bodies, allowing the scanner to detect in-band SSRF without relying on
// external services.
type SSRFListener struct {
	Port     int
	server   *http.Server
	hits     map[string]*SSRFHit
	hitsMu   sync.RWMutex
	listener net.Listener
	started  bool
}

// SSRFHit represents a callback received by the listener.
type SSRFHit struct {
	Marker    string
	Timestamp time.Time
	RemoteIP  string
	Method    string
	Path      string
	Headers   map[string]string
	Body      string
}

// NewSSRFListener creates a new SSRF callback listener.
// If port is 0, it will automatically select an available port.
func NewSSRFListener(port int) (*SSRFListener, error) {
	sl := &SSRFListener{
		Port: port,
		hits: make(map[string]*SSRFHit),
	}
	return sl, nil
}

// Start begins listening for SSRF callbacks on the configured port.
// Returns the actual address (IP:port) where the listener is bound.
func (sl *SSRFListener) Start() (string, error) {
	if sl.started {
		return "", fmt.Errorf("listener already started")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", sl.handleCallback)

	sl.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	addr := fmt.Sprintf(":%d", sl.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to start listener: %w", err)
	}

	sl.listener = listener
	sl.Port = listener.Addr().(*net.TCPAddr).Port
	sl.started = true

	// Get the local IP address
	localIP := getLocalIP()
	listenAddr := fmt.Sprintf("%s:%d", localIP, sl.Port)

	go func() {
		if err := sl.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("SSRF listener error: %v", err)
		}
	}()

	return listenAddr, nil
}

// handleCallback processes incoming HTTP requests to the listener.
func (sl *SSRFListener) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract marker from path (e.g., /ssrf-abc123)
	marker := strings.TrimPrefix(r.URL.Path, "/")

	// Read body
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // Max 1MB
	defer r.Body.Close()

	// Extract headers
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Get remote IP (strip port)
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx > 0 {
		remoteIP = remoteIP[:idx]
	}

	hit := &SSRFHit{
		Marker:    marker,
		Timestamp: time.Now(),
		RemoteIP:  remoteIP,
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   headers,
		Body:      string(body),
	}

	sl.hitsMu.Lock()
	sl.hits[marker] = hit
	sl.hitsMu.Unlock()

	// Respond with a generic 200 OK
	w.Header().Set("Server", "SSGhost666-Callback")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// CheckHit checks if a callback with the given marker has been received.
func (sl *SSRFListener) CheckHit(marker string) *SSRFHit {
	sl.hitsMu.RLock()
	defer sl.hitsMu.RUnlock()
	hit, ok := sl.hits[marker]
	if !ok {
		return nil
	}
	return hit
}

// GetHits returns all recorded callbacks.
func (sl *SSRFListener) GetHits() map[string]*SSRFHit {
	sl.hitsMu.RLock()
	defer sl.hitsMu.RUnlock()
	copied := make(map[string]*SSRFHit, len(sl.hits))
	for k, v := range sl.hits {
		copied[k] = v
	}
	return copied
}

// Stop gracefully shuts down the listener.
func (sl *SSRFListener) Stop() error {
	if !sl.started {
		return nil
	}
	sl.started = false
	if sl.server != nil {
		return sl.server.Close()
	}
	return nil
}

// getLocalIP attempts to determine the local machine's non-loopback IP address.
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
