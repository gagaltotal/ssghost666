package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- WebSocket security testing ---------------------------------------------
//
// WebSocket endpoints are collected by the crawler (from the browser's
// network events and from wss?:// literals in JavaScript) and tested here
// with a minimal, dependency-free RFC 6455 client: handshake, then
// client-to-server text frames. The checks are:
//
//   - reachability: does the endpoint complete a handshake at all
//   - authentication: with credentials configured, does the same handshake
//     succeed with the credentials stripped (authorization bypass)
//   - Origin validation: does a handshake carrying a foreign Origin still
//     succeed (Cross-Site WebSocket Hijacking, since WebSockets are not
//     subject to the same-origin policy)
//   - message handling: is client input echoed back verbatim (a stored-DOM
//     XSS primitive if an admin UI renders socket messages as HTML)
//   - rate limiting: are message floods throttled at all

const (
	wsHandshakeTimeout = 8 * time.Second
	wsReadWindow       = 1500 * time.Millisecond
	wsMaxFrameSize     = 1 << 20 // 1 MiB cap on a single frame we will read
	wsFloodCount       = 30
)

// isWebSocketTarget reports whether a discovered target is a WebSocket
// endpoint rather than something to fuzz over HTTP.
func isWebSocketTarget(t model.Target) bool {
	if strings.EqualFold(t.Source, "websocket") {
		return true
	}
	low := strings.ToLower(t.URL)
	return strings.HasPrefix(low, "ws://") || strings.HasPrefix(low, "wss://")
}

// wsOriginOf derives the http(s) Origin a well-behaved client would send
// for a ws(s) URL.
func wsOriginOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	scheme := "https"
	if strings.EqualFold(u.Scheme, "ws") {
		scheme = "http"
	}
	return scheme + "://" + u.Host
}

// wsAuthHeaders copies the HTTP client's configured credentials into a
// header map usable for a WebSocket handshake.
func wsAuthHeaders(cli *httpclient.Client) map[string]string {
	h := map[string]string{}
	if cli == nil {
		return h
	}
	if cli.CookieHeader != "" {
		h["Cookie"] = cli.CookieHeader
	}
	for k, v := range cli.ExtraHeaders {
		h[k] = v
	}
	if cli.UserAgent != "" {
		h["User-Agent"] = cli.UserAgent
	}
	if _, ok := h["User-Agent"]; !ok {
		h["User-Agent"] = "SSGhost666"
	}
	return h
}

func wsMerge(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// wsKey generates the base64 nonce a handshake must send.
func wsKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsHandshake performs the RFC 6455 opening handshake and returns the
// live connection, a buffered reader positioned just after the response
// headers, and the raw HTTP response (so callers can inspect the status
// code when the upgrade did not happen).
func wsHandshake(rawURL string, headers map[string]string) (net.Conn, *bufio.Reader, *http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, nil, err
	}
	if !strings.EqualFold(u.Scheme, "ws") && !strings.EqualFold(u.Scheme, "wss") &&
		!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return nil, nil, nil, fmt.Errorf("unsupported websocket scheme %q", u.Scheme)
	}
	secure := strings.EqualFold(u.Scheme, "wss") || strings.EqualFold(u.Scheme, "https")

	host := u.Host
	if u.Port() == "" {
		if secure {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := net.Dialer{Timeout: wsHandshakeTimeout}
	var conn net.Conn
	if secure {
		conn, err = tls.DialWithDialer(&dialer, "tcp", host, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true})
	} else {
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, nil, nil, err
	}

	key := wsKey()
	path := u.RequestURI()
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")

	_ = conn.SetDeadline(time.Now().Add(wsHandshakeTimeout))
	if _, err := io.WriteString(conn, b.String()); err != nil {
		conn.Close()
		return nil, nil, nil, err
	}

	br := bufio.NewReader(conn)
	req := &http.Request{Method: http.MethodGet, URL: u}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	if resp.StatusCode == http.StatusSwitchingProtocols {
		if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "" && got != wsAccept(key) {
			conn.Close()
			return nil, nil, resp, fmt.Errorf("invalid Sec-WebSocket-Accept")
		}
	}
	return conn, br, resp, nil
}

// wsDialLimited is wsHandshake behind the shared rate limiter, so
// WebSocket probing is paced exactly like every other scanner request.
func wsDialLimited(ctx context.Context, lim *ratelimiter.Limiter, rawURL string, headers map[string]string) (net.Conn, *bufio.Reader, *http.Response, error) {
	if !lim.Acquire(ctx) {
		return nil, nil, nil, context.Canceled
	}
	defer lim.Release()
	return wsHandshake(rawURL, headers)
}

// wsWriteTextFrame writes a single, masked client text frame.
func wsWriteTextFrame(w io.Writer, payload []byte) error {
	var frame bytes.Buffer
	frame.WriteByte(0x80 | 0x1) // FIN + text opcode

	n := len(payload)
	switch {
	case n < 126:
		frame.WriteByte(0x80 | byte(n)) // MASK bit set
	case n <= 0xFFFF:
		frame.WriteByte(0x80 | 126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		frame.Write(ext[:])
	default:
		frame.WriteByte(0x80 | 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		frame.Write(ext[:])
	}

	var mask [4]byte
	_, _ = rand.Read(mask[:])
	frame.Write(mask[:])
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	frame.Write(masked)

	_, err := w.Write(frame.Bytes())
	return err
}

// wsReadFrame reads one frame. It returns the opcode, whether it was the
// final fragment, and the unmasked payload. Control frames (close/ping/
// pong) are returned to the caller so floods can be interpreted.
func wsReadFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0

	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > wsMaxFrameSize {
		return 0, nil, fmt.Errorf("frame too large: %d", length)
	}

	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

// wsDrain reads whatever frames arrive before the deadline, returning the
// concatenated text/close payloads and whether the peer closed.
func wsDrain(conn net.Conn, br *bufio.Reader, window time.Duration) (data []byte, closed bool) {
	_ = conn.SetReadDeadline(time.Now().Add(window))
	for {
		op, payload, err := wsReadFrame(br)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return data, false
			}
			if err == io.EOF {
				return data, true
			}
			return data, true
		}
		switch op {
		case 0x1, 0x2: // text / binary
			data = append(data, payload...)
		case 0x8: // close
			return data, true
		case 0x9: // ping -> answer with pong so the peer keeps talking
			_ = wsWriteControl(conn, 0xA, payload)
		}
	}
}

// wsWriteControl writes an unmasked-free (client-masked) control frame.
func wsWriteControl(w io.Writer, opcode byte, payload []byte) error {
	var frame bytes.Buffer
	frame.WriteByte(0x80 | (opcode & 0x0F))
	frame.WriteByte(0x80 | byte(len(payload)&0x7F))
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	frame.Write(mask[:])
	for i := range payload {
		frame.WriteByte(payload[i] ^ mask[i%4])
	}
	_, err := w.Write(frame.Bytes())
	return err
}

// CheckWebSocket runs the full WebSocket test suite against one endpoint.
func CheckWebSocket(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, rawURL string, hasAuth bool) []model.Finding {
	auth := wsAuthHeaders(cli)
	origin := wsOriginOf(rawURL)

	conn, br, resp, err := wsDialLimited(ctx, lim, rawURL, wsMerge(auth, map[string]string{"Origin": origin}))
	if err != nil || resp == nil {
		return nil
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		if conn != nil {
			conn.Close()
		}
		// The endpoint exists but refused to upgrade (404/401/403/...):
		// nothing WebSocket-specific we can assess.
		return nil
	}
	defer conn.Close()

	var findings []model.Finding
	findings = append(findings, model.Finding{
		Category:    "WebSocket",
		Severity:    model.SeverityInfo,
		Title:       "WebSocket endpoint detected",
		Description: fmt.Sprintf("The endpoint completed an RFC 6455 handshake (%s). WebSocket connections bypass the browser's same-origin policy, so the server must enforce authentication, authorization and Origin validation itself on every connection and every message.", rawURL),
		URL:         rawURL,
		Method:      "GET",
		Parameter:   "Upgrade: websocket",
		Evidence:    model.Evidence{Notes: fmt.Sprintf("Handshake succeeded with %s.\nOrigin sent: %s", resp.Status, origin)},
		Remediation: "Validate the Origin header, authenticate the connection (e.g. via a session cookie checked during the upgrade or a short-lived token), and re-check authorization for every message.",
	})

	// --- Authorization bypass -----------------------------------------
	if hasAuth {
		anonConn, _, anonResp, anonErr := wsDialLimited(ctx, lim, rawURL, map[string]string{"Origin": origin})
		if anonErr == nil && anonResp != nil && anonResp.StatusCode == http.StatusSwitchingProtocols {
			findings = append(findings, model.Finding{
				Category:    "WebSocket",
				Severity:    model.SeverityHigh,
				Title:       "WebSocket endpoint accepts unauthenticated connections",
				Description: "With credentials configured, the endpoint's handshake was repeated with the Cookie/Authorization headers stripped and it still switched protocols. If messages on this socket carry or act on the authenticated user's data, an anonymous client can reach it.",
				URL:         rawURL,
				Method:      "GET",
				Parameter:   "upgrade (no credentials)",
				Evidence:    model.Evidence{Notes: fmt.Sprintf("Unauthenticated handshake also returned %s.", anonResp.Status)},
				Remediation: "Reject the upgrade (401/403) when the session/token is missing or invalid, before any socket state is created.",
			})
		}
		if anonConn != nil {
			anonConn.Close()
		}
	}

	// --- Origin validation (Cross-Site WebSocket Hijacking) -----------
	if origin != "" {
		evil := "https://ssghost666-attacker.invalid"
		evilConn, _, evilResp, evilErr := wsDialLimited(ctx, lim, rawURL, wsMerge(auth, map[string]string{"Origin": evil}))
		if evilErr == nil && evilResp != nil && evilResp.StatusCode == http.StatusSwitchingProtocols {
			findings = append(findings, model.Finding{
				Category:    "WebSocket",
				Severity:    model.SeverityMedium,
				Title:       "WebSocket handshake does not validate the Origin header (CSWSH)",
				Description: fmt.Sprintf("A handshake carrying Origin: %s — a domain the application does not control — was accepted. Because WebSocket handshakes are not protected by CORS or the same-origin policy, any website a logged-in user visits can open this socket with that user's ambient cookies and read/write its messages.", evil),
				URL:         rawURL,
				Method:      "GET",
				Parameter:   "Origin",
				Evidence:    model.Evidence{Notes: fmt.Sprintf("Handshake with foreign Origin returned %s (expected a rejection).", evilResp.Status)},
				Remediation: "Validate the Origin header during the upgrade against an explicit allowlist of the application's own origins, and additionally require a CSRF-style token that a cross-site page cannot know.",
			})
		}
		if evilConn != nil {
			evilConn.Close()
		}
	}

	// --- Message handling: reflection and flood throttling -------------
	findings = append(findings, wsMessageChecks(conn, br, rawURL)...)
	return findings
}

// wsMessageChecks drives the live socket: a marker-bearing message to see
// whether the server echoes client input back (a DOM-XSS primitive when a
// UI renders socket data as HTML), then a rapid burst to see whether the
// server throttles message floods at all.
func wsMessageChecks(conn net.Conn, br *bufio.Reader, rawURL string) []model.Finding {
	var findings []model.Finding

	marker := "wsx" + Marker()[3:]
	_ = conn.SetWriteDeadline(time.Now().Add(wsHandshakeTimeout))
	if err := wsWriteTextFrame(conn, []byte("SSGHOST666-PING-"+marker)); err != nil {
		return findings
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Drain control/ping frames first so the flood test measures the same
	// connection state a browser would see.
	data, _ := wsDrain(conn, br, wsReadWindow)
	if strings.Contains(string(data), marker) {
		findings = append(findings, model.Finding{
			Category:    "WebSocket",
			Severity:    model.SeverityLow,
			Title:       "WebSocket server echoes client messages verbatim",
			Description: fmt.Sprintf("A unique marker (%s) sent over the socket was received back in the server's response unchanged. If any client renders incoming socket messages as HTML rather than text, a message injected here becomes stored DOM XSS; at minimum it confirms the server broadcasts unsanitized client input.", marker),
			URL:         rawURL,
			Method:      "GET",
			Parameter:   "websocket message",
			Evidence:    model.Evidence{Notes: fmt.Sprintf("Sent: SSGHOST666-PING-%s\nReceived: %s", marker, truncateForNote(string(data)))},
			Remediation: "Treat socket messages as untrusted data: validate and constrain them server-side, and render them with textContent / a sanitizer on the client instead of innerHTML.",
		})
	}

	// --- Rate limiting ------------------------------------------------
	_ = conn.SetWriteDeadline(time.Now().Add(wsHandshakeTimeout))
	sent := 0
	for i := 0; i < wsFloodCount; i++ {
		if err := wsWriteTextFrame(conn, fmt.Appendf(nil, "SSGHOST666-FLOOD-%d-%s", i, marker)); err != nil {
			break
		}
		sent++
	}
	_ = conn.SetWriteDeadline(time.Time{})

	floodData, closed := wsDrain(conn, br, wsReadWindow)
	if sent == wsFloodCount && !closed && !strings.Contains(string(floodData), "1008") && !strings.Contains(string(floodData), "1013") {
		findings = append(findings, model.Finding{
			Category:    "WebSocket",
			Severity:    model.SeverityInfo,
			Title:       "No WebSocket message rate limiting observed",
			Description: fmt.Sprintf("%d messages sent back-to-back on the socket were all accepted without the server closing the connection or sending a policy/overload close frame (1008/1013). WebSocket message handlers are frequently left unthrottled, which lets a single client drive expensive server work.", wsFloodCount),
			URL:         rawURL,
			Method:      "GET",
			Parameter:   "websocket message",
			Evidence:    model.Evidence{Notes: fmt.Sprintf("Sent %d messages in a burst; connection stayed open.", sent)},
			Remediation: "Apply a per-connection and per-user message-rate limit (token bucket or sliding window) and close the socket with 1008/1013 when it is exceeded.",
		})
	}

	return findings
}

func truncateForNote(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

// RunWebSocketChecks tests every discovered WebSocket endpoint once per run.
func RunWebSocketChecks(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, targets []model.Target, hasAuth bool) []model.Finding {
	var findings []model.Finding
	for _, t := range targets {
		if !isWebSocketTarget(t) {
			continue
		}
		findings = append(findings, CheckWebSocket(ctx, lim, cli, t.URL, hasAuth)...)
	}
	return findings
}
