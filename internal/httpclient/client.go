// Package httpclient wraps net/http with the auth, proxy and TLS handling
// every other package needs, plus helpers to render a raw request/response
// pair for use as Finding evidence.
package httpclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"ssghost666/internal/options"
)

// Client is a configured HTTP client plus the auth/headers to attach to
// every outgoing request.
type Client struct {
	HTTP         *http.Client
	ExtraHeaders map[string]string
	CookieHeader string
	UserAgent    string
}

// New builds a Client from the parsed CLI config.
func New(cfg *options.Config) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.Insecure}, // #nosec G402 -- opt-in via -insecure for self-signed/proxy CA testing
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     30 * time.Second,
	}

	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid -proxy URL: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}

	c := &Client{
		HTTP: &http.Client{
			Transport: tr,
			Timeout:   cfg.Timeout,
			// Scanners need to see 3xx responses themselves (for open-redirect /
			// SSRF-via-redirect style checks) rather than have them silently
			// followed, so redirects are not auto-followed.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ExtraHeaders: map[string]string{},
		CookieHeader: cfg.Cookie,
		UserAgent:    cfg.UserAgent,
	}

	if cfg.Bearer != "" {
		c.ExtraHeaders["Authorization"] = "Bearer " + cfg.Bearer
	}
	for _, h := range cfg.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -header %q, expected \"Key: Value\"", h)
		}
		c.ExtraHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	return c, nil
}

// applyAuth attaches cookie/bearer/extra headers and the User-Agent to req.
func (c *Client) applyAuth(req *http.Request) {
	req.Header.Set("User-Agent", c.UserAgent)
	if c.CookieHeader != "" {
		req.Header.Set("Cookie", c.CookieHeader)
	}
	for k, v := range c.ExtraHeaders {
		req.Header.Set(k, v)
	}
}

// Exchange is one HTTP request/response round trip, captured in full
// (headers + body) so it can become Finding or CapturedResponse evidence.
type Exchange struct {
	Request     *http.Request
	RequestRaw  string
	Response    *http.Response
	ResponseRaw string
	Body        string // decoded response body, read once and buffered here
	ElapsedMS   int64
	Err         error
}

// Do builds and sends a request, buffering the body and rendering raw
// request/response text for evidence. extraHeaders override/add to the
// client's defaults for this one call (used when a scanner needs a
// per-request header, e.g. a CORS Origin probe).
func (c *Client) Do(method, rawURL string, body io.Reader, extraHeaders map[string]string) *Exchange {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return &Exchange{Err: err}
	}
	c.applyAuth(req)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return c.send(req)
}

// DoWithoutAuth behaves like Do but skips the client's default
// Cookie/Authorization/extra headers entirely (only User-Agent is set).
// It exists for the broken-access-control check, which needs to see
// whether a normally-authenticated endpoint still returns data with no
// credentials at all.
func (c *Client) DoWithoutAuth(method, rawURL string, body io.Reader) *Exchange {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return &Exchange{Err: err}
	}
	req.Header.Set("User-Agent", c.UserAgent)
	return c.send(req)
}

func (c *Client) send(req *http.Request) *Exchange {
	// httputil.DumpRequestOut needs the body readable twice (once to dump,
	// once to actually send), so buffer it up front for small bodies,
	// which is all a scanner like this ever sends.
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	reqDump, _ := httputil.DumpRequestOut(cloneReqWithBody(req, bodyBytes), false)
	reqRaw := string(reqDump)
	if len(bodyBytes) > 0 {
		reqRaw += string(bodyBytes) + "\n"
	}

	start := time.Now()
	resp, err := c.HTTP.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return &Exchange{Request: req, RequestRaw: reqRaw, Err: err, ElapsedMS: elapsed.Milliseconds()}
	}
	defer resp.Body.Close()

	const maxBody = 1 << 20 // 1MB cap so a huge response can't blow up memory/report size
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	respDump, _ := httputil.DumpResponse(&http.Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		ProtoMajor: resp.ProtoMajor,
		ProtoMinor: resp.ProtoMinor,
		Header:     resp.Header,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, false)
	respRaw := string(respDump) + string(rawBody)

	return &Exchange{
		Request:     req,
		RequestRaw:  reqRaw,
		Response:    resp,
		ResponseRaw: respRaw,
		Body:        string(rawBody),
		ElapsedMS:   elapsed.Milliseconds(),
	}
}

func cloneReqWithBody(req *http.Request, body []byte) *http.Request {
	clone := req.Clone(req.Context())
	clone.Body = io.NopCloser(bytes.NewReader(body))
	return clone
}

// Get is a convenience wrapper around Do for simple GET requests.
func (c *Client) Get(rawURL string) *Exchange {
	return c.Do(http.MethodGet, rawURL, nil, nil)
}
