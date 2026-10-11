package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// advancedSSRFTargets includes non-HTTP schemes for advanced SSRF detection
// targeting internal services like Redis, Memcached, and file access
var advancedSSRFTargets = []struct {
	scheme      string
	payload     string
	description string
	markers     []string
}{
	// Gopher protocol for Redis interaction (non-destructive INFO command)
	{
		scheme:      "gopher",
		payload:     "gopher://127.0.0.1:6379/_INFO%0D%0A",
		description: "Redis via gopher (INFO command)",
		markers:     []string{"redis_version", "role:master", "role:slave", "tcp_port:6379"},
	},
	// Gopher protocol for Memcached stats (read-only)
	{
		scheme:      "gopher",
		payload:     "gopher://127.0.0.1:11211/_stats%0D%0A",
		description: "Memcached via gopher (stats command)",
		markers:     []string{"STAT pid", "STAT uptime", "STAT version", "memcached"},
	},
	// Dict protocol for service fingerprinting
	{
		scheme:      "dict",
		payload:     "dict://127.0.0.1:11211/stat",
		description: "Internal service via dict protocol",
		markers:     []string{"220", "dict"},
	},
	// File protocol for local file access (non-destructive, common readable files)
	{
		scheme:      "file",
		payload:     "file:///etc/hostname",
		description: "Local file access via file:// (/etc/hostname)",
		markers:     []string{}, // hostname can be any string, so we check for successful read
	},
	{
		scheme:      "file",
		payload:     "file:///etc/hosts",
		description: "Local file access via file:// (/etc/hosts)",
		markers:     []string{"127.0.0.1", "localhost", "::1"},
	},
	{
		scheme:      "file",
		payload:     "file:///proc/version",
		description: "Local file access via file:// (/proc/version)",
		markers:     []string{"Linux version", "gcc version"},
	},
	// Windows file access
	{
		scheme:      "file",
		payload:     "file:///C:/Windows/win.ini",
		description: "Local file access via file:// (Windows win.ini)",
		markers:     []string{"[fonts]", "[extensions]", "for 16-bit app support"},
	},
}

// CheckAdvancedSSRF tests for SSRF vulnerabilities using advanced protocols
// beyond HTTP/HTTPS: gopher (for Redis/Memcached interaction), dict, and file://
// Only runs on parameters that look like they accept URLs.
func CheckAdvancedSSRF(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, p model.Param, listener *SSRFListener) []model.Finding {
	if !looksLikeURLParam(p.Name) {
		return nil
	}
	var findings []model.Finding

	// Control baseline to compare against
	control := sendWithPayload(ctx, lim, cli, t, p.Name, ssrfControlHost)

	for _, probe := range advancedSSRFTargets {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, probe.payload)
		if ex.Err != nil || ex.Response == nil {
			continue
		}

		// Strip payload from response to avoid false positives from echo/reflection
		bodyMinusEcho := strings.ReplaceAll(ex.Body, probe.payload, "")
		bodyMinusEcho = strings.ReplaceAll(bodyMinusEcho, probe.scheme+"://", "")

		// Check for protocol-specific markers in response
		var matchedMarker string
		for _, marker := range probe.markers {
			if strings.Contains(strings.ToLower(bodyMinusEcho), strings.ToLower(marker)) {
				matchedMarker = marker
				break
			}
		}

		if matchedMarker != "" {
			// Confirmed SSRF with protocol-specific marker detected
			findings = append(findings, model.Finding{
				Category:    "SSRF",
				Severity:    model.SeverityCritical,
				Title:       fmt.Sprintf("Confirmed Advanced SSRF (%s) via parameter %q", probe.scheme, p.Name),
				Description: fmt.Sprintf("Setting %q to %q (%s) caused the response to contain %q — the server fetched content using a non-HTTP protocol, potentially exposing internal services or file system.", p.Name, probe.payload, probe.description, matchedMarker),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("Matched %s marker: %s", probe.scheme, matchedMarker)},
				Remediation: fmt.Sprintf("Strictly validate URL schemes — allow only http/https, reject %s and other non-HTTP protocols. Implement allowlisting for destination hosts/ports, and block access to internal/loopback addresses.", probe.scheme),
			})
			continue
		}

		// For file:// specifically, check if response differs significantly from control
		// (file content read success vs error) even without specific markers
		if probe.scheme == "file" && control.Response != nil {
			// File read success typically results in different status or much longer response
			if ex.Response.StatusCode != control.Response.StatusCode ||
				len(ex.Body) > len(control.Body)+50 {
				// Potential file read, but not confirmed with markers
				findings = append(findings, model.Finding{
					Category:    "SSRF",
					Severity:    model.SeverityHigh,
					Title:       fmt.Sprintf("Potential file:// SSRF via parameter %q — manual verification recommended", p.Name),
					Description: fmt.Sprintf("Setting %q to %q produced a response that differs from control (status %d vs %d, length %d vs %d), suggesting the server may have attempted file access. Manual verification needed to confirm.", p.Name, probe.payload, ex.Response.StatusCode, control.Response.StatusCode, len(ex.Body), len(control.Body)),
					URL:         t.URL,
					Method:      t.Method,
					Parameter:   p.Name,
					Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("Control: status=%d len=%d", control.Response.StatusCode, len(control.Body))},
					Remediation: "Strictly validate URL schemes — allow only http/https, reject file:// and other protocols. Never allow user input to directly control file system access.",
				})
			}
		}

		// Generic check: if response differs significantly from control, might be successful fetch
		if control.Response != nil && probe.scheme != "file" {
			if looksLikeAttemptedFetch(ex, control) {
				findings = append(findings, model.Finding{
					Category:    "SSRF",
					Severity:    model.SeverityMedium,
					Title:       fmt.Sprintf("Potential %s SSRF via parameter %q — manual verification recommended", probe.scheme, p.Name),
					Description: fmt.Sprintf("Setting %q to %q (%s) produced a response that differs from control (status %d vs %d, %dms vs %dms), suggesting the server may have attempted the fetch. Manual verification recommended.", p.Name, probe.payload, probe.description, ex.Response.StatusCode, control.Response.StatusCode, ex.ElapsedMS, control.ElapsedMS),
					URL:         t.URL,
					Method:      t.Method,
					Parameter:   p.Name,
					Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("Control: status=%d elapsed=%dms", control.Response.StatusCode, control.ElapsedMS)},
					Remediation: fmt.Sprintf("Strictly validate URL schemes — allow only http/https, reject %s protocol. Implement allowlisting for destination hosts/ports.", probe.scheme),
				})
			}
		}
	}

	// Try gopher callback through local listener if available (for blind SSRF detection)
	if listener != nil {
		marker := "ssrf-adv-" + Marker()
		// Gopher payload that would attempt to connect back
		cb := fmt.Sprintf("gopher://%s/%s", listener.listener.Addr().String(), marker)
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, cb)
		if ex.Err == nil && ex.Response != nil {
			time.Sleep(500 * time.Millisecond)
			hit := listener.CheckHit(marker)
			if hit != nil {
				findings = append(findings, model.Finding{
					Category:    "SSRF",
					Severity:    model.SeverityCritical,
					Title:       fmt.Sprintf("Confirmed gopher:// SSRF via local callback to parameter %q", p.Name),
					Description: fmt.Sprintf("Parameter %q was set to gopher callback URL %q and the target server successfully connected back. This confirms the server supports gopher protocol SSRF, which can be used to interact with internal services like Redis, Memcached, SMTP, etc.", p.Name, cb),
					URL:         t.URL,
					Method:      t.Method,
					Parameter:   p.Name,
					Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("Gopher callback received from %s at %s", hit.RemoteIP, hit.Timestamp.Format(time.RFC3339))},
					Remediation: "Strictly validate URL schemes — allow only http/https. The gopher protocol is particularly dangerous as it can be used to send arbitrary data to internal TCP services.",
				})
			}
		}
	}

	return findings
}
