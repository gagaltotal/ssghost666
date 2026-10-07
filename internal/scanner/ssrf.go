package scanner

import (
	"context"
	"fmt"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// internalTargets are non-destructive, read-only probes aimed at common
// cloud metadata services and loopback addresses — the standard set any
// SSRF testing checklist starts with. A hit only ever triggers an HTTP
// GET; nothing here tries to use, decode or exfiltrate whatever a
// metadata service might return.
var internalTargets = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/computeMetadata/v1/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://127.0.0.1/",
	"http://localhost/",
}

// ssrfControlHost is a host that cannot resolve, used as a control to see
// how the target behaves when a fetch target is simply broken — the
// baseline to compare "did it actually try to reach the internal target"
// against.
const ssrfControlHost = "http://ssghost666-unreachable-control.invalid/"

// CheckSSRF only runs on parameters whose name suggests they hold a
// server-fetched URL (see looksLikeURLParam), since blasting every field
// with URL payloads is noisy and rarely meaningful.
func CheckSSRF(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, p model.Param, callbackHost string) []model.Finding {
	if !looksLikeURLParam(p.Name) {
		return nil
	}
	var findings []model.Finding

	// Control request establishes what "the server tried and failed"
	// looks like for this exact parameter, to compare the real probes
	// against.
	control := sendWithPayload(ctx, lim, cli, t, p.Name, ssrfControlHost)

	for _, target := range internalTargets {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, target)
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		// Strip any verbatim echo of the payload itself before matching
		// markers: an endpoint that merely reflects its input back (e.g.
		// an XSS-vulnerable param) would otherwise "match" a marker like
		// computeMetadata just because that substring is part of the
		// *payload URL*, not because the server fetched anything.
		bodyMinusEcho := strings.ReplaceAll(ex.Body, target, "")
		if sig := matchMetadataMarker(bodyMinusEcho); sig != "" {
			findings = append(findings, model.Finding{
				Category:    "SSRF",
				Severity:    model.SeverityCritical,
				Title:       "Confirmed SSRF to internal/metadata service via parameter \"" + p.Name + "\"",
				Description: fmt.Sprintf("Setting %q to %q caused the response to contain %q — the server itself fetched an internal/cloud-metadata address on the attacker's behalf.", p.Name, target, sig),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched metadata marker: " + sig},
				Remediation: "Validate/allowlist outbound destinations server-side (not just by regex on the URL string), block requests to link-local/metadata and loopback ranges, and prefer not letting user input choose a server-fetched URL at all.",
			})
			continue
		}
		if control.Response != nil && looksLikeAttemptedFetch(ex, control) {
			findings = append(findings, model.Finding{
				Category:    "SSRF",
				Severity:    model.SeverityMedium,
				Title:       "Potential SSRF via parameter \"" + p.Name + "\" — manual verification recommended",
				Description: fmt.Sprintf("Setting %q to %q produced a response that differs from an unreachable-host control (status %d vs %d, %dms vs %dms), suggesting the server attempted the fetch. No data was conclusively confirmed in the response, so this needs manual review.", p.Name, target, ex.Response.StatusCode, control.Response.StatusCode, ex.ElapsedMS, control.ElapsedMS),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("Control response: status=%d elapsed=%dms", control.Response.StatusCode, control.ElapsedMS)},
				Remediation: "Validate/allowlist outbound destinations server-side, and block requests to link-local/metadata and loopback ranges.",
			})
		}
	}

	if callbackHost != "" {
		cb := callbackHost
		if !strings.HasPrefix(cb, "http://") && !strings.HasPrefix(cb, "https://") {
			cb = "http://" + cb
		}
		cb = strings.TrimRight(cb, "/") + "/ssrf-" + Marker()
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, cb)
		if ex.Err == nil && ex.Response != nil {
			findings = append(findings, model.Finding{
				Category:    "SSRF",
				Severity:    model.SeverityInfo,
				Title:       "Out-of-band SSRF payload sent via parameter \"" + p.Name + "\" — check your callback listener",
				Description: fmt.Sprintf("Parameter %q was set to your callback URL %q. This tool cannot see whether the target actually called back — check your Collaborator/interactsh/listener for an incoming request to confirm.", p.Name, cb),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw},
				Remediation: "If the callback fires: validate/allowlist outbound destinations server-side, and block requests to internal/loopback/link-local ranges.",
			})
		}
	}

	return findings
}

func looksLikeAttemptedFetch(probe, control *httpclient.Exchange) bool {
	if probe.Response == nil || control.Response == nil {
		return false
	}
	if probe.Response.StatusCode != control.Response.StatusCode {
		return true
	}
	// A clearly longer stall than the "instantly broken host" control
	// suggests the server actually tried to connect somewhere real.
	return probe.ElapsedMS > control.ElapsedMS+1500
}
