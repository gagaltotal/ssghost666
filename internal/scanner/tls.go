package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- TLS/SSL configuration testing ------------------------------------------
//
// This module inspects the transport security of each discovered endpoint:
// which protocol versions the server still accepts, whether it still offers
// broken cipher suites, and whether its certificate is trustworthy.
//
// Design notes:
//
//   * Protocol-version detection is done with a hand-rolled ClientHello
//     instead of crypto/tls. Go's TLS client refuses to negotiate SSLv3 at
//     all and its default minimum is TLS 1.2, so the standard library simply
//     cannot answer "does this host still accept TLS 1.0?" — which is the
//     whole point of the check. The raw probe sends a record whose version is
//     pinned to the version under test; RFC-compliant servers reply with a
//     ServerHello carrying min(server_max, offered_version) but only after
//     checking offered_version >= server_min. So a ServerHello echoing the
//     offered version proves the server's minimum is at or below it.
//
//   * Weak-cipher detection offers *only* the weak suites in a dedicated
//     ClientHello. If the handshake completes, the server really does still
//     enable them; if it fails, the suites are gone. Offering them alongside
//     strong suites would be useless because the server would simply pick a
//     strong one from the list.
//
//   * Heartbleed (CVE-2014-0160) is NOT tested. Confirming it requires
//     sending a malformed heartbeat record and inspecting the leaked bytes
//     that come back — i.e. deliberately triggering an out-of-bounds read on
//     the target. This tool is non-destructive by contract and will not do
//     that. The limitation is reported explicitly in the module output rather
//     than silently ignored.
//
// Scope: the check is per host:port, capped at tlsMaxEndpoints endpoints, and
// each probe is paced through the shared rate limiter.

const (
	tlsRecordHandshake   = 22
	tlsRecordAlert       = 21
	handshakeServerHello = 2

	tlsDialTimeout  = 6 * time.Second
	tlsReadTimeout  = 6 * time.Second
	tlsMaxEndpoints = 6 // bounded: ~10 short-lived connections each

	tlsVersionSSL30 = 0x0300
	tlsVersionTLS10 = 0x0301
	tlsVersionTLS11 = 0x0302
	tlsVersionTLS12 = 0x0303
)

// tlsEndpoint is one host:port worth probing, with the name to put in SNI and
// to verify the certificate against.
type tlsEndpoint struct {
	Addr string // host:port, what we dial
	Host string // hostname without port, for report text
	SNI  string // empty when Host is an IP literal (SNI must be a DNS name)
}

// tlsEndpointsFromTargets derives the distinct host:port pairs to probe.
// Plain-HTTP targets are mapped onto the default 443 port, because a service
// crawled over HTTP very often terminates TLS on the same host and would
// otherwise never be inspected.
func tlsEndpointsFromTargets(targets []model.Target) []tlsEndpoint {
	seen := map[string]bool{}
	var out []tlsEndpoint
	for _, t := range targets {
		u, err := url.Parse(t.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" || port == "80" {
			port = "443"
		}
		addr := net.JoinHostPort(host, port)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		ep := tlsEndpoint{Addr: addr, Host: host}
		if net.ParseIP(host) == nil {
			ep.SNI = host
		}
		out = append(out, ep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	if len(out) > tlsMaxEndpoints {
		out = out[:tlsMaxEndpoints]
	}
	return out
}

// tlsProbeCiphers is the "anything reasonable" list used for reachability and
// version probing. It spans TLS 1.3, ECDHE and RSA key exchange, GCM and CBC,
// so a server that speaks any contemporary profile will find something it
// accepts.
var tlsProbeCiphers = []uint16{
	0x1301, 0x1302, 0x1303, // TLS 1.3
	0xc02b, 0xc02c, 0xc02f, 0xc030, // ECDHE + AES-GCM
	0xc009, 0xc00a, 0xc013, 0xc014, // ECDHE + AES-CBC
	0x009c, 0x009d, // RSA + AES-GCM
	0x002f, 0x0035, 0x003c, 0x003d, // RSA + AES-CBC
	0x000a, 0x0016, 0x0013, // 3DES
	0x0005, 0x0004, // RC4
}

// tlsWeakCipherGroups are the broken cipher families worth proving out. Only
// suite IDs from the original IANA registry (RFC 2246 / RFC 4346) are used, so
// a positive result cannot be an accident of mis-numbering: every ID below is
// unambiguously a weak suite.
var tlsWeakCipherGroups = []struct {
	Label    string
	Severity model.Severity
	Ciphers  []uint16
	Note     string
}{
	{
		Label:    "NULL cipher suites (no encryption at all)",
		Severity: model.SeverityCritical,
		Ciphers:  []uint16{0x0000, 0x0001, 0x0002, 0x003b},
		Note:     "These suites perform no encryption whatsoever, so anyone on the path reads and rewrites the traffic in clear text.",
	},
	{
		Label:    "EXPORT / 40-bit cipher suites",
		Severity: model.SeverityCritical,
		Ciphers:  []uint16{0x0003, 0x0006, 0x0008, 0x0014, 0x0017, 0x0019},
		Note:     "EXPORT-grade suites use 40-bit keys that are brute-forceable in hours on commodity hardware.",
	},
	{
		Label:    "RC4 cipher suites",
		Severity: model.SeverityHigh,
		Ciphers:  []uint16{0x0004, 0x0005, 0x0018},
		Note:     "RC4 keystream biases allow plaintext recovery of repeatedly transmitted secrets (CVE-2013-2566, CVE-2015-2808, RFC 7465).",
	},
	{
		Label:    "single DES cipher suites",
		Severity: model.SeverityHigh,
		Ciphers:  []uint16{0x0009, 0x000c, 0x000f, 0x0012, 0x0015, 0x001a},
		Note:     "DES has a 56-bit effective key and was broken by dedicated hardware decades ago.",
	},
	{
		Label:    "3DES cipher suites (Sweet32)",
		Severity: model.SeverityMedium,
		Ciphers:  []uint16{0x000a, 0x0013, 0x0016, 0x001b, 0xc008, 0xc012},
		Note:     "64-bit block ciphers leak plaintext through birthday collisions once a long-lived session carries enough data (CVE-2016-2183).",
	},
}

// tlsHelloResult is the parsed answer to a raw ClientHello.
type tlsHelloResult struct {
	RecordVersion uint16
	SelVersion    uint16
	SelCipher     uint16
	Alert         bool
}

// tlsClientHelloRecord builds a complete TLS record containing a ClientHello
// pinned to the given protocol version.
func tlsClientHelloRecord(ver uint16, sni string, ciphers []uint16) []byte {
	random := make([]byte, 32)
	_, _ = rand.Read(random) // crypto/rand never fails on supported platforms

	body := make([]byte, 0, 128)
	body = append(body, byte(ver>>8), byte(ver))
	body = append(body, random...)
	body = append(body, 0x00) // empty session id
	body = append(body, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
	for _, c := range ciphers {
		body = append(body, byte(c>>8), byte(c))
	}
	body = append(body, 0x01, 0x00) // one compression method: null

	if ext := tlsServerNameExtension(sni); len(ext) > 0 {
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	}

	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, tlsRecordHandshake, byte(ver>>8), byte(ver), byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

// tlsServerNameExtension encodes the SNI (server_name) extension, which is
// required for any virtual-hosted endpoint.
func tlsServerNameExtension(sni string) []byte {
	if sni == "" {
		return nil
	}
	name := []byte(sni)
	if len(name) > 255 {
		return nil
	}
	list := make([]byte, 0, 3+len(name))
	list = append(list, 0x00, byte(len(name)>>8), byte(len(name)))
	list = append(list, name...)
	ext := make([]byte, 0, 4+len(list))
	ext = append(ext, 0x00, 0x00, byte(len(list)>>8), byte(len(list)))
	ext = append(ext, list...)
	return ext
}

// tlsRawHello sends one raw ClientHello and parses whatever comes back.
// The boolean is true only for a completed ServerHello, i.e. an accepted
// handshake; an alert or a truncated/garbage answer means the server refused
// the offered combination.
func tlsRawHello(ctx context.Context, lim *ratelimiter.Limiter, ep tlsEndpoint, helloVersion uint16, ciphers []uint16) (tlsHelloResult, bool) {
	var res tlsHelloResult
	if len(ciphers) == 0 {
		return res, false
	}
	if !lim.Acquire(ctx) {
		return res, false
	}
	defer lim.Release()

	d := &net.Dialer{Timeout: tlsDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", ep.Addr)
	if err != nil {
		return res, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(tlsReadTimeout))

	if _, err := conn.Write(tlsClientHelloRecord(helloVersion, ep.SNI, ciphers)); err != nil {
		return res, false
	}

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return res, false
	}
	res.RecordVersion = uint16(hdr[1])<<8 | uint16(hdr[2])
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 1<<16 {
		return res, false
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		if hdr[0] == tlsRecordAlert {
			res.Alert = true
		}
		return res, false
	}

	if hdr[0] == tlsRecordAlert {
		res.Alert = true
		return res, false
	}
	if hdr[0] != tlsRecordHandshake || len(body) < 4 || body[0] != handshakeServerHello {
		return res, false
	}

	msg := body[4:]
	if len(msg) < 38 {
		return res, false
	}
	res.SelVersion = uint16(msg[0])<<8 | uint16(msg[1])
	pos := 2 + 32 // version + random
	if pos >= len(msg) {
		return res, false
	}
	sidLen := int(msg[pos])
	pos += 1 + sidLen
	if pos+3 > len(msg) {
		return res, false
	}
	res.SelCipher = uint16(msg[pos])<<8 | uint16(msg[pos+1])
	return res, true
}

// tlsCertInfo holds what we learned from a crypto/tls handshake.
type tlsCertInfo struct {
	Leaf        *x509.Certificate
	Chain       []*x509.Certificate
	Negotiated  uint16
	HandshakeOK bool
}

// tlsFetchCertificate performs one handshake with verification disabled purely
// to obtain the certificate chain. Verification is then re-done by hand so we
// can distinguish expiry, name mismatch and trust-chain problems instead of
// collapsing them into a single opaque handshake error.
func tlsFetchCertificate(ctx context.Context, lim *ratelimiter.Limiter, ep tlsEndpoint) tlsCertInfo {
	var info tlsCertInfo
	if !lim.Acquire(ctx) {
		return info
	}
	defer lim.Release()

	d := &net.Dialer{Timeout: tlsDialTimeout}
	raw, err := d.DialContext(ctx, "tcp", ep.Addr)
	if err != nil {
		return info
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(tlsReadTimeout))

	conn := tls.Client(raw, &tls.Config{
		ServerName:         ep.SNI,
		InsecureSkipVerify: true, // we validate by hand below, with precise reasons
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.Chain = state.PeerCertificates
	if len(info.Chain) == 0 {
		return info
	}
	info.Leaf = info.Chain[0]
	info.Negotiated = state.Version
	info.HandshakeOK = true
	return info
}

// tlsVersionName maps a protocol version to its display name.
func tlsVersionName(v uint16) string {
	switch v {
	case tlsVersionSSL30:
		return "SSLv3"
	case tlsVersionTLS10:
		return "TLS 1.0"
	case tlsVersionTLS11:
		return "TLS 1.1"
	case tlsVersionTLS12:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// tlsCertFindings reports everything that is wrong with the certificate
// itself. verifyChain controls only the trust-chain finding: when the operator
// passed -insecure they have explicitly opted out of chain-trust evaluation,
// so reporting "untrusted issuer" would just be noise. Expiry, name mismatch
// and weak keys are properties of the certificate, not of any trust decision,
// so they are always reported.
func tlsCertFindings(ep tlsEndpoint, info tlsCertInfo, verifyChain bool) []model.Finding {
	leaf := info.Leaf
	if leaf == nil {
		return nil
	}
	now := time.Now()
	siteURL := "https://" + ep.Host + "/"
	portNote := ""
	if ep.Addr != net.JoinHostPort(ep.Host, "443") {
		portNote = " (probed on " + ep.Addr + ")"
	}
	fp := sha256.Sum256(leaf.Raw)
	evidence := model.Evidence{
		Notes: fmt.Sprintf("Subject: %s; Issuer: %s; Valid: %s to %s; Serial: %s; SHA-256 fingerprint: %s; Negotiated protocol: %s; Chain length: %d.",
			leaf.Subject.String(), leaf.Issuer.String(),
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339),
			leaf.SerialNumber.String(), hex.EncodeToString(fp[:]),
			tlsVersionName(info.Negotiated), len(info.Chain)),
	}

	var out []model.Finding

	expired := now.After(leaf.NotAfter)
	if expired {
		out = append(out, model.Finding{
			Category:    "TLS/SSL",
			Severity:    model.SeverityHigh,
			Title:       fmt.Sprintf("Expired TLS certificate on %s", ep.Host),
			Description: fmt.Sprintf("The certificate presented by %s%s expired on %s. Every browser and HTTP client will reject the connection or show an interstitial warning, and clients that enforce certificate validation cannot connect at all.", ep.Host, portNote, leaf.NotAfter.UTC().Format("2006-01-02 15:04:05 MST")),
			URL:         siteURL,
			Method:      "TLS",
			Evidence:    evidence,
			Remediation: "Renew the certificate and automate renewal (ACME/Let's Encrypt, or your CA's scheduled issuance) so expiration cannot recur silently.",
		})
	}

	if now.Before(leaf.NotBefore) {
		out = append(out, model.Finding{
			Category:    "TLS/SSL",
			Severity:    model.SeverityMedium,
			Title:       fmt.Sprintf("TLS certificate on %s is not yet valid", ep.Host),
			Description: fmt.Sprintf("The certificate presented by %s%s is not valid before %s. This usually means the server clock is wrong or a future-dated certificate was deployed by mistake; validators will reject the connection until that time.", ep.Host, portNote, leaf.NotBefore.UTC().Format("2006-01-02 15:04:05 MST")),
			URL:         siteURL,
			Method:      "TLS",
			Evidence:    evidence,
			Remediation: "Reissue the certificate, check NTP synchronisation on the server, and verify the issuance time reported by the CA.",
		})
	}

	// VerifyHostname also enforces the validity window, so an expired
	// certificate would trip it too. Expiry is already reported above; skip
	// the name check in that case so we don't double-report one defect.
	if ep.SNI != "" && !expired && leaf.VerifyHostname(ep.SNI) != nil {
		out = append(out, model.Finding{
			Category:    "TLS/SSL",
			Severity:    model.SeverityHigh,
			Title:       fmt.Sprintf("TLS certificate name mismatch for %s", ep.Host),
			Description: fmt.Sprintf("The certificate served on %s%s is not valid for the hostname %q (it covers %s). Clients that validate certificates will abort the connection, and users who click through the warning are trained to accept man-in-the-middle attacks.", ep.Host, portNote, ep.SNI, strings.Join(tlsCertNames(leaf), ", ")),
			URL:         siteURL,
			Method:      "TLS",
			Evidence:    evidence,
			Remediation: "Issue the certificate with the hostname (and any required wildcard/SAN entries) actually served from this endpoint; a SAN-less or wrong-CN certificate must be re-issued by the CA.",
		})
	}

	if verifyChain {
		if roots, err := x509.SystemCertPool(); err == nil && roots != nil {
			inter := x509.NewCertPool()
			for _, c := range info.Chain[1:] {
				inter.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter}); err != nil {
				selfSigned := leaf.Subject.String() == leaf.Issuer.String() &&
					leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
				kind := "does not chain to a trusted root CA"
				hint := "An unknown issuer is typical of a self-managed CA or a misconfigured chain."
				if selfSigned {
					kind = "is self-signed"
					hint = "A self-signed certificate cannot be validated by any client that trusts the public CA set."
				}
				out = append(out, model.Finding{
					Category:    "TLS/SSL",
					Severity:    model.SeverityMedium,
					Title:       fmt.Sprintf("Invalid TLS certificate chain on %s", ep.Host),
					Description: fmt.Sprintf("The certificate served on %s%s %s. %s Clients will refuse the connection unless they are explicitly configured to trust it (for example with -insecure or a pinned CA bundle).", ep.Host, portNote, kind, hint),
					URL:         siteURL,
					Method:      "TLS",
					Evidence:    model.Evidence{Notes: evidence.Notes + " Chain verification error: " + err.Error() + "."},
					Remediation: "Serve the full chain including every intermediate certificate, or issue a certificate from a publicly trusted CA if this endpoint is internet-facing.",
				})
			}
		}
	}

	// Weak signature algorithm.
	switch leaf.SignatureAlgorithm {
	case x509.MD5WithRSA:
		out = append(out, model.Finding{
			Category:    "TLS/SSL",
			Severity:    model.SeverityCritical,
			Title:       fmt.Sprintf("TLS certificate on %s is signed with MD5", ep.Host),
			Description: fmt.Sprintf("The certificate served on %s%s uses an MD5 signature. MD5 collisions are trivially computable, so a forged certificate with the same signature can be produced by anyone with a copy of the legitimate certificate.", ep.Host, portNote),
			URL:         siteURL,
			Method:      "TLS",
			Evidence:    evidence,
			Remediation: "Reissue the certificate with SHA-256 (or better) and confirm the CA no longer issues MD5 signatures.",
		})
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		out = append(out, model.Finding{
			Category:    "TLS/SSL",
			Severity:    model.SeverityHigh,
			Title:       fmt.Sprintf("TLS certificate on %s is signed with SHA-1", ep.Host),
			Description: fmt.Sprintf("The certificate served on %s%s uses a SHA-1 signature, which is deprecated and rejected by modern browsers. Practical chosen-prefix collisions have been demonstrated, making certificate forgery feasible for a well-resourced attacker.", ep.Host, portNote),
			URL:         siteURL,
			Method:      "TLS",
			Evidence:    evidence,
			Remediation: "Reissue the certificate with SHA-256 or stronger; every public CA has been required to stop issuing SHA-1 certificates since 2016.",
		})
	}

	// Weak key material.
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < 2048 {
			sev := model.SeverityHigh
			if bits < 1024 {
				sev = model.SeverityCritical
			}
			out = append(out, model.Finding{
				Category:    "TLS/SSL",
				Severity:    sev,
				Title:       fmt.Sprintf("RSA key on %s is only %d bits", ep.Host, bits),
				Description: fmt.Sprintf("The certificate served on %s%s carries an RSA key of %d bits. Keys below 2048 bits are considered factorable by a determined attacker, and 1024-bit keys are within reach of academic and well-funded efforts.", ep.Host, portNote, bits),
				URL:         siteURL,
				Method:      "TLS",
				Evidence:    evidence,
				Remediation: "Reissue the certificate with an RSA key of at least 2048 bits, or switch to an ECDSA P-256 key.",
			})
		}
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			if bits := pub.Curve.Params().BitSize; bits < 224 {
				out = append(out, model.Finding{
					Category:    "TLS/SSL",
					Severity:    model.SeverityHigh,
					Title:       fmt.Sprintf("ECDSA curve on %s is only %d bits", ep.Host, bits),
					Description: fmt.Sprintf("The certificate served on %s%s uses an ECDSA key on a %d-bit curve, which no longer meets current strength requirements.", ep.Host, portNote, bits),
					URL:         siteURL,
					Method:      "TLS",
					Evidence:    evidence,
					Remediation: "Reissue the certificate with an ECDSA key on the P-256 curve or larger.",
				})
			}
		}
	}

	return out
}

// tlsCertNames collects the names a certificate claims to be valid for, used
// in the mismatch finding.
func tlsCertNames(leaf *x509.Certificate) []string {
	names := append([]string{}, leaf.DNSNames...)
	if leaf.Subject.CommonName != "" {
		names = append([]string{"CN=" + leaf.Subject.CommonName}, names...)
	}
	if len(names) == 0 {
		return []string{"no DNS names"}
	}
	return names
}

// RunTLSChecks probes every discovered endpoint for outdated protocol
// versions, broken cipher suites and certificate defects.
//
// verifyChain should be true unless the operator explicitly passed -insecure;
// it only gates the trust-chain finding, never the intrinsic certificate
// defects.
func RunTLSChecks(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, targets []model.Target, verifyChain bool) []model.Finding {
	_ = cli // TLS probing works on raw sockets; the HTTP client's proxy/cookie state does not apply

	endpoints := tlsEndpointsFromTargets(targets)
	if len(endpoints) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		siteURL := "https://" + ep.Host + "/"

		// Reachability: one broad-profile ClientHello and one real handshake.
		// If neither completes, there is no TLS service here and the
		// remaining probes would only waste connections.
		_, reachOK := tlsRawHello(ctx, lim, ep, tlsVersionTLS12, tlsProbeCiphers)
		cert := tlsFetchCertificate(ctx, lim, ep)
		if !reachOK && !cert.HandshakeOK {
			continue
		}

		findings = append(findings, tlsCertFindings(ep, cert, verifyChain)...)

		// Legacy protocol versions. Probing from the oldest upward lets us
		// report exactly which versions the server's minimum still permits.
		rawTLS10 := false
		for _, v := range []uint16{tlsVersionSSL30, tlsVersionTLS10, tlsVersionTLS11} {
			res, ok := tlsRawHello(ctx, lim, ep, v, tlsProbeCiphers)
			if !ok || res.SelVersion != v {
				continue
			}
			switch v {
			case tlsVersionSSL30:
				findings = append(findings, model.Finding{
					Category:    "TLS/SSL",
					Severity:    model.SeverityHigh,
					Title:       fmt.Sprintf("SSLv3 is accepted by %s", ep.Host),
					Description: fmt.Sprintf("The server on %s completed an SSLv3 handshake (ServerHello version 0x0300), so SSLv3 is still enabled. SSLv3 requires no integrity protection after the MAC-then-encrypt step, which lets a network attacker recover plaintext from roughly one byte per request by injecting chosen plaintext and observing ciphertext — the POODLE attack (CVE-2014-3566). Because SSLv3 has no secure mode, there is no way to keep the protocol and fix it.", ep.Host),
					URL:         siteURL,
					Method:      "TLS",
					Evidence:    model.Evidence{Notes: fmt.Sprintf("Raw ClientHello with record version 0x0300 was answered with a ServerHello of version %s. Record version seen: %s.", tlsVersionName(res.SelVersion), tlsVersionName(res.RecordVersion))},
					Remediation: "Remove SSLv3 from the server configuration entirely (for OpenSSL: SSLProtocol -SSLv3, or ssl_protocols TLSv1.2 TLSv1.3 in nginx).",
				})
			case tlsVersionTLS10:
				rawTLS10 = true
			case tlsVersionTLS11:
				findings = append(findings, model.Finding{
					Category:    "TLS/SSL",
					Severity:    model.SeverityLow,
					Title:       fmt.Sprintf("TLS 1.1 is accepted by %s", ep.Host),
					Description: fmt.Sprintf("The server on %s completed a TLS 1.1 handshake, so the server's minimum protocol version is at or below TLS 1.1. TLS 1.1 is deprecated (RFC 8996) and provides no defence against the CBC padding oracles and the BEAST-style chosen-boundary issues that TLS 1.2 was designed to address.", ep.Host),
					URL:         siteURL,
					Method:      "TLS",
					Evidence:    model.Evidence{Notes: fmt.Sprintf("Raw ClientHello with record version 0x0302 was answered with a ServerHello of version %s; the server accepted suite 0x%04x.", tlsVersionName(res.SelVersion), res.SelCipher)},
					Remediation: "Raise the minimum protocol version to TLS 1.2 (nginx: ssl_protocols TLSv1.2 TLSv1.3).",
				})
			}
		}
		if rawTLS10 {
			findings = append(findings, model.Finding{
				Category:    "TLS/SSL",
				Severity:    model.SeverityMedium,
				Title:       fmt.Sprintf("TLS 1.0 is accepted by %s", ep.Host),
				Description: fmt.Sprintf("The server on %s completed a TLS 1.0 handshake, so the server's minimum protocol version is at or below TLS 1.0. TLS 1.0 is deprecated (RFC 8996) and is vulnerable to BEAST (CVE-2011-3389) when a CBC cipher suite is negotiated, because the initialisation vector for the first block is predictable.", ep.Host),
				URL:         siteURL,
				Method:      "TLS",
				Evidence:    model.Evidence{Notes: "Raw ClientHello with record version 0x0301 was answered with a ServerHello of version 0x0301 (TLS 1.0), proving the server minimum is at or below TLS 1.0."},
				Remediation: "Raise the minimum protocol version to TLS 1.2 and, if legacy clients genuinely need TLS 1.0, move them behind a dedicated endpoint (nginx: ssl_protocols TLSv1.2 TLSv1.3).",
			})
		}

		// Broken cipher suites: each weak family is offered on its own, at
		// TLS 1.2, so an accepted handshake proves the suite is enabled.
		for _, group := range tlsWeakCipherGroups {
			res, ok := tlsRawHello(ctx, lim, ep, tlsVersionTLS12, group.Ciphers)
			if !ok {
				continue
			}
			findings = append(findings, model.Finding{
				Category:    "TLS/SSL",
				Severity:    group.Severity,
				Title:       fmt.Sprintf("Weak cipher suite accepted by %s: %s", ep.Host, group.Label),
				Description: fmt.Sprintf("The server on %s negotiated a %s when it was offered as the only option (selected suite 0x%04x). %s Accepting a suite means the server is willing to use it, so any client that offers it — including an attacker who downgrades the negotiation — gets the weakened protection.", ep.Host, group.Label, res.SelCipher, group.Note),
				URL:         siteURL,
				Method:      "TLS",
				Evidence:    model.Evidence{Notes: fmt.Sprintf("A ClientHello offering only the %s suites completed a handshake with ServerHello version %s and cipher suite 0x%04x.", group.Label, tlsVersionName(res.SelVersion), res.SelCipher)},
				Remediation: "Remove the weak suites from the server's cipher list and keep only AEAD suites (for OpenSSL: 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5'), then re-run this check to confirm.",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() < findings[j].Severity.Rank()
		}
		return findings[i].Title < findings[j].Title
	})
	return findings
}
