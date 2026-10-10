package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- Insecure deserialization ----------------------------------------------
//
// Two signals are combined. First, many apps leak that they deserialize by
// carrying a recognizable serialized object in a parameter/header (the
// base64 Java stream magic "rO0AB", a PHP "O:8:" / "a:2:{" string, a .NET
// BinaryFormatter "AAEAAAD/////", a raw pickle). Finding one of those is a
// strong hint worth surfacing even before any payload is sent. Second, a
// marker-bearing serialized payload is submitted; if the server answers
// with a deserialization error (InvalidClassException, UnpicklingError,
// unserialize(), SerializationException) that was absent from the
// baseline, the endpoint is trying to deserialize attacker input. A
// non-destructive sleep payload provides the final confirmation.

// deserSleepSeconds matches the other time-based checks' waiting budget.
const deserSleepSeconds = 5

var deserErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)java\.io\.InvalidClassException`),
	regexp.MustCompile(`(?i)java\.io\.ObjectInputStream`),
	regexp.MustCompile(`(?i)java\.lang\.ClassNotFoundException`),
	regexp.MustCompile(`(?i)cannot deserialize`),
	regexp.MustCompile(`(?i)deserializ(e|ing) (error|failed|exception)`),
	regexp.MustCompile(`(?i)unserialize\(\)`),
	regexp.MustCompile(`(?i)__PHP_Incomplete_Class`),
	regexp.MustCompile(`(?i)UnpicklingError`),
	regexp.MustCompile(`(?i)_pickle\.`),
	regexp.MustCompile(`(?i)System\.Runtime\.Serialization`),
	regexp.MustCompile(`(?i)SerializationException`),
	regexp.MustCompile(`(?i)BinaryFormatter`),
	regexp.MustCompile(`(?i)is not marked as serializable`),
	regexp.MustCompile(`(?i)ObjectInputStream`),
}

func matchDeserError(body string) string {
	for _, re := range deserErrorPatterns {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// serializedSignatures are substrings that only appear when a value is (or
// was) a serialized object, used to flag likely deserialization sinks.
var serializedSignatures = []struct{ Name, Marker string }{
	{"Java serialized stream (base64)", "rO0AB"},
	{".NET BinaryFormatter (base64)", "AAEAAAD/////"},
	{"PHP serialize() object", "O:8:"},
	{"PHP serialize() object", "O:4:"},
	{"PHP serialize() array", "a:2:{"},
}

func matchSerializedSignature(sample string) string {
	for _, sig := range serializedSignatures {
		if strings.Contains(sample, sig.Marker) {
			return sig.Name
		}
	}
	return ""
}

// deserParamHints are parameter-name substrings that tend to carry
// serialized state.
var deserParamHints = []string{
	"object", "obj", "state", "data", "session", "token", "viewstate",
	"serialize", "java", "payload", "form", "blob", "cache", "restore",
}

func looksLikeDeserParam(name string) bool {
	low := strings.ToLower(name)
	for _, hint := range deserParamHints {
		if strings.Contains(low, hint) {
			return true
		}
	}
	return false
}

// javaSerializedMarker is the base64 of the Java serialization magic
// (0xACED0005) followed by a harmless marker string, enough for a strict
// parser to attempt (and fail) deserialization, which is the signal we
// want — never a valid gadget chain.
func javaSerializedMarker(marker string) string {
	raw := []byte{0xAC, 0xED, 0x00, 0x05} // STREAM_MAGIC + STREAM_VERSION
	raw = append(raw, []byte(marker)...)
	return base64.StdEncoding.EncodeToString(raw)
}

// pickleSleepPayload is a Python pickle that calls os.system("sleep N")
// via __reduce__/system — a classic, non-destructive proof that a pickle
// sink executes attacker-controlled code. It only ever sleeps.
func pickleSleepPayload(seconds int) string {
	script := "cos\nsystem\n(S'" + fmt.Sprintf("sleep %d", seconds) + "'\ntR."
	return base64.StdEncoding.EncodeToString([]byte(script))
}

// deserPayloads returns the marker-bearing payloads tried per parameter.
func deserPayloads(marker string) []string {
	return []string{
		javaSerializedMarker(marker),
		base64.StdEncoding.EncodeToString([]byte(`O:8:"stdClass":1:{s:1:"a";s:6:"` + marker + `";}`)),
	}
}

// deserHeaders are request headers a Java/.NET app might deserialize.
var deserHeaders = []string{
	"X-Java-Serialized-Object",
	"X-Object",
	"X-Serialized",
	"X-Data",
}

// CheckDeserialization tests a target for insecure deserialization.
func CheckDeserialization(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target) []model.Finding {
	var findings []model.Finding

	// Signal A: a serialized object already visible in the request.
	for _, p := range fuzzableParams(t) {
		if name := matchSerializedSignature(p.Sample); name != "" {
			findings = append(findings, model.Finding{
				Category:    "Insecure Deserialization",
				Severity:    model.SeverityMedium,
				Title:       "Serialized object found in parameter \"" + p.Name + "\"",
				Description: fmt.Sprintf("Parameter %q carries what looks like a %s value. If the server deserializes this value without integrity checks, it may be exploitable for object injection / remote code execution.", p.Name, name),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   p.Name,
				Evidence:    model.Evidence{Notes: "Matched serialized signature: " + name},
				Remediation: "Never deserialize untrusted input. Prefer a data-only format (JSON) with a strict schema, sign serialized blobs and verify the signature, and if a serialized format is unavoidable, use an allowlist of permitted classes.",
			})
		}
	}

	// Signal B: header-based deserialization probes.
	for _, h := range deserHeaders {
		probe := t
		probe.Params = append(append([]model.Param(nil), t.Params...),
			model.Param{Name: h, Location: model.LocHeader, Sample: "application/x-java-serialized-object"})
		ex := sendWithPayload(ctx, lim, cli, probe, h, javaSerializedMarker(Marker()))
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		if sig := matchDeserError(ex.Body); sig != "" && (baseline == nil || !strings.Contains(baseline.Body, sig)) {
			findings = append(findings, deserErrorFinding(t, h, "header", sig, ex))
		}
	}

	// Signal C: parameter injection + (D) sleep-based confirmation.
	for _, p := range fuzzableParams(t) {
		if !looksLikeDeserParam(p.Name) && matchSerializedSignature(p.Sample) == "" {
			continue
		}
		marker := Marker()
		for _, payload := range deserPayloads(marker) {
			ex := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
			if ex.Err != nil || ex.Response == nil {
				continue
			}
			if sig := matchDeserError(ex.Body); sig != "" && (baseline == nil || !strings.Contains(baseline.Body, sig)) {
				findings = append(findings, deserErrorFinding(t, p.Name, "parameter", sig, ex))
				break
			}
		}

		// Sleep-based confirmation: only when a serialized signature was
		// already present (so we are confident a pickle-capable sink is
		// even plausible) to avoid a multi-second delay on every field.
		if matchSerializedSignature(p.Sample) == "" {
			continue
		}
		payload := pickleSleepPayload(deserSleepSeconds)
		threshold := int64(deserSleepSeconds*1000) - 1200
		ex1 := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex1.Err != nil || ex1.Response == nil || ex1.ElapsedMS < threshold {
			continue
		}
		time.Sleep(300 * time.Millisecond)
		ex2 := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex2.Err != nil || ex2.Response == nil || ex2.ElapsedMS < threshold {
			continue
		}
		findings = append(findings, model.Finding{
			Category:    "Insecure Deserialization",
			Severity:    model.SeverityCritical,
			Title:       "Confirmed insecure deserialization in parameter \"" + p.Name + "\" (pickle sleep executed)",
			Description: fmt.Sprintf("A Python pickle payload whose only action is `sleep %d` made the response consistently take about %dms and %dms (two independent requests) versus a normal baseline — the server deserialized and executed attacker-controlled object data.", deserSleepSeconds, ex1.ElapsedMS, ex2.ElapsedMS),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   p.Name,
			Evidence:    model.Evidence{RequestRaw: ex2.RequestRaw, ResponseRaw: ex2.ResponseRaw, Notes: fmt.Sprintf("Confirmation request 1: %dms, request 2: %dms, baseline: %dms", ex1.ElapsedMS, ex2.ElapsedMS, safeElapsed(baseline))},
			Remediation: "Never deserialize untrusted input. Replace pickle/native serialization with a data-only format (JSON) validated against a schema, or use a safe deserializer with class allowlisting and signed payloads.",
		})
		break
	}

	return findings
}

func deserErrorFinding(t model.Target, name, where, sig string, ex *httpclient.Exchange) model.Finding {
	return model.Finding{
		Category:    "Insecure Deserialization",
		Severity:    model.SeverityHigh,
		Title:       "Deserialization error triggered via " + where + " \"" + name + "\"",
		Description: fmt.Sprintf("A marker-bearing serialized payload sent via the %s %q made the server respond with a deserialization error (%q) that was not present at baseline, indicating the endpoint attempts to deserialize attacker-influenced data.", where, name, sig),
		URL:         t.URL,
		Method:      t.Method,
		Parameter:   name,
		Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Matched deserialization error signature: " + sig},
		Remediation: "Do not deserialize untrusted input. Use a data-only format with strict validation, and avoid leaking deserialization errors to clients.",
	}
}
