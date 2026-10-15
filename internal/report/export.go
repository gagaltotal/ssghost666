package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ssghost666/internal/model"
)

// --- Machine-readable report exporters ---------------------------------------
//
// The HTML report is for humans; these exporters turn the same findings into
// formats that other tooling consumes directly:
//
//   * JSON  — a flat array of finding objects, for scripting, dashboards and
//             anything that wants the raw fields without parsing a document.
//   * CSV   — RFC 4180 records, for spreadsheets and Jira/ServiceNow bulk
//             imports.
//   * SARIF — the OASIS static-analysis interchange format (2.1.0), which is
//             what GitHub code scanning, Azure DevOps, DefectDojo, Faraday
//             and most SIEM/SOAR pipelines ingest natively.
//
// All three reuse the HTML path's evidence redaction rules, so a report
// written with -out-format json is no more likely to leak Authorization or
// Cookie values than the HTML one. Redaction is applied to the request and
// response evidence only; URLs and parameter names are preserved verbatim
// because a sanitised URL would make the report unusable.

// NormalizeFormat resolves the requested output format, allowing "auto" to be
// decided from the output file's extension.
func NormalizeFormat(format, path string) (string, error) {
	f := strings.ToLower(strings.TrimSpace(format))
	if f == "" {
		f = "auto"
	}
	if f != "auto" {
		switch f {
		case "html", "htm":
			return "html", nil
		case "json":
			return "json", nil
		case "csv":
			return "csv", nil
		case "sarif":
			return "sarif", nil
		}
		return "", fmt.Errorf("unknown report format %q (expected auto, html, json, csv or sarif)", format)
	}

	// auto: decide from the extension. ".sarif" and ".sarif.json" must be
	// checked before the generic ".json" case, otherwise a SARIF file named
	// scan.sarif.json would silently become a plain JSON report.
	low := strings.ToLower(path)
	switch {
	case strings.HasSuffix(low, ".sarif"), strings.HasSuffix(low, ".sarif.json"):
		return "sarif", nil
	case strings.HasSuffix(low, ".json"):
		return "json", nil
	case strings.HasSuffix(low, ".csv"):
		return "csv", nil
	case strings.HasSuffix(low, ".html"), strings.HasSuffix(low, ".htm"):
		return "html", nil
	}
	return "html", nil // no recognisable extension: HTML is the historical default
}

// exportedFinding is the JSON shape of one finding. Field names are stable and
// snake-free so downstream consumers can rely on them.
type exportedFinding struct {
	ID          string           `json:"id"`
	Category    string           `json:"category"`
	Severity    string           `json:"severity"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	URL         string           `json:"url"`
	Method      string           `json:"method"`
	Parameter   string           `json:"parameter"`
	Remediation string           `json:"remediation"`
	Timestamp   string           `json:"timestamp"`
	Evidence    exportedEvidence `json:"evidence"`
}

type exportedEvidence struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Notes    string `json:"notes"`
}

// exportedReport is the top-level JSON document: run metadata plus findings.
// A bare array would lose the context needed to interpret the results, so the
// metadata is always included alongside the findings array.
type exportedReport struct {
	Tool          string            `json:"tool"`
	ToolVersion   string            `json:"tool_version"`
	Target        string            `json:"target"`
	GeneratedAt   string            `json:"generated_at"`
	DurationSecs  float64           `json:"duration_seconds"`
	VisitedPages  int               `json:"visited_pages"`
	TotalRequests int               `json:"total_requests"`
	ChecksRun     string            `json:"checks_run"`
	TotalFindings int               `json:"total_findings"`
	SeverityCount map[string]int    `json:"severity_counts"`
	Findings      []exportedFinding `json:"findings"`
}

// prepareFindings converts model findings into the shared export shape,
// applying the same redaction rules as the HTML report, and sorts them
// most-severe-first so every format presents the same ordering.
func prepareFindings(findings []model.Finding, meta Meta) []exportedFinding {
	out := make([]exportedFinding, 0, len(findings))
	for _, f := range findings {
		reqRaw, respRaw := f.Evidence.RequestRaw, f.Evidence.ResponseRaw
		if meta.Redact {
			reqRaw = redact(reqRaw)
			respRaw = redact(respRaw)
		}
		ts := f.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		out = append(out, exportedFinding{
			ID:          f.ID,
			Category:    f.Category,
			Severity:    string(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			URL:         f.URL,
			Method:      f.Method,
			Parameter:   f.Parameter,
			Remediation: f.Remediation,
			Timestamp:   ts.UTC().Format(time.RFC3339),
			Evidence: exportedEvidence{
				Request:  strings.TrimSpace(reqRaw),
				Response: strings.TrimSpace(respRaw),
				Notes:    f.Evidence.Notes,
			},
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri := model.Severity(out[i].Severity).Rank()
		rj := model.Severity(out[j].Severity).Rank()
		if ri != rj {
			return ri < rj
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// severityCounts tallies findings per severity, including zero entries so a
// consumer can rely on every key being present.
func severityCounts(findings []model.Finding) map[string]int {
	counts := map[string]int{
		string(model.SeverityCritical): 0,
		string(model.SeverityHigh):     0,
		string(model.SeverityMedium):   0,
		string(model.SeverityLow):      0,
		string(model.SeverityInfo):     0,
	}
	for _, f := range findings {
		counts[string(f.Severity)]++
	}
	return counts
}

// GenerateJSON renders the findings as an indented JSON document.
func GenerateJSON(findings []model.Finding, meta Meta) ([]byte, error) {
	doc := exportedReport{
		Tool:          "SSGhost666",
		ToolVersion:   meta.ToolVersion,
		Target:        meta.Target,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		DurationSecs:  meta.Duration.Seconds(),
		VisitedPages:  meta.VisitedPages,
		TotalRequests: meta.TotalRequests,
		ChecksRun:     meta.ChecksRun,
		TotalFindings: len(findings),
		SeverityCount: severityCounts(findings),
		Findings:      prepareFindings(findings, meta),
	}
	buf, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding JSON report: %w", err)
	}
	return append(buf, '\n'), nil
}

// csvColumns is the fixed column order of the CSV report. Keeping it fixed
// (rather than deriving it) means a consumer's header mapping never shifts
// because a particular run happened to produce no findings in some category.
var csvColumns = []string{
	"id", "severity", "category", "title", "url", "method", "parameter",
	"description", "remediation", "timestamp", "evidence_notes",
	"evidence_request", "evidence_response",
}

// GenerateCSV renders the findings as RFC 4180 CSV. encoding/csv handles
// quoting, embedded commas, quotes and newlines, so evidence blocks containing
// raw HTTP text are safe.
func GenerateCSV(findings []model.Finding, meta Meta) ([]byte, error) {
	rows := prepareFindings(findings, meta)

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(csvColumns); err != nil {
		return nil, fmt.Errorf("encoding CSV header: %w", err)
	}
	for _, f := range rows {
		if err := w.Write([]string{
			f.ID,
			f.Severity,
			f.Category,
			f.Title,
			f.URL,
			f.Method,
			f.Parameter,
			f.Description,
			f.Remediation,
			f.Timestamp,
			f.Evidence.Notes,
			f.Evidence.Request,
			f.Evidence.Response,
		}); err != nil {
			return nil, fmt.Errorf("encoding CSV row: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("encoding CSV report: %w", err)
	}
	return buf.Bytes(), nil
}

// --- SARIF 2.1.0 -------------------------------------------------------------

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	FullDescription  sarifMessage      `json:"fullDescription,omitempty"`
	Help             sarifMessage      `json:"help,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

var sarifSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

// sarifRuleID turns a finding category into a stable, lowercase rule
// identifier (e.g. "SQL Injection" -> "sql-injection").
func sarifRuleID(category string) string {
	slug := sarifSlugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(category)), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		return "ssghost666-finding"
	}
	return slug
}

// sarifLevel maps the tool's severity onto SARIF's four-level scale: only
// critical and high issues are treated as errors, so a pipeline that fails on
// "error" is not tripped by informational results.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifFingerprint is a stable content hash of the finding's identity. SARIF
// consumers use partialFingerprints to track an issue across runs (suppressing
// it once triaged, re-opening it if the location or nature changes), so it must
// depend only on stable fields and never on the volatile ID or timestamp.
func sarifFingerprint(f model.Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		f.Category, f.Method, f.URL, f.Parameter, f.Title,
	}, "|")))
	return hex.EncodeToString(h[:])
}

// GenerateSARIF renders the findings as a SARIF 2.1.0 log. One rule is emitted
// per distinct category so that every result references a declared rule, which
// SARIF requires and which is what makes the results group sensibly in a
// code-scanning UI.
func GenerateSARIF(findings []model.Finding, meta Meta) ([]byte, error) {
	rows := prepareFindings(findings, meta)

	ruleIndex := map[string]int{}
	rules := []sarifRule{} // non-nil: SARIF consumers expect an array, not null

	results := make([]sarifResult, 0, len(rows))
	for _, f := range rows {
		ruleID, ok := ruleIndex[f.Category]
		if !ok {
			ruleID = len(rules)
			ruleIndex[f.Category] = ruleID
			rules = append(rules, sarifRule{
				ID:               sarifRuleID(f.Category),
				Name:             sarifRuleID(f.Category),
				ShortDescription: sarifMessage{Text: f.Category},
				FullDescription:  sarifMessage{Text: f.Category + " findings reported by SSGhost666."},
				Help:             sarifMessage{Text: "Remediation: " + firstNonEmptyStr(f.Remediation, "see the finding description")},
				Properties:       map[string]string{"category": f.Category},
			})
		}

		msg := f.Title
		if f.Description != "" {
			msg = f.Title + " — " + f.Description
		}
		if f.Parameter != "" {
			msg += " (parameter: " + f.Parameter + ")"
		}

		props := map[string]string{}
		if f.Severity != "" {
			props["severity"] = f.Severity
		}
		if f.Category != "" {
			props["category"] = f.Category
		}

		results = append(results, sarifResult{
			RuleID:              sarifRuleID(f.Category),
			RuleIndex:           ruleID,
			Level:               sarifLevel(model.Severity(f.Severity)),
			Message:             sarifMessage{Text: msg},
			Locations:           []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: f.URL}}}},
			PartialFingerprints: map[string]string{"ssghost666Finding/v1": sarifFingerprint(model.Finding{Category: f.Category, Method: f.Method, URL: f.URL, Parameter: f.Parameter, Title: f.Title})},
			Properties:          props,
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "SSGhost666",
				Version:        meta.ToolVersion,
				InformationURI: "https://github.com/gagaltotal/ssghost666",
				Rules:          rules,
			}},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful: true,
				EndTimeUTC:          time.Now().UTC().Format(time.RFC3339),
			}},
			Results: results,
		}},
	}

	buf, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding SARIF report: %w", err)
	}
	return append(buf, '\n'), nil
}

// firstNonEmptyStr is a tiny local helper so export.go does not depend on any
// scanner-package utility.
func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// GenerateFormatted renders the findings in the requested format.
func GenerateFormatted(findings []model.Finding, meta Meta, format string) ([]byte, string, error) {
	switch format {
	case "json":
		b, err := GenerateJSON(findings, meta)
		return b, "application/json", err
	case "csv":
		b, err := GenerateCSV(findings, meta)
		return b, "text/csv", err
	case "sarif":
		b, err := GenerateSARIF(findings, meta)
		return b, "application/json", err
	case "html":
		s, err := Generate(findings, meta)
		return []byte(s), "text/html", err
	}
	return nil, "", fmt.Errorf("unknown report format %q", format)
}

// WriteFormatted renders the findings in the requested format and writes them
// to path. The format must already have been resolved by NormalizeFormat.
func WriteFormatted(findings []model.Finding, meta Meta, path, format string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("no output path given")
	}
	body, _, err := GenerateFormatted(findings, meta, format)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(path, body, 0o644)
}
