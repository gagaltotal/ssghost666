package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"regexp"
	"strings"
	"time"

	"ssghost666/internal/model"
)

//go:embed template.html
var templateHTML string

// Using html/template (not text/template) is load-bearing: evidence
// fields hold raw HTTP bodies, which may contain exactly the
// <script>...</script> payloads an XSS check just confirmed were
// reflected unescaped by the TARGET. html/template auto-escapes
// everything it writes into the page, so that same payload lands in the
// report as inert text instead of becoming a stored-XSS bug in the
// report itself when someone opens it in a browser.
var tmpl = template.Must(template.New("report").Parse(templateHTML))

// Meta is the run-level information shown in the report header.
type Meta struct {
	Target        string
	Duration      time.Duration
	VisitedPages  int
	TotalRequests int
	ChecksRun     string
	Redact        bool // redact Authorization/Cookie values in evidence (default true from main.go unless -no-redact)
}

type severityCount struct {
	Severity string
	Count    int
}

type findingView struct {
	ID, Category, Severity, Title, Description string
	URL, Method, Parameter, Remediation        string
	RequestRaw, ResponseRaw, Notes             string
}

type reportData struct {
	Target         string
	GeneratedAt    string
	Duration       string
	VisitedPages   int
	TotalRequests  int
	ChecksRun      string
	TotalFindings  int
	SeverityCounts []severityCount
	Findings       []findingView
}

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?im)^(Authorization:\s*Bearer\s+)\S+`),
	regexp.MustCompile(`(?im)^(Authorization:\s*Basic\s+)\S+`),
	regexp.MustCompile(`(?im)^(Cookie:\s*).+$`),
	regexp.MustCompile(`(?im)^(Set-Cookie:\s*).+$`),
}

func redact(s string) string {
	for _, re := range redactPatterns {
		s = re.ReplaceAllString(s, "${1}[REDACTED — rerun with -no-redact to include this in the report]")
	}
	return s
}

// Generate renders the full HTML report to a string.
func Generate(findings []model.Finding, meta Meta) (string, error) {
	data := reportData{
		Target:        meta.Target,
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05 MST"),
		Duration:      meta.Duration.Round(time.Second).String(),
		VisitedPages:  meta.VisitedPages,
		TotalRequests: meta.TotalRequests,
		ChecksRun:     meta.ChecksRun,
		TotalFindings: len(findings),
	}

	order := []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	for _, s := range order {
		if counts[s] > 0 {
			data.SeverityCounts = append(data.SeverityCounts, severityCount{Severity: string(s), Count: counts[s]})
		}
	}

	for _, f := range findings {
		reqRaw, respRaw := f.Evidence.RequestRaw, f.Evidence.ResponseRaw
		if meta.Redact {
			reqRaw = redact(reqRaw)
			respRaw = redact(respRaw)
		}
		data.Findings = append(data.Findings, findingView{
			ID:          f.ID,
			Category:    f.Category,
			Severity:    string(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			URL:         f.URL,
			Method:      f.Method,
			Parameter:   f.Parameter,
			Remediation: f.Remediation,
			RequestRaw:  strings.TrimSpace(reqRaw),
			ResponseRaw: strings.TrimSpace(respRaw),
			Notes:       f.Evidence.Notes,
		})
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering HTML report: %w", err)
	}
	return buf.String(), nil
}

// WriteFile renders the report and writes it to path.
func WriteFile(findings []model.Finding, meta Meta, path string) error {
	html, err := Generate(findings, meta)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(html), 0o644)
}
