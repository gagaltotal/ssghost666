// Package report renders scan results two ways: colorized, readable
// terminal output as the scan runs, and a self-contained HTML file with
// full request/response evidence for sharing afterward.
package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"ssghost666/internal/model"
)

// Terminal is a small stateful printer so main.go doesn't have to pass
// the no-color flag into every call.
type Terminal struct {
	NoColor bool
	start   time.Time
}

func NewTerminal(noColor bool) *Terminal {
	return &Terminal{NoColor: noColor, start: time.Now()}
}

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cMagen  = "\033[35m"
	cCyan   = "\033[36m"
	cGray   = "\033[90m"
)

func (t *Terminal) c(code, s string) string {
	if t.NoColor {
		return s
	}
	return code + s + cReset
}

func severityColor(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return cRed + cBold
	case model.SeverityHigh:
		return cRed
	case model.SeverityMedium:
		return cYellow
	case model.SeverityLow:
		return cBlue
	default:
		return cGray
	}
}

// Banner prints the startup banner plus the resolved run configuration.
func (t *Terminal) Banner(text, target string, depth int, checks string) {
	fmt.Fprint(os.Stderr, t.c(cCyan, text))
	fmt.Fprintf(os.Stderr, "%s %s\n", t.c(cBold, "target:"), target)
	fmt.Fprintf(os.Stderr, "%s %d    %s %s\n\n", t.c(cBold, "depth:"), depth, t.c(cBold, "checks:"), checks)
}

// Section prints a phase header, e.g. "CRAWLING", "DISCOVERY", "SCANNING".
func (t *Terminal) Section(name string) {
	fmt.Fprintf(os.Stderr, "\n%s %s\n", t.c(cBold+cMagen, "▶"), t.c(cBold, strings.ToUpper(name)))
}

// Info prints a dim, single-line progress message (verbose-only output
// from main.go should gate calls to this itself; Terminal doesn't know
// about -v).
func (t *Terminal) Info(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", t.c(cGray, "·"), fmt.Sprintf(format, a...))
}

// Warn prints a yellow warning line.
func (t *Terminal) Warn(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "  %s %s\n", t.c(cYellow, "!"), fmt.Sprintf(format, a...))
}

// FindingLive prints one finding the moment it's confirmed, so a long
// scan shows results as they happen rather than only at the very end.
func (t *Terminal) FindingLive(f model.Finding) {
	fmt.Fprintf(os.Stderr, "  %s %-8s %s %s\n",
		t.c(severityColor(f.Severity), "["+string(f.Severity)+"]"),
		f.Category,
		t.c(cBold, f.Title),
		t.c(cGray, f.Method+" "+f.URL),
	)
}

// Summary prints the final severity-count table and full findings list.
func (t *Terminal) Summary(findings []model.Finding, visitedPages, totalRequests int) {
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Fprintf(os.Stderr, "\n%s\n", t.c(cBold, strings.Repeat("═", 60)))
	fmt.Fprintf(os.Stderr, "%s  %d findings · %d pages crawled · %d requests sent · %s\n",
		t.c(cBold, "SCAN COMPLETE"), len(findings), visitedPages, totalRequests, time.Since(t.start).Round(time.Second))
	fmt.Fprintf(os.Stderr, "%s\n\n", t.c(cBold, strings.Repeat("═", 60)))

	order := []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	for _, s := range order {
		if counts[s] == 0 {
			continue
		}
		fmt.Fprintf(os.Stderr, "  %s %d\n", t.c(severityColor(s), fmt.Sprintf("%-9s", s)), counts[s])
	}
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, t.c(cGreen, "  No issues found by the checks that ran."))
		return
	}
	fmt.Fprintln(os.Stderr)

	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "%s %s  %s\n", t.c(severityColor(f.Severity), "["+string(f.Severity)+"]"), t.c(cBold, f.Title), t.c(cGray, f.ID))
		fmt.Fprintf(os.Stderr, "  %-11s %s\n", "category:", f.Category)
		fmt.Fprintf(os.Stderr, "  %-11s %s %s\n", "request:", f.Method, f.URL)
		if f.Parameter != "" {
			fmt.Fprintf(os.Stderr, "  %-11s %s\n", "parameter:", f.Parameter)
		}
		fmt.Fprintf(os.Stderr, "  %-11s %s\n", "details:", wrap(f.Description, 78, "              "))
		if f.Remediation != "" {
			fmt.Fprintf(os.Stderr, "  %-11s %s\n", "fix:", wrap(f.Remediation, 78, "              "))
		}
		fmt.Fprintln(os.Stderr)
	}
}

func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n"+indent)
}
