// Package model holds the shared data types passed between the crawler,
// the OpenAPI importer, the scan engine and the reporters. Keeping these
// in one neutral package avoids import cycles between internal/crawler,
// internal/openapi, internal/scanner and internal/report.
package model

import "time"

// Severity is a coarse risk rating attached to a Finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// severityRank gives a total order for sorting findings worst-first.
var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// Rank returns a sortable integer for the severity (lower = more severe).
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return 99
}

// ParamLocation describes where a testable parameter lives in a request.
type ParamLocation string

const (
	LocQuery  ParamLocation = "query"
	LocBody   ParamLocation = "body"
	LocPath   ParamLocation = "path"
	LocHeader ParamLocation = "header"
	LocCookie ParamLocation = "cookie"
)

// Param is one fuzzable input discovered on a Target.
type Param struct {
	Name     string
	Location ParamLocation
	Sample   string // example/current value, used as a baseline before fuzzing
}

// Target is a single (method, URL) combination discovered during
// crawling, brute-force discovery, or OpenAPI/Swagger import, along with
// whatever fuzzable parameters are known for it.
type Target struct {
	Method       string
	URL          string // concrete URL, path params already substituted
	Params       []Param
	BodyTemplate string // raw JSON body template, "{{PARAM:name}}" placeholders for body params
	ContentType  string
	Source       string // "crawl" | "jsextract" | "discovery" | "robots" | "sitemap" | "openapi" | "dynamic"
	RequiresAuth bool   // best-effort guess, e.g. matched an authenticated-only pattern
}

// Key returns a stable dedup key for a target.
func (t Target) Key() string {
	return t.Method + " " + t.URL
}

// Evidence is the raw request/response pair (or diff/timing notes) backing
// a Finding, shown in both the terminal (truncated) and the HTML report.
type Evidence struct {
	RequestRaw  string
	ResponseRaw string
	Notes       string // free-form extra context: timing deltas, diff summary, etc.
}

// Finding is one confirmed or suspected issue surfaced by a scanner module.
type Finding struct {
	ID          string
	Category    string // "SQL Injection", "XSS", "Command Injection", "SSRF", "Auth", "Passive", ...
	Severity    Severity
	Title       string
	Description string
	URL         string
	Method      string
	Parameter   string
	Evidence    Evidence
	Remediation string
	Timestamp   time.Time
}

// CapturedResponse is a lightweight record of one HTTP exchange made
// during crawling, kept around so passive checks can analyze it without
// re-requesting the page.
type CapturedResponse struct {
	Method     string
	URL        string
	StatusCode int
	Headers    map[string][]string
	Body       string
	RequestRaw string
	Cookies    []string // raw Set-Cookie header values
	ElapsedMS  int64
}
