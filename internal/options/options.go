// Package options parses SSGhost666's command-line flags into a Config
// used by every other package.
package options

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// Version is the tool version, set at build time via -ldflags if desired.
var Version = "0.1.0"

// headerList implements flag.Value so -header can be passed multiple times.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ",") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// Config holds every setting the rest of the program needs.
type Config struct {
	TargetURL string
	Depth     int

	JSRender   bool
	ChromePath string

	Concurrency int
	RatePerSec  float64
	Timeout     time.Duration
	MaxRequests int

	Cookie    string
	Bearer    string
	Headers   []string
	UserAgent string

	Proxy    string
	Insecure bool

	OpenAPIPath string
	Wordlist    string
	NoDiscover  bool

	Checks  string // "all" or comma list
	Exclude string
	Scope   string

	SSRFCallback string

	OutReport string
	NoColor   bool
	NoRedact  bool
	Verbose   bool

	ShowVersion bool
}

// Parse reads os.Args[1:] into a Config, applying defaults and basic
// validation. It calls os.Exit on -h/-version or on fatal flag errors,
// matching normal CLI behaviour.
func Parse(args []string) *Config {
	fs := flag.NewFlagSet("ssghost666", flag.ExitOnError)
	cfg := &Config{}
	var headers headerList

	fs.StringVar(&cfg.TargetURL, "url", "", "Target base URL to scan, e.g. https://app.example.com (required)")
	fs.IntVar(&cfg.Depth, "depth", 2, "Crawl depth for link discovery")

	fs.BoolVar(&cfg.JSRender, "js-render", false, "Render pages with headless Chrome to discover JS-loaded routes/endpoints (requires Chrome/Chromium)")
	fs.StringVar(&cfg.ChromePath, "chrome-path", "", "Explicit path to a Chrome/Chromium binary (optional, auto-detected otherwise)")

	fs.IntVar(&cfg.Concurrency, "concurrency", 8, "Max concurrent HTTP requests")
	fs.Float64Var(&cfg.RatePerSec, "rate", 15, "Max requests per second (politeness limit)")
	fs.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "Per-request HTTP timeout")
	fs.IntVar(&cfg.MaxRequests, "max-requests", 4000, "Safety cap on total HTTP requests made during the whole scan")

	fs.StringVar(&cfg.Cookie, "cookie", "", `Cookie header to send, e.g. "session=abc123; other=1"`)
	fs.StringVar(&cfg.Bearer, "bearer", "", "Bearer token to send as Authorization: Bearer <token>")
	fs.Var(&headers, "header", `Extra header, "Key: Value" (repeatable)`)
	fs.StringVar(&cfg.UserAgent, "ua", "SSGhost666/"+Version+" (+authorized-security-scan)", "User-Agent header to send")

	fs.StringVar(&cfg.Proxy, "proxy", "", "HTTP(S) proxy URL to route all traffic through, e.g. http://127.0.0.1:8080 (Burp/ZAP/mitmproxy)")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "Skip TLS certificate verification (e.g. self-signed certs, intercepting proxy CA)")

	fs.StringVar(&cfg.OpenAPIPath, "openapi", "", "Path or URL to an OpenAPI 3 or Swagger 2 definition (JSON or YAML) to import as scan targets")
	fs.StringVar(&cfg.Wordlist, "wordlist", "", "Path to a custom wordlist for hidden file/endpoint discovery (one path per line). Defaults to a small built-in list")
	fs.BoolVar(&cfg.NoDiscover, "no-discover", false, "Disable wordlist-based hidden endpoint discovery")

	fs.StringVar(&cfg.Checks, "checks", "all", "Comma-separated active checks to run: sqli,xss,cmdi,ssrf,auth,passive,all")
	fs.StringVar(&cfg.Exclude, "exclude", "", "Regex of URLs to exclude from crawling/testing (e.g. logout endpoints)")
	fs.StringVar(&cfg.Scope, "scope", "", "Regex restricting crawl to in-scope URLs. Defaults to same host as -url")

	fs.StringVar(&cfg.SSRFCallback, "ssrf-callback", "", "Out-of-band callback URL/domain you control (e.g. Burp Collaborator, interact.sh) used as the SSRF payload target")

	fs.StringVar(&cfg.OutReport, "out", "", "Path to write an HTML report with request/response evidence (e.g. report.html)")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "Disable ANSI colour in terminal output")
	fs.BoolVar(&cfg.NoRedact, "no-redact", false, "Do not redact Authorization/Cookie values in the saved HTML report")
	fs.BoolVar(&cfg.Verbose, "v", false, "Verbose progress output")

	fs.BoolVar(&cfg.ShowVersion, "version", false, "Print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, bannerText)
		fmt.Fprintf(os.Stderr, "\nUsage:\n  ssghost666 -url https://target.example.com [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nOnly scan applications you own or are explicitly authorized to test.\n")
	}

	_ = fs.Parse(args)
	cfg.Headers = headers

	if cfg.ShowVersion {
		fmt.Println("SSGhost666 " + Version)
		os.Exit(0)
	}

	if cfg.TargetURL == "" {
		fmt.Fprintln(os.Stderr, "error: -url is required")
		fs.Usage()
		os.Exit(2)
	}

	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.RatePerSec <= 0 {
		cfg.RatePerSec = 1
	}
	if cfg.MaxRequests < 1 {
		cfg.MaxRequests = 1
	}

	return cfg
}

const bannerText = `
███████╗███████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗ ██████╗  ██████╗  ██████╗ 
██╔════╝██╔════╝██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝ ██╔════╝ ██╔════╝ 
███████╗███████╗██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗ ███████╗ ███████╗ 
╚════██║╚════██║██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔═══██╗██╔═══██╗██╔═══██╗
███████║███████║╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚██████╔╝╚██████╔╝╚██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝  ╚═════╝  ╚═════╝ 
   evidence-gathering web scanner · for authorized testing only
`

// Banner returns the startup banner text (exported for main.go).
func Banner() string { return bannerText }
