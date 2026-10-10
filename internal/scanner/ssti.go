package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- SSTI (Server-Side Template Injection) ---------------------------------
//
// Detection happens in two tiers. First a small set of engine-agnostic
// arithmetic probes: if a template engine evaluates the expression, the
// literal product shows up in the response (e.g. 49 where "7*7" was sent)
// — a signal no plain reflection or SQL/JS evaluation produces the same
// way. Second, for each engine the arithmetic hit suggests, a
// conformance payload (e.g. {{7*'7'}} which is 7777777 on Jinja2 but 49 on
// Twig) confirms which engine is actually running, which is what turns a
// vague "SSTI somewhere" into a concrete, actionable finding.

// sstiSeed is a number whose square is distinctive enough not to appear
// by accident in ordinary page content.
const sstiSeed = 7331

// sstiArithmeticProbes cover the common template delimiters. Each embeds
// sstiSeed*sstiSeed so an evaluated response contains its product.
func sstiArithmeticProbes() []string {
	expr := fmt.Sprintf("%d*%d", sstiSeed, sstiSeed)
	return []string{
		"{{" + expr + "}}",    // Jinja2, Twig, Nunjucks, Go template
		"${" + expr + "}",     // Freemarker, JSP EL, Thymeleaf
		"#{" + expr + "}",     // Ruby, some Java frameworks
		"<%= " + expr + " %>", // ERB, EJS
		"*{" + expr + "}",     // Smarty, some others
	}
}

func sstiProduct() string { return fmt.Sprintf("%d", sstiSeed*sstiSeed) }

type sstiEngine struct {
	Name     string
	Payload  string // engine-confirming payload
	Expect   string // substring expected in the response when confirmed
	Severity model.Severity
	ExecNote string
}

func sstiEngines() []sstiEngine {
	return []sstiEngine{
		{
			Name:     "Jinja2 (Python)",
			Payload:  "{{7*'7'}}",
			Expect:   "7777777",
			Severity: model.SeverityCritical,
			ExecNote: `Jinja2 evaluated {{7*'7'}} to "7777777" (string repetition), confirming a Python/Jinja2 template context in which attacker input reaches the template engine.`,
		},
		{
			Name:     "Twig (PHP)",
			Payload:  "{{7*'7'}}",
			Expect:   "49",
			Severity: model.SeverityCritical,
			ExecNote: `Twig evaluated {{7*'7'}} to 49 (numeric coercion), confirming a PHP/Twig template context.`,
		},
		{
			Name:     "Freemarker (Java)",
			Payload:  "${7*7}",
			Expect:   "49",
			Severity: model.SeverityHigh,
			ExecNote: `Freemarker evaluated ${7*7} to 49, confirming a Java/Freemarker template context.`,
		},
		{
			Name:     "Velocity (Java)",
			Payload:  "#set($x=7*7)$x",
			Expect:   "49",
			Severity: model.SeverityHigh,
			ExecNote: `Velocity evaluated #set($x=7*7)$x to 49, confirming a Java/Apache Velocity template context.`,
		},
		{
			Name:     "ERB (Ruby)",
			Payload:  "<%= 7*7 %>",
			Expect:   "49",
			Severity: model.SeverityHigh,
			ExecNote: `ERB evaluated <%= 7*7 %> to 49, confirming a Ruby/ERB template context.`,
		},
		{
			Name:     "Smarty (PHP)",
			Payload:  "{7*7}",
			Expect:   "49",
			Severity: model.SeverityHigh,
			ExecNote: `Smarty evaluated {7*7} to 49, confirming a PHP/Smarty template context.`,
		},
	}
}

var sstiErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)jinja2\.exceptions`),
	regexp.MustCompile(`(?i)freemarker\.core`),
	regexp.MustCompile(`(?i)freemarker\.template`),
	regexp.MustCompile(`(?i)org\.apache\.velocity`),
	regexp.MustCompile(`(?i)velocity\.exception`),
	regexp.MustCompile(`(?i)actionview::template::error`),
	regexp.MustCompile(`(?i)twig\\error`),
	regexp.MustCompile(`(?i)template (syntax|parse) error`),
	regexp.MustCompile(`(?i)unexpected token .* in template`),
}

func matchSSTIError(body string) string {
	for _, re := range sstiErrorPatterns {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// CheckSSTI tests one parameter for template injection.
func CheckSSTI(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, baseline *httpclient.Exchange, t model.Target, p model.Param) []model.Finding {
	product := sstiProduct()

	// Tier 1: echo-anchored arithmetic. A probe counts as evaluation
	// (rather than mere reflection) when the response drops the literal
	// payload and instead contains its product. A template error or a
	// known engine error signature is an equally strong secondary hint.
	var evidence *httpclient.Exchange
	for _, payload := range sstiArithmeticProbes() {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, payload)
		if ex.Err != nil || ex.Response == nil || len(ex.Body) == 0 {
			continue
		}
		if strings.Contains(ex.Body, payload) {
			continue // reflected verbatim — not evaluated
		}
		if strings.Contains(ex.Body, product) || matchSSTIError(ex.Body) != "" {
			evidence = ex
			break
		}
	}
	if evidence == nil {
		return nil
	}

	// Tier 2: name the engine with a conformance payload.
	for _, e := range sstiEngines() {
		ex := sendWithPayload(ctx, lim, cli, t, p.Name, e.Payload)
		if ex.Err != nil || ex.Response == nil {
			continue
		}
		if strings.Contains(ex.Body, e.Payload) {
			continue // reflected unchanged
		}
		if !strings.Contains(ex.Body, e.Expect) {
			continue
		}
		return []model.Finding{{
			Category:    "SSTI",
			Severity:    e.Severity,
			Title:       "Server-Side Template Injection (" + e.Name + ") in parameter \"" + p.Name + "\"",
			Description: e.ExecNote + fmt.Sprintf(" The engine-confirming payload was %q and the response contained %q where the payload was sent.", e.Payload, e.Expect),
			URL:         t.URL,
			Method:      t.Method,
			Parameter:   p.Name,
			Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: "Engine confirmed via " + e.Name + " payload " + e.Payload},
			Remediation: "Never build template source from user input. Pass untrusted values only as data into a fixed template, and/or use a sandboxed template environment with dangerous constructs disabled.",
		}}
	}

	return []model.Finding{{
		Category:    "SSTI",
		Severity:    model.SeverityMedium,
		Title:       "Possible template expression evaluation in parameter \"" + p.Name + "\"",
		Description: fmt.Sprintf("An arithmetic probe produced %q in the response without the payload itself being reflected — consistent with server-side expression/template evaluation, though the exact engine could not be fingerprinted. Manual verification recommended.", product),
		URL:         t.URL,
		Method:      t.Method,
		Parameter:   p.Name,
		Evidence:    model.Evidence{RequestRaw: evidence.RequestRaw, ResponseRaw: evidence.ResponseRaw, Notes: "Arithmetic probe evaluated; engine not fingerprinted."},
		Remediation: "Avoid evaluating user input as template/expression code; use fixed templates with data-only interpolation.",
	}}
}
