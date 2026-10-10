package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// --- GraphQL introspection & injection --------------------------------------
//
// GraphQL endpoints are found in two ways: any crawled/common target whose
// path or parameters look GraphQL-ish, plus the conventional endpoint
// paths probed directly on every distinct origin. Once an endpoint
// answers as GraphQL (a {"data":...} / {"errors":[...]} envelope, or the
// classic "must provide query string" / introspection-validation error),
// three things are checked: whether introspection is left enabled (a
// schema-disclosure issue in its own right), whether an unauthenticated
// caller can reach data an authenticated baseline saw (authorization
// bypass / IDOR), and whether the query/resolver layer leaks errors or
// SQL errors that indicate injection.

const graphqlQuery = `{"query":"query{__schema{queryType{name} mutationType{name} subscriptionType{name} types{name kind}}}"}`

// graphqlPayloads are cheaper, always-needed probes sent before the big
// introspection payload. The malformed one is what proves the endpoint is
// really evaluating GraphQL rather than echoing JSON.
var graphqlProbes = []string{
	`{"query":"{__typename}"}`,
	`{"query":"{"}`, // deliberately malformed: a GraphQL server reports a syntax error
	`{"query":"query{__typename}"}`,
}

var graphqlPaths = []string{
	"/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/gql",
	"/query", "/api/query", "/graphiql", "/api/graphql/v1", "/index.php?graphql",
}

var graphqlIndicators = []string{
	"__schema", "__typename", "queryType", "mutationType", "GraphQL",
	"must provide query string", "Cannot query field", "Syntax Error",
	"GraphQLError", "graphql", "Unknown argument",
}

// graphqlContentTypeOf picks the body encoding the endpoint appears to
// use: JSON for everything except a form-encoded body target.
func graphqlContentTypeOf(t model.Target) string {
	if strings.Contains(strings.ToLower(t.ContentType), "form-urlencoded") {
		return "application/x-www-form-urlencoded"
	}
	return "application/json"
}

// graphqlEncodeBody wraps a raw GraphQL query in the encoding the
// endpoint expects (JSON {"query":...} or a form field).
func graphqlEncodeBody(rawQuery, contentType string) string {
	if strings.Contains(contentType, "form-urlencoded") {
		return "query=" + url.QueryEscape(rawQuery)
	}
	b, _ := json.Marshal(map[string]string{"query": rawQuery})
	return string(b)
}

// graphqlRespondsAsGraphQL reports whether an exchange looks like a
// GraphQL endpoint answered it.
func graphqlRespondsAsGraphQL(ex *httpclient.Exchange) bool {
	if ex == nil || ex.Response == nil || ex.Err != nil {
		return false
	}
	if ex.Response.StatusCode == 404 || ex.Response.StatusCode == 405 {
		return false
	}
	body := ex.Body
	if strings.Contains(body, `"data"`) || strings.Contains(body, `"errors"`) {
		// The envelope alone is weak (any JSON API), so require a
		// GraphQL-ish token too.
		for _, ind := range graphqlIndicators {
			if strings.Contains(body, ind) {
				return true
			}
		}
	}
	if ex.Response.StatusCode == 400 {
		for _, ind := range []string{"query string", "Syntax Error", "Cannot query field", "GraphQL", "Unknown argument"} {
			if strings.Contains(body, ind) {
				return true
			}
		}
	}
	return false
}

// graphqlCandidateTargets builds the list of (method, URL, content-type)
// targets to probe for GraphQL: every distinct origin's conventional
// paths, plus any crawled target that already looks GraphQL-ish.
func graphqlCandidateTargets(all []model.Target) []model.Target {
	seen := map[string]bool{}
	var out []model.Target
	add := func(t model.Target) {
		k := t.Key()
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, t)
	}

	origins := map[string]bool{}
	for _, t := range all {
		if u, err := url.Parse(t.URL); err == nil {
			origins[u.Scheme+"://"+u.Host] = true
		}
		if looksGraphQLTarget(t) {
			add(t)
		}
	}
	var sortedOrigins []string
	for o := range origins {
		sortedOrigins = append(sortedOrigins, o)
	}
	sort.Strings(sortedOrigins)
	for _, o := range sortedOrigins {
		for _, p := range graphqlPaths {
			add(model.Target{Method: "POST", URL: o + p, Source: "graphql"})
			add(model.Target{Method: "GET", URL: o + p, Source: "graphql"})
		}
	}
	return out
}

func looksGraphQLTarget(t model.Target) bool {
	low := strings.ToLower(t.URL)
	if strings.Contains(low, "graphql") || strings.Contains(low, "/gql") {
		return true
	}
	if strings.Contains(low, "graphiql") {
		return true
	}
	for _, p := range t.Params {
		if strings.EqualFold(p.Name, "query") && p.Location == model.LocBody {
			return true
		}
	}
	return false
}

// CheckGraphQLEndpoint probes a single candidate endpoint. It is
// safe to call against endpoints that turn out not to be GraphQL: those
// simply return no findings.
func CheckGraphQLEndpoint(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, hasAuth bool) []model.Finding {
	method := t.Method
	if method == "" {
		method = "POST"
	}
	ct := graphqlContentTypeOf(t)

	// Identify: send a malformed query; a real GraphQL server answers
	// with a GraphQL-shaped error, a non-GraphQL endpoint with something
	// else entirely.
	probe := sendRawBody(ctx, lim, cli, t, method, ct, graphqlEncodeBody(`{`, ct))
	if !graphqlRespondsAsGraphQL(probe) {
		return nil
	}

	var findings []model.Finding
	findings = append(findings, model.Finding{
		Category:    "GraphQL",
		Severity:    model.SeverityInfo,
		Title:       "GraphQL endpoint detected",
		Description: fmt.Sprintf("The endpoint accepts GraphQL queries (%s %s). GraphQL APIs expose a single structured surface that frequently lacks the per-field authorization and rate limiting a REST API gets from distinct routes, so it is worth enumerating.", method, t.URL),
		URL:         t.URL,
		Method:      method,
		Parameter:   "query",
		Evidence:    model.Evidence{RequestRaw: probe.RequestRaw, ResponseRaw: probe.ResponseRaw, Notes: "Endpoint returned a GraphQL-shaped response to a malformed query."},
		Remediation: "If the API is not public, require authentication before parsing GraphQL, and disable introspection in production (see below).",
	})

	// Introspection: if the schema comes back, the whole type system
	// (including fields not exposed in any UI) is enumerable.
	intro := sendRawBody(ctx, lim, cli, t, method, ct, graphqlQuery)
	if intro.Err == nil && intro.Response != nil && strings.Contains(intro.Body, "__schema") {
		findings = append(findings, model.Finding{
			Category:    "GraphQL",
			Severity:    model.SeverityMedium,
			Title:       "GraphQL introspection enabled",
			Description: "A full introspection query returned the schema (types, queries and mutations). Introspection lets an attacker map every field and mutation the API defines, including ones no client UI exposes, which is a large step toward a targeted attack on missing authorization.",
			URL:         t.URL,
			Method:      method,
			Parameter:   "query",
			Evidence:    model.Evidence{RequestRaw: intro.RequestRaw, ResponseRaw: intro.ResponseRaw, Notes: graphqlSchemaSummary(intro.Body)},
			Remediation: "Disable introspection in production builds, or restrict it to authenticated/administrative callers. Enforce per-field authorization in resolvers regardless, since introspection being off is not a security control on its own.",
		})
	}

	// Authorization: does the same query work with and without the
	// caller's credentials?
	if hasAuth {
		anon := sendRawBodyNoAuth(ctx, lim, cli, t, method, ct, graphqlQuery)
		if anon.Err == nil && anon.Response != nil &&
			anon.Response.StatusCode < 400 &&
			strings.Contains(anon.Body, "__schema") &&
			strings.Contains(intro.Body, "__schema") {
			findings = append(findings, model.Finding{
				Category:    "GraphQL",
				Severity:    model.SeverityHigh,
				Title:       "GraphQL endpoint reachable without authentication",
				Description: "The introspection query that succeeded with the configured credentials also succeeds with those credentials removed: the endpoint does not require authentication for this operation. If any resolver protects data only by assuming the caller is authenticated, that data is exposed to anonymous requests.",
				URL:         t.URL,
				Method:      method,
				Parameter:   "query",
				Evidence:    model.Evidence{RequestRaw: anon.RequestRaw, ResponseRaw: anon.ResponseRaw, Notes: "Identical introspection response with and without the configured auth headers."},
				Remediation: "Authenticate the caller before parsing GraphQL, and enforce object- and field-level authorization inside resolvers rather than relying on the client to send credentials.",
			})
		}
	}

	// Injection: error-based SQL signatures in a resolver's error output,
	// and information disclosure via error messages.
	injBody := `{"query":"query($id:String){__typename}","variables":{"id":"1' AND 1=1-- -","name":"1' OR '1'='1"}}`
	inj := sendRawBody(ctx, lim, cli, t, method, ct, injBody)
	if inj.Err == nil && inj.Response != nil {
		if sqlErr := matchSQLError(inj.Body); sqlErr != "" {
			findings = append(findings, model.Finding{
				Category:    "GraphQL",
				Severity:    model.SeverityHigh,
				Title:       "GraphQL variable reflects a SQL error",
				Description: fmt.Sprintf("A SQL error (%q) appeared in the GraphQL error channel after a quote-bearing variable was supplied as a query variable. This usually means a resolver interpolates the variable into a SQL query instead of using a parameterized statement.", sqlErr),
				URL:         t.URL,
				Method:      method,
				Parameter:   "variables",
				Evidence:    model.Evidence{RequestRaw: inj.RequestRaw, ResponseRaw: inj.ResponseRaw, Notes: "Matched SQL error in GraphQL errors: " + sqlErr},
				Remediation: "Parameterize every SQL statement in resolvers, validate and coerce GraphQL input types before use, and stop returning raw database errors in GraphQL error extensions.",
			})
		}
	}

	// Information disclosure: stack traces / debug advice in errors.
	fullErr := sendRawBody(ctx, lim, cli, t, method, ct, graphqlEncodeBody(`{__typename @deprecated}`, ct))
	if fullErr.Err == nil && fullErr.Response != nil {
		if leak := matchGraphQLLeak(fullErr.Body); leak != "" {
			findings = append(findings, model.Finding{
				Category: "GraphQL",
				Severity: model.SeverityLow,
				Title:    "GraphQL error discloses internal details",
				Description: fmt.Sprintf("Error output leaked internal information (%q) — stack traces, file paths, library versions or "+
					"debug hints that help an attacker target the exact stack.", leak),
				URL:         t.URL,
				Method:      method,
				Parameter:   "query",
				Evidence:    model.Evidence{RequestRaw: fullErr.RequestRaw, ResponseRaw: fullErr.ResponseRaw, Notes: "Matched disclosure marker: " + leak},
				Remediation: "Return generic error messages to clients; log full details server-side. Never enable GraphQL debug/playground in production.",
			})
		}
	}

	return findings
}

// matchGraphQLLeak looks for leaky details in an error response body.
func matchGraphQLLeak(body string) string {
	for _, ind := range []string{
		"stack trace", "at Object.", "at com.", "Traceback (most recent call last)",
		"/var/www", "/usr/lib", "/app/node_modules", "node_modules/",
		"graphql-js", "GraphQL Playground", "GraphiQL", "suggestions",
	} {
		if strings.Contains(body, ind) {
			return ind
		}
	}
	return ""
}

// graphqlSchemaSummary counts the top-level types the introspection
// response named, giving the report something more meaningful than a blob.
func graphqlSchemaSummary(body string) string {
	count := strings.Count(body, `"kind"`)
	if count == 0 {
		return "Introspection response received."
	}
	return fmt.Sprintf("Introspection response named %d schemas/types.", count)
}

// RunGraphQLChecks fans the GraphQL endpoint probing out over all
// candidate targets exactly once per run.
func RunGraphQLChecks(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, targets []model.Target, hasAuth bool) []model.Finding {
	candidates := graphqlCandidateTargets(targets)
	if len(candidates) == 0 {
		return nil
	}

	var mu sync.Mutex
	var findings []model.Finding
	var wg sync.WaitGroup
	for _, t := range candidates {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			fs := CheckGraphQLEndpoint(ctx, lim, cli, t, hasAuth)
			if len(fs) == 0 {
				return
			}
			mu.Lock()
			findings = append(findings, fs...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return findings
}
