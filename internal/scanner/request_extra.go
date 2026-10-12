package scanner

import (
	"context"
	"net/url"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// sendRawBody sends target's URL (carrying its baseline query parameters)
// with a caller-supplied method, Content-Type and raw body. It exists for
// checks whose payload is not a simple per-parameter substitution — XML
// documents (XXE), serialized blobs (deserialization) and GraphQL JSON —
// while still acquiring the shared rate limiter so these requests are
// paced and concurrency-bounded exactly like every other scanner request.
func sendRawBody(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, method, contentType, body string) *httpclient.Exchange {
	return sendRawBodyWithAuth(ctx, lim, cli, t, method, contentType, body, true)
}

// sendRawBodyNoAuth is like sendRawBody but drops the client's default
// Cookie/Authorization headers, used to compare authenticated vs
// unauthenticated access to the same raw-body endpoint (GraphQL checks).
func sendRawBodyNoAuth(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, method, contentType, body string) *httpclient.Exchange {
	return sendRawBodyWithAuth(ctx, lim, cli, t, method, contentType, body, false)
}

// sendQueryFragment appends a caller-supplied raw query fragment to the
// target URL and sends the request with a GET (or the target's method if
// set). It exists for checks like prototype pollution that need to inject
// a *new* nested query parameter (e.g. "__proto__[x]=true") rather than
// replace the value of one of the target's known params — something
// sendWithPayload deliberately does not do, since it only substitutes
// values of declared params.
func sendQueryFragment(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, fragment string) *httpclient.Exchange {
	if !lim.Acquire(ctx) {
		return &httpclient.Exchange{Err: context.Canceled}
	}
	defer lim.Release()

	reqURL := t.URL
	if u, err := url.Parse(t.URL); err == nil {
		q := u.Query()
		for _, p := range t.Params {
			if p.Location == model.LocQuery {
				q.Set(p.Name, p.Sample)
			}
		}
		encoded := q.Encode()
		if encoded != "" {
			encoded += "&"
		}
		encoded += fragment
		u.RawQuery = encoded
		reqURL = u.String()
	} else {
		sep := "?"
		if strings.Contains(reqURL, "?") {
			sep = "&"
		}
		reqURL = reqURL + sep + fragment
	}

	method := t.Method
	if method == "" {
		method = "GET"
	}
	// Query-fragment injection is a GET-style test; forcing GET avoids
	// mutating resources via an unexpected method on the target.
	if method != "GET" && method != "HEAD" {
		method = "GET"
	}
	ex := cli.Do(method, reqURL, nil, nil)
	observeForAdaptive(lim, ex)
	return ex
}

func sendRawBodyWithAuth(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, method, contentType, body string, auth bool) *httpclient.Exchange {
	if !lim.Acquire(ctx) {
		return &httpclient.Exchange{Err: context.Canceled}
	}
	defer lim.Release()

	reqURL := t.URL
	if u, err := url.Parse(t.URL); err == nil {
		q := u.Query()
		for _, p := range t.Params {
			if p.Location == model.LocQuery {
				q.Set(p.Name, p.Sample)
			}
		}
		u.RawQuery = q.Encode()
		reqURL = u.String()
	}

	if method == "" {
		method = t.Method
	}
	if method == "" {
		method = "POST"
	}

	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}

	if !auth {
		if body == "" {
			ex := cli.DoWithoutAuth(method, reqURL, nil)
			observeForAdaptive(lim, ex)
			return ex
		}
		ex := cli.DoWithoutAuth(method, reqURL, rdr)
		observeForAdaptive(lim, ex)
		return ex
	}

	extra := map[string]string{}
	if contentType != "" {
		extra["Content-Type"] = contentType
	}
	if body == "" {
		ex := cli.Do(method, reqURL, nil, extra)
		observeForAdaptive(lim, ex)
		return ex
	}
	ex := cli.Do(method, reqURL, rdr, extra)
	observeForAdaptive(lim, ex)
	return ex
}

// observeForAdaptive forwards a completed exchange to the limiter's
// adaptive controller, if one is attached. Centralised here so every
// scanner request path reports uniformly without each call site having to
// remember (and without the peer checks that call lim.Acquire directly
// needing to change their signatures).
func observeForAdaptive(lim *ratelimiter.Limiter, ex *httpclient.Exchange) {
	if lim == nil || ex == nil {
		return
	}
	status := 0
	if ex.Response != nil {
		status = ex.Response.StatusCode
	}
	lim.Observe(ex.ElapsedMS, status, ex.Err)
}
