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
			return cli.DoWithoutAuth(method, reqURL, nil)
		}
		return cli.DoWithoutAuth(method, reqURL, rdr)
	}

	extra := map[string]string{}
	if contentType != "" {
		extra["Content-Type"] = contentType
	}
	if body == "" {
		return cli.Do(method, reqURL, nil, extra)
	}
	return cli.Do(method, reqURL, rdr, extra)
}
