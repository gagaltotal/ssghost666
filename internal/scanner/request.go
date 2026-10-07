package scanner

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// sendWithPayload sends target's request with every parameter at its
// baseline (sample) value, except fuzzName, which is set to payload.
// Passing fuzzName="" (which never matches a real param name) sends the
// pure baseline — used to get a fresh "before" response to diff against.
//
// This is the one place that knows how to turn a model.Target + a single
// substitution into an actual HTTP request, so sqli/xss/cmdi/ssrf all
// share identical, correct handling of query/path/header/cookie/body
// parameters instead of re-implementing it four times. It is also the
// one place that acquires the rate limiter, so every real HTTP call any
// check makes — however many payloads it tries internally — is paced and
// concurrency-bounded the same way, not just the first one.
func sendWithPayload(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target, fuzzName, payload string) *httpclient.Exchange {
	if !lim.Acquire(ctx) {
		return &httpclient.Exchange{Err: context.Canceled}
	}
	defer lim.Release()
	reqURL := t.URL
	extraHeaders := map[string]string{}

	if u, err := url.Parse(t.URL); err == nil {
		q := u.Query()
		touched := false
		for _, p := range t.Params {
			if p.Location == model.LocQuery {
				v := p.Sample
				if p.Name == fuzzName {
					v = payload
				}
				q.Set(p.Name, v)
				touched = true
			}
		}
		if touched {
			u.RawQuery = q.Encode()
		}
		reqURL = u.String()
	}

	for _, p := range t.Params {
		switch p.Location {
		case model.LocPath:
			if p.Name == fuzzName && p.Sample != "" {
				reqURL = strings.Replace(reqURL, "/"+url.PathEscape(p.Sample), "/"+url.PathEscape(payload), 1)
			}
		case model.LocHeader:
			v := p.Sample
			if p.Name == fuzzName {
				v = payload
			}
			if v != "" {
				extraHeaders[p.Name] = v
			}
		case model.LocCookie:
			v := p.Sample
			if p.Name == fuzzName {
				v = payload
			}
			if existing, ok := extraHeaders["Cookie"]; ok {
				extraHeaders["Cookie"] = existing + "; " + p.Name + "=" + v
			} else {
				extraHeaders["Cookie"] = p.Name + "=" + v
			}
		}
	}

	method := t.Method
	if method == "" {
		method = "GET"
	}

	hasBody := false
	bodyMap := map[string]string{}
	for _, p := range t.Params {
		if p.Location == model.LocBody {
			hasBody = true
			v := p.Sample
			if p.Name == fuzzName {
				v = payload
			}
			bodyMap[p.Name] = v
		}
	}
	if !hasBody {
		return cli.Do(method, reqURL, nil, extraHeaders)
	}

	if t.ContentType == "application/x-www-form-urlencoded" {
		form := url.Values{}
		for k, v := range bodyMap {
			form.Set(k, v)
		}
		extraHeaders["Content-Type"] = "application/x-www-form-urlencoded"
		return cli.Do(method, reqURL, strings.NewReader(form.Encode()), extraHeaders)
	}

	b, _ := json.Marshal(bodyMap)
	extraHeaders["Content-Type"] = "application/json"
	return cli.Do(method, reqURL, strings.NewReader(string(b)), extraHeaders)
}

// fuzzableParams returns only the params worth actively fuzzing (every
// location SSGhost666 knows how to substitute into a request).
func fuzzableParams(t model.Target) []model.Param {
	var out []model.Param
	for _, p := range t.Params {
		switch p.Location {
		case model.LocQuery, model.LocPath, model.LocBody, model.LocHeader, model.LocCookie:
			out = append(out, p)
		}
	}
	return out
}
