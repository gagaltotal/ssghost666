package crawler

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"ssghost666/internal/browser"
	"ssghost666/internal/model"
)

// RenderResult is what one headless-render pass produced for a single URL.
type RenderResult struct {
	Links      []string       // links found in the post-render DOM (e.g. SPA router output)
	JSRequests []model.Target // XHR/Fetch calls the page issued while running
	Err        error
}

// RenderJS launches headless Chrome, navigates to rawURL, lets the page's
// JavaScript execute for `settle`, and returns both the rendered DOM's
// links and every XHR/Fetch request observed while it loaded. This is
// what finds routes a plain HTML crawl can never see: endpoints a
// single-page app only calls after the bundle runs (chromedp.go-rod-class
// browser automation; no endpoint is "hidden" from the app itself, this
// just gives SSGhost666 the same view the browser has).
func RenderJS(ctx context.Context, chromePath, rawURL string, settle time.Duration) RenderResult {
	tabCtx, cancel := browser.NewTab(ctx, chromePath, settle+20*time.Second)
	defer cancel()

	var mu sync.Mutex
	seen := map[string]bool{}
	var reqs []model.Target

	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		e, ok := ev.(*network.EventRequestWillBeSent)
		if !ok || e.Request == nil {
			return
		}
		switch e.Type {
		case network.ResourceTypeXHR, network.ResourceTypeFetch:
			// exactly the "loaded via JavaScript" calls we're after
		default:
			return
		}
		reqURL := e.Request.URL
		mu.Lock()
		defer mu.Unlock()
		if seen[reqURL] {
			return
		}
		seen[reqURL] = true
		t := model.Target{Method: strings.ToUpper(e.Request.Method), URL: reqURL, Source: "dynamic"}
		if pu, err := url.Parse(reqURL); err == nil && pu.RawQuery != "" {
			t.Params = queryTarget(reqURL).Params
		}
		reqs = append(reqs, t)
	})

	var outerHTML string
	err := chromedp.Run(tabCtx,
		network.Enable(),
		chromedp.Navigate(rawURL),
		chromedp.Sleep(settle), // pragmatic "network idle" stand-in: lets async fetches on page-load fire
		chromedp.OuterHTML("html", &outerHTML),
	)
	if err != nil {
		return RenderResult{Err: friendlyRenderErr(err)}
	}

	var links []string
	if base, perr := url.Parse(rawURL); perr == nil && outerHTML != "" {
		links = extractPage(base, outerHTML).Links
	}

	mu.Lock()
	defer mu.Unlock()
	return RenderResult{Links: links, JSRequests: append([]model.Target(nil), reqs...)}
}

// RenderMany runs RenderJS over a bounded set of URLs. Each call launches
// its own headless Chrome tab, so callers (main.go) should cap `urls` to
// a handful of key pages rather than every crawled page.
func RenderMany(ctx context.Context, chromePath string, urls []string, settle time.Duration, onPage func(pageURL string, newLinks, newRequests int, err error)) ([]string, []model.Target) {
	var allLinks []string
	var allTargets []model.Target
	for _, u := range urls {
		res := RenderJS(ctx, chromePath, u, settle)
		if onPage != nil {
			onPage(u, len(res.Links), len(res.JSRequests), res.Err)
		}
		if res.Err != nil {
			continue
		}
		allLinks = append(allLinks, res.Links...)
		allTargets = append(allTargets, res.JSRequests...)
	}
	return allLinks, allTargets
}

// friendlyRenderErr adds the -js-render-specific prefix on top of
// browser.FriendlyErr's generic "no Chrome found" rewrite.
func friendlyRenderErr(err error) error {
	return browser.FriendlyErr(err)
}
