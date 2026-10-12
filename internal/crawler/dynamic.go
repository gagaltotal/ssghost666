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

// netRecorder accumulates the XHR/Fetch requests (and WebSocket endpoints)
// a page issues while it runs. It is shared by RenderJS (a single settle)
// and RenderJSInfiniteScroll (repeated scroll rounds) so the request-
// capture logic lives in exactly one place.
type netRecorder struct {
	mu   sync.Mutex
	seen map[string]bool
	reqs []model.Target
}

func newNetRecorder() *netRecorder {
	return &netRecorder{seen: map[string]bool{}}
}

func (r *netRecorder) listen(tabCtx context.Context) {
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		// WebSocket endpoints the page opened. They can't be fuzzed like
		// an HTTP route, so they're recorded with a distinct Source and
		// handed to the WebSocket scanner module.
		if ws, ok := ev.(*network.EventWebSocketCreated); ok && ws.URL != "" {
			r.mu.Lock()
			if !r.seen[ws.URL] {
				r.seen[ws.URL] = true
				r.reqs = append(r.reqs, model.Target{Method: "GET", URL: ws.URL, Source: "websocket"})
			}
			r.mu.Unlock()
			return
		}

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
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.seen[reqURL] {
			return
		}
		r.seen[reqURL] = true
		t := model.Target{Method: strings.ToUpper(e.Request.Method), URL: reqURL, Source: "dynamic"}
		if pu, err := url.Parse(reqURL); err == nil && pu.RawQuery != "" {
			t.Params = queryTarget(reqURL).Params
		}
		r.reqs = append(r.reqs, t)
	})
}

func (r *netRecorder) snapshot() []model.Target {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]model.Target(nil), r.reqs...)
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

	rec := newNetRecorder()
	rec.listen(tabCtx)

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

	return RenderResult{Links: links, JSRequests: rec.snapshot()}
}

// scrollToBottomJS scrolls to the page bottom and returns the new document
// height, so the caller can tell whether more content loaded.
const scrollToBottomJS = `(function(){window.scrollTo(0, document.body.scrollHeight); return document.body.scrollHeight;})()`

// clickLoadMoreJS clicks a conventional "load more" / "show more" control
// if one is present, covering the non-infinite-scroll variant of the same
// pattern. It is a no-op when no such control exists.
const clickLoadMoreJS = `(function(){var s=['button[data-testid="load-more"]','.load-more','#load-more','button.loadMore','[aria-label="Load more"]','a.load-more']; for(var i=0;i<s.length;i++){var b=document.querySelector(s[i]); if(b){b.click(); return true;}} return false;})()`

// RenderJSInfiniteScroll is like RenderJS but additionally drives the page
// the way a user would to reach content that only appears on scroll or via
// a "load more" button: it repeatedly scrolls to the bottom (and clicks a
// load-more control if present), waiting `settle` between rounds, up to
// maxRounds times, stopping early once the document stops growing. Every
// XHR/Fetch fired by those scroll-triggered loads is captured, so pages
// that paginate client-side reveal their real API routes.
func RenderJSInfiniteScroll(ctx context.Context, chromePath, rawURL string, settle time.Duration, maxRounds int) RenderResult {
	if maxRounds < 1 {
		maxRounds = 3
	}
	budget := time.Duration(maxRounds)*(settle+2*time.Second) + 20*time.Second
	tabCtx, cancel := browser.NewTab(ctx, chromePath, budget)
	defer cancel()

	rec := newNetRecorder()
	rec.listen(tabCtx)

	if err := chromedp.Run(tabCtx, network.Enable(), chromedp.Navigate(rawURL), chromedp.Sleep(settle)); err != nil {
		return RenderResult{Err: friendlyRenderErr(err)}
	}

	lastHeight := 0
	for round := 0; round < maxRounds; round++ {
		if ctx.Err() != nil {
			break
		}
		var height int
		if err := chromedp.Run(tabCtx, chromedp.Evaluate(scrollToBottomJS, &height)); err != nil {
			break
		}
		// Best-effort "load more" click; ignored if nothing matches.
		_ = chromedp.Run(tabCtx, chromedp.Evaluate(clickLoadMoreJS, nil))
		if err := chromedp.Run(tabCtx, chromedp.Sleep(settle)); err != nil {
			break
		}
		if height <= lastHeight {
			break // page stopped growing: no more scroll-triggered content
		}
		lastHeight = height
	}

	var links []string
	if base, perr := url.Parse(rawURL); perr == nil {
		var outerHTML string
		if err := chromedp.Run(tabCtx, chromedp.OuterHTML("html", &outerHTML)); err == nil && outerHTML != "" {
			links = extractPage(base, outerHTML).Links
		}
	}

	return RenderResult{Links: links, JSRequests: rec.snapshot()}
}

// RenderOptions configures RenderMany.
type RenderOptions struct {
	ChromePath string
	Settle     time.Duration
	Smart      bool // also drive infinite-scroll / "load more" rounds (mines lazy-loaded pages)
	MaxRounds  int  // scroll rounds when Smart is set (default 3)
}

// RenderMany runs a render pass over a bounded set of URLs. Each call
// launches its own headless Chrome tab, so callers (main.go) should cap
// `urls` to a handful of key pages rather than every crawled page. When
// opt.Smart is set it uses RenderJSInfiniteScroll instead of the plain
// single-settle RenderJS, so pages whose content only loads on scroll
// still reveal their API routes.
func RenderMany(ctx context.Context, urls []string, opt RenderOptions, onPage func(pageURL string, newLinks, newRequests int, err error)) ([]string, []model.Target) {
	var allLinks []string
	var allTargets []model.Target
	for _, u := range urls {
		var res RenderResult
		if opt.Smart {
			res = RenderJSInfiniteScroll(ctx, opt.ChromePath, u, opt.Settle, opt.MaxRounds)
		} else {
			res = RenderJS(ctx, opt.ChromePath, u, opt.Settle)
		}
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
