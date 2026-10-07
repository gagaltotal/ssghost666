package scanner

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"

	"ssghost666/internal/browser"
)

// confirmXSSInBrowser navigates real headless Chrome to targetURL — which
// must already contain the reflected payload, e.g. baked into a query
// string — and checks whether the page's own JavaScript execution set
// window[marker] to 1 (see xssPayloads: every execution-style payload
// assigns exactly that). A true result here is proof the browser actually
// ran the injected script, not just that the HTTP response happened to
// contain a matching substring — it also catches the inverse case, where
// a WAF or templating quirk makes a payload "look" reflected in the raw
// response but it actually lands somewhere inert (inside a comment, an
// already-escaped attribute, text content that never reaches a sink).
func confirmXSSInBrowser(ctx context.Context, chromePath, targetURL, marker string) (bool, error) {
	tabCtx, cancel := browser.NewTab(ctx, chromePath, 10*time.Second)
	defer cancel()

	var fired bool
	err := chromedp.Run(tabCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(500*time.Millisecond), // let an onload/inline <script> actually run
		chromedp.Evaluate(`window[`+jsStringLiteral(marker)+`] === 1`, &fired),
	)
	if err != nil {
		return false, browser.FriendlyErr(err)
	}
	return fired, nil
}

// jsStringLiteral renders s as a double-quoted JS string literal. marker
// is always SSGhost666's own Marker() output (lowercase letters/digits
// only), so this only needs to be correct for that alphabet, not
// general-purpose JS string escaping.
func jsStringLiteral(s string) string {
	return `"` + s + `"`
}
