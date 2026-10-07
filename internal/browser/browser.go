// Package browser holds the one piece of headless-Chrome setup logic
// (launching a tab with the right flags) shared by anything in SSGhost666
// that drives a real browser: internal/crawler's -js-render route
// discovery, and internal/scanner's XSS execution confirmation. Keeping
// it here avoids duplicating allocator options in two packages and avoids
// crawler and scanner depending on each other just for this.
package browser

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// NewTab launches headless Chrome (or reuses chromePath if given) and
// returns a tab-scoped context bounded by timeout, plus a single cancel
// function that tears down both the tab and the underlying browser
// process. Every caller should `defer cancel()`.
func NewTab(parent context.Context, chromePath string, timeout time.Duration) (context.Context, context.CancelFunc) {
	allocOpts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	allocOpts = append(allocOpts,
		chromedp.NoSandbox, // headless Chrome commonly runs as root in CI/containers, which Chrome refuses without this
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("ignore-certificate-errors", true), // mirrors -insecure: let the scanner reach self-signed/staging targets
	)
	if chromePath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(chromePath))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, allocOpts...)
	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	tabCtx, cancelTimeout := context.WithTimeout(tabCtx, timeout)

	cancel := func() {
		cancelTimeout()
		cancelTab()
		cancelAlloc()
	}
	return tabCtx, cancel
}

// FriendlyErr rewrites the common "no Chrome binary found" chromedp error
// into something a person can act on, and passes everything else through
// unchanged.
func FriendlyErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "cannot find the path") {
		return fmt.Errorf("needs a Chrome/Chromium binary, none was found on PATH: install chromium (e.g. `apt install chromium`) or pass -chrome-path /path/to/chrome: %w", err)
	}
	return err
}
