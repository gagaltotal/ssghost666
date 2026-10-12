package crawler

import (
	"net/url"
	"strconv"
	"strings"
)

// PaginationParams are the conventional query-parameter names used for
// numeric pagination, roughly ordered by how common they are in the wild.
// They're used both to recognise a page as paginated and to synthesise the
// next page's URL for endpoints whose "next" link is built client-side.
var PaginationParams = []string{
	"page", "p", "pg", "pageno", "pagenum", "page_number", "page_num",
	"offset", "start", "skip", "from", "index",
}

// isNumeric reports whether s is a plain non-negative integer.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// paginationParam returns the page's numeric pagination parameter (name and
// value) if it has one, so the crawler knows which knob to turn to get the
// next page.
func paginationParam(rawURL string) (name, value string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false
	}
	for k, vals := range u.Query() {
		if len(vals) == 0 || !isNumeric(vals[0]) {
			continue
		}
		low := strings.ToLower(k)
		for _, p := range PaginationParams {
			if low == p {
				return k, vals[0], true
			}
		}
	}
	return "", "", false
}

// DetectPagination works out how to fetch the *next* pages of a paginated
// page and returns a small, bounded set of URLs for them. It uses two
// complementary signals: a numeric pagination parameter already present on
// the page (in which case it synthesises value+1 and value+2), and any
// in-scope links that already point at higher page numbers (used verbatim).
//
// This is intentionally conservative — it only ever emits a handful of
// extra URLs (capped by max) and never invents pagination on a page that
// shows none — so enabling -smart-crawl can't turn a small scan into an
// unbounded crawl of a deep archive.
func DetectPagination(page *url.URL, links []string, max int) []string {
	if max <= 0 {
		max = 5
	}
	if page == nil {
		return nil
	}
	seen := map[string]bool{page.String(): true}
	var out []string

	// Signal 1: the page itself carries a numeric page/offset param.
	if name, val, ok := paginationParam(page.String()); ok {
		cur, _ := strconv.Atoi(val)
		for _, delta := range []int{1, 2} {
			nu := *page
			q := nu.Query()
			q.Set(name, strconv.Itoa(cur+delta))
			nu.RawQuery = q.Encode()
			s := nu.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
			if len(out) >= max {
				return out
			}
		}
	}

	// Signal 2: links that already point at a higher page number.
	for _, l := range links {
		if len(out) >= max {
			break
		}
		lu, err := url.Parse(l)
		if err != nil || !strings.EqualFold(lu.Host, page.Host) {
			continue
		}
		if _, _, ok := paginationParam(l); !ok {
			continue
		}
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}
