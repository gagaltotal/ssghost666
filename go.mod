module ssghost666

go 1.23

require (
	github.com/chromedp/cdproto v0.0.0-20241022234722-4d5d5faf59fb
	github.com/chromedp/chromedp v0.11.2
	golang.org/x/net v0.33.0
	golang.org/x/time v0.8.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/chromedp/sysutil v1.1.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	golang.org/x/sys v0.28.0 // indirect
	gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 // indirect
)

// The replace directives below pin these modules to their official GitHub
// mirrors. This is functionally identical to fetching from the canonical
// golang.org/x/... and gopkg.in/... paths, but also keeps the build working
// on networks that only allow github.com egress (common in locked-down
// corporate/CI environments). On a normal network you can drop them with:
//   go mod edit -dropreplace=golang.org/x/net -dropreplace=golang.org/x/time \
//     -dropreplace=golang.org/x/sys -dropreplace=gopkg.in/yaml.v3 -dropreplace=gopkg.in/check.v1
replace golang.org/x/net => github.com/golang/net v0.33.0

replace golang.org/x/time => github.com/golang/time v0.8.0

replace golang.org/x/sys => github.com/golang/sys v0.28.0

replace gopkg.in/yaml.v3 => github.com/go-yaml/yaml v0.0.0-20220527083530-f6f7691b1fde

replace gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20201130134442-10cb98267c6c
