package crawler

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"ssghost666/internal/model"
)

// FormField is one input/select/textarea discovered inside a <form>.
type FormField struct {
	Name  string
	Type  string // input type: text, hidden, email, password, checkbox, ...
	Value string
}

// FormInfo is one <form> discovered on a page, enough to build a Target.
type FormInfo struct {
	Action string // absolute URL
	Method string // GET or POST
	Fields []FormField
}

// pageExtract is everything of interest pulled out of one HTML page.
type pageExtract struct {
	Links   []string // absolute URLs from <a href>
	JSFiles []string // absolute URLs from <script src>
	Forms   []FormInfo
}

// extractPage walks the parsed DOM once, collecting links, script sources
// and forms. Malformed HTML is tolerated the same way a browser tolerates
// it, since x/net/html implements the HTML5 parsing algorithm.
func extractPage(base *url.URL, body string) pageExtract {
	var out pageExtract
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return out
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if href, ok := attr(n, "href"); ok {
					if abs, ok := normalizeURL(base, href); ok {
						out.Links = append(out.Links, abs)
					}
				}
			case "script":
				if src, ok := attr(n, "src"); ok {
					if abs, ok := normalizeURL(base, src); ok {
						out.JSFiles = append(out.JSFiles, abs)
					}
				}
			case "form":
				out.Forms = append(out.Forms, extractForm(base, n))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func extractForm(base *url.URL, formNode *html.Node) FormInfo {
	fi := FormInfo{Method: "GET"}
	if action, ok := attr(formNode, "action"); ok {
		if abs, ok := normalizeURL(base, action); ok {
			fi.Action = abs
		}
	}
	if fi.Action == "" {
		fi.Action = base.String() // empty action means "submit to current URL"
	}
	if m, ok := attr(formNode, "method"); ok && strings.EqualFold(m, "post") {
		fi.Method = "POST"
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "select", "textarea":
				name, ok := attr(n, "name")
				if ok && name != "" {
					typ, _ := attr(n, "type")
					if typ == "" {
						typ = "text"
					}
					val, _ := attr(n, "value")
					fi.Fields = append(fi.Fields, FormField{Name: name, Type: typ, Value: val})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(formNode)
	return fi
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

// formToTarget turns a discovered form into a scannable Target. GET forms
// become query-param targets; POST forms become url-encoded body targets
// (the common case for plain HTML forms; JSON APIs are instead picked up
// via jsendpoints.go, dynamic.go or OpenAPI import).
func formToTarget(fi FormInfo) model.Target {
	t := model.Target{Method: fi.Method, URL: fi.Action, Source: "crawl"}
	if fi.Method == "GET" {
		for _, f := range fi.Fields {
			if f.Type == "submit" || f.Type == "button" {
				continue
			}
			t.Params = append(t.Params, model.Param{Name: f.Name, Location: model.LocQuery, Sample: f.Value})
		}
		return t
	}
	t.ContentType = "application/x-www-form-urlencoded"
	for _, f := range fi.Fields {
		if f.Type == "submit" || f.Type == "button" {
			continue
		}
		t.Params = append(t.Params, model.Param{Name: f.Name, Location: model.LocBody, Sample: f.Value})
	}
	return t
}
