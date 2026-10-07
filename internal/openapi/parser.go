// Package openapi turns an OpenAPI 3 or Swagger 2 definition (JSON or
// YAML, local file or URL) into model.Target entries so its documented
// operations get the same active/passive checks as crawled pages.
//
// This is a deliberately lightweight, generic-map-based reader rather
// than a full spec-validating client: it only extracts what's needed to
// build test requests (paths, methods, parameter names/locations, and
// JSON request body field names), and tolerates documents that aren't
// 100% spec-compliant, which real-world API definitions often aren't.
package openapi

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
)

// M is a generic JSON/YAML object as decoded by yaml.v3 (which, unlike
// yaml.v2, decodes string-keyed mappings straight into map[string]any —
// handy since it lets the same code path parse plain JSON too, as JSON is
// a subset of YAML).
type M = map[string]interface{}

// Load fetches and parses an OpenAPI/Swagger document from a local path
// or a URL, and returns the Targets for every operation it documents.
func Load(cli *httpclient.Client, location, baseURLOverride string) ([]model.Target, error) {
	raw, err := read(cli, location)
	if err != nil {
		return nil, err
	}
	var doc M
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("could not parse %s as JSON/YAML: %w", location, err)
	}

	base := resolveBaseURL(doc, location, baseURLOverride)
	paths, _ := doc["paths"].(M)
	if paths == nil {
		return nil, fmt.Errorf("%s has no \"paths\" object — is this a valid OpenAPI/Swagger document?", location)
	}

	isSwagger2 := strings.HasPrefix(toStr(doc["swagger"]), "2")

	var targets []model.Target
	for p, item := range paths {
		pathItem, ok := item.(M)
		if !ok {
			continue
		}
		pathLevelParams := asSlice(pathItem["parameters"])
		for method, op := range pathItem {
			lm := strings.ToUpper(method)
			switch lm {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			default:
				continue // "parameters", "$ref", vendor extensions, etc.
			}
			opMap, ok := op.(M)
			if !ok {
				continue
			}
			targets = append(targets, buildTarget(doc, base, p, lm, opMap, pathLevelParams, isSwagger2))
		}
	}
	return targets, nil
}

func read(cli *httpclient.Client, location string) ([]byte, error) {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		ex := cli.Get(location)
		if ex.Err != nil {
			return nil, fmt.Errorf("fetching %s: %w", location, ex.Err)
		}
		if ex.Response == nil || ex.Response.StatusCode >= 400 {
			return nil, fmt.Errorf("fetching %s: unexpected response", location)
		}
		return []byte(ex.Body), nil
	}
	b, err := os.ReadFile(location)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", location, err)
	}
	return b, nil
}

// resolveBaseURL picks the server/host to build concrete target URLs
// against: an explicit override (normally the -url the user already gave)
// wins, then OpenAPI 3's servers[0].url, then Swagger 2's
// scheme+host+basePath, then finally the document's own location if it
// was itself fetched from the target's own origin.
func resolveBaseURL(doc M, location, override string) string {
	if override != "" {
		return strings.TrimRight(override, "/")
	}
	if servers := asSlice(doc["servers"]); len(servers) > 0 {
		if s, ok := servers[0].(M); ok {
			if u := toStr(s["url"]); u != "" {
				return strings.TrimRight(u, "/")
			}
		}
	}
	if host := toStr(doc["host"]); host != "" {
		scheme := "https"
		if schemes := asSlice(doc["schemes"]); len(schemes) > 0 {
			scheme = toStr(schemes[0])
		}
		basePath := toStr(doc["basePath"])
		return strings.TrimRight(scheme+"://"+host+basePath, "/")
	}
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		if u, err := url.Parse(location); err == nil {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

func buildTarget(doc M, base, path, method string, op M, pathLevelParams []interface{}, isSwagger2 bool) model.Target {
	t := model.Target{Method: method, Source: "openapi"}

	params := append(append([]interface{}{}, pathLevelParams...), asSlice(op["parameters"])...)
	resolvedPath := path
	for _, pr := range params {
		// A parameter entry can itself be {"$ref": "#/components/parameters/Foo"}
		// instead of being written out inline — resolve that first.
		pm := resolveParamObj(doc, pr, 0)
		if pm == nil {
			continue
		}
		name := toStr(pm["name"])
		in := toStr(pm["in"])
		if name == "" {
			continue
		}
		schema := resolveSchema(doc, pm["schema"], 0)
		sample := sampleFromSchema(schema)
		if sample == "" {
			sample = toStr(pm["default"])
		}
		if sample == "" {
			sample = toStr(pm["type"]) // Swagger 2 puts type directly on the param
		}
		if sample == "" {
			sample = "1"
		}
		switch in {
		case "path":
			resolvedPath = strings.ReplaceAll(resolvedPath, "{"+name+"}", sample)
			t.Params = append(t.Params, model.Param{Name: name, Location: model.LocPath, Sample: sample})
		case "query":
			t.Params = append(t.Params, model.Param{Name: name, Location: model.LocQuery, Sample: sample})
		case "header":
			t.Params = append(t.Params, model.Param{Name: name, Location: model.LocHeader, Sample: sample})
		case "cookie":
			t.Params = append(t.Params, model.Param{Name: name, Location: model.LocCookie, Sample: sample})
		case "body": // Swagger 2 style: the whole JSON body is one "in: body" param
			t.ContentType = "application/json"
			for _, f := range schemaPropertyNames(doc, pm["schema"]) {
				t.Params = append(t.Params, model.Param{Name: f, Location: model.LocBody})
			}
		}
	}

	// OpenAPI 3 style request body — schema may be $ref'd and/or built
	// from allOf, both fully resolved here. requestBody itself can also
	// be a top-level $ref (e.g. "#/components/requestBodies/Foo").
	if rbRaw, ok := op["requestBody"]; ok {
		rb := resolveParamObj(doc, rbRaw, 0)
		if content, ok := rb["content"].(M); ok {
			if js, ok := content["application/json"].(M); ok {
				t.ContentType = "application/json"
				for _, f := range schemaPropertyNames(doc, js["schema"]) {
					t.Params = append(t.Params, model.Param{Name: f, Location: model.LocBody})
				}
			} else if form, ok := content["application/x-www-form-urlencoded"].(M); ok {
				t.ContentType = "application/x-www-form-urlencoded"
				for _, f := range schemaPropertyNames(doc, form["schema"]) {
					t.Params = append(t.Params, model.Param{Name: f, Location: model.LocBody})
				}
			}
		}
	}

	if !strings.HasPrefix(resolvedPath, "/") {
		resolvedPath = "/" + resolvedPath
	}
	t.URL = base + resolvedPath

	if sec, ok := op["security"]; ok {
		if arr, ok := sec.([]interface{}); ok && len(arr) > 0 {
			t.RequiresAuth = true
		}
	}
	_ = isSwagger2
	return t
}

// schemaPropertyNames returns the property names of a JSON schema object,
// after fully resolving $ref (local, same-document pointers) and
// flattening allOf — so a request body defined as {"allOf": [{"$ref":
// "#/components/schemas/Base"}, {"properties": {...}}]}, a very common
// pattern for "shared base + per-endpoint extra fields", yields every
// field from both branches rather than just the inline ones.
func schemaPropertyNames(doc M, schema interface{}) []string {
	resolved := resolveSchema(doc, schema, 0)
	props, ok := resolved["properties"].(M)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	return names
}

// sampleFromSchema pulls a representative example value out of a
// parameter's schema, if one is given, to use as the baseline (pre-fuzz)
// value.
func sampleFromSchema(schema interface{}) string {
	sm, ok := schema.(M)
	if !ok {
		return ""
	}
	if ex := toStr(sm["example"]); ex != "" {
		return ex
	}
	if def := toStr(sm["default"]); def != "" {
		return def
	}
	switch toStr(sm["type"]) {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	}
	return ""
}

func asSlice(v interface{}) []interface{} {
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return nil
}

func toStr(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return fmt.Sprintf("%d", x)
	case float64:
		return fmt.Sprintf("%g", x)
	case bool:
		return fmt.Sprintf("%t", x)
	default:
		return ""
	}
}
