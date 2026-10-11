package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"ssghost666/internal/httpclient"
	"ssghost666/internal/model"
	"ssghost666/internal/ratelimiter"
)

// massAssignmentTestFields are sensitive fields commonly protected in APIs
// that should not be directly modifiable by users
var massAssignmentTestFields = []struct {
	field       string
	testValue   string
	description string
	severity    model.Severity
}{
	{"role", "admin", "User role elevation", model.SeverityCritical},
	{"isAdmin", "true", "Admin flag manipulation", model.SeverityCritical},
	{"is_admin", "true", "Admin flag manipulation (snake_case)", model.SeverityCritical},
	{"admin", "true", "Admin status manipulation", model.SeverityCritical},
	{"privileges", "admin", "Privilege escalation", model.SeverityCritical},
	{"permissions", "[\"admin\",\"write\",\"delete\"]", "Permissions manipulation", model.SeverityCritical},
	{"isVerified", "true", "Verification bypass", model.SeverityHigh},
	{"is_verified", "true", "Verification bypass (snake_case)", model.SeverityHigh},
	{"verified", "true", "Verification status manipulation", model.SeverityHigh},
	{"emailVerified", "true", "Email verification bypass", model.SeverityHigh},
	{"email_verified", "true", "Email verification bypass (snake_case)", model.SeverityHigh},
	{"price", "0.01", "Price manipulation", model.SeverityHigh},
	{"amount", "0.01", "Amount manipulation", model.SeverityHigh},
	{"balance", "999999", "Balance manipulation", model.SeverityHigh},
	{"credits", "999999", "Credits manipulation", model.SeverityHigh},
	{"discount", "99", "Discount manipulation", model.SeverityMedium},
	{"status", "approved", "Status manipulation", model.SeverityMedium},
	{"approved", "true", "Approval bypass", model.SeverityMedium},
	{"isActive", "true", "Activation bypass", model.SeverityMedium},
	{"is_active", "true", "Activation bypass (snake_case)", model.SeverityMedium},
	{"userId", "1", "User ID manipulation", model.SeverityMedium},
	{"user_id", "1", "User ID manipulation (snake_case)", model.SeverityMedium},
	{"accountId", "1", "Account ID manipulation", model.SeverityMedium},
	{"account_id", "1", "Account ID manipulation (snake_case)", model.SeverityMedium},
}

// CheckMassAssignment detects REST API mass assignment vulnerabilities where
// protected fields can be modified through user-controllable input
func CheckMassAssignment(ctx context.Context, lim *ratelimiter.Limiter, cli *httpclient.Client, t model.Target) []model.Finding {
	var findings []model.Finding

	// Only test JSON API endpoints (POST, PUT, PATCH)
	if !isJSONEndpoint(t) || !isModifyingMethod(t.Method) {
		return nil
	}

	// Get baseline response
	baseline := sendWithPayload(ctx, lim, cli, t, "", "")
	if baseline.Err != nil || baseline.Response == nil {
		return nil
	}

	// Parse baseline response to check structure
	var baselineData map[string]interface{}
	baselineIsJSON := false
	if strings.Contains(baseline.Response.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal([]byte(baseline.Body), &baselineData); err == nil {
			baselineIsJSON = true
		}
	}

	for _, testField := range massAssignmentTestFields {
		// Create a JSON payload that includes the test field
		payload := createMassAssignmentPayload(t, testField.field, testField.testValue)
		if payload == "" {
			continue
		}

		// Send request with injected field as a raw JSON body. sendRawBody
		// is used (rather than sendWithPayload) because the injected field
		// is deliberately *not* one of the target's known params — we are
		// testing whether the endpoint accepts extra, undeclared fields.
		ex := sendRawBody(ctx, lim, cli, t, t.Method, "application/json", payload)

		if ex.Err != nil || ex.Response == nil {
			continue
		}

		// Check for signs of successful mass assignment
		evidence := []string{}

		// 1. Check if the injected field appears in the response
		if strings.Contains(ex.Body, testField.field) {
			// Parse response to see if field value was accepted
			if baselineIsJSON && strings.Contains(ex.Response.Header.Get("Content-Type"), "application/json") {
				var modifiedData map[string]interface{}
				if err := json.Unmarshal([]byte(ex.Body), &modifiedData); err == nil {
					// Check if our injected field exists with our value
					if val, exists := modifiedData[testField.field]; exists {
						valStr := fmt.Sprintf("%v", val)
						if strings.Contains(valStr, testField.testValue) || strings.Contains(strings.ToLower(valStr), strings.ToLower(testField.testValue)) {
							evidence = append(evidence, fmt.Sprintf("Field %q accepted with value %q in response", testField.field, valStr))
						}
						// Also check if field was absent in baseline but present now
						if _, baselineHas := baselineData[testField.field]; !baselineHas {
							evidence = append(evidence, fmt.Sprintf("Field %q was not in baseline but appears after injection", testField.field))
						}
					}
				}
			} else {
				// Non-JSON response, check for field and value in body
				if strings.Contains(ex.Body, testField.testValue) {
					evidence = append(evidence, fmt.Sprintf("Field %q and test value %q reflected in response", testField.field, testField.testValue))
				}
			}
		}

		// 2. Check for successful status codes (200, 201) vs errors
		if ex.Response.StatusCode >= 200 && ex.Response.StatusCode < 300 {
			if baseline.Response.StatusCode >= 400 || len(evidence) > 0 {
				evidence = append(evidence, fmt.Sprintf("Request with injected field succeeded (status %d)", ex.Response.StatusCode))
			}
		}

		// 3. Check for response differences that suggest field was processed
		if len(ex.Body) != len(baseline.Body) {
			// Response structure changed
			if strings.Contains(ex.Body, testField.field) && !strings.Contains(baseline.Body, testField.field) {
				evidence = append(evidence, "Response structure changed to include injected field")
			}
		}

		// 4. Check for validation errors mentioning the field (negative signal - field was rejected)
		rejectionSignatures := []string{
			"not allowed",
			"forbidden",
			"unauthorized",
			"invalid field",
			"unknown field",
			"cannot modify",
			"read-only",
			"protected field",
		}
		bodyLower := strings.ToLower(ex.Body)
		rejected := false
		for _, sig := range rejectionSignatures {
			if strings.Contains(bodyLower, sig) && strings.Contains(bodyLower, strings.ToLower(testField.field)) {
				rejected = true
				break
			}
		}

		// Report finding if we have evidence and field wasn't explicitly rejected
		if len(evidence) >= 1 && !rejected {
			findings = append(findings, model.Finding{
				Category:    "Mass Assignment",
				Severity:    testField.severity,
				Title:       fmt.Sprintf("Potential Mass Assignment vulnerability: %s via field %q", testField.description, testField.field),
				Description: fmt.Sprintf("The API endpoint appears to accept the protected field %q with value %q. Evidence: %s. This could allow unauthorized modification of sensitive object properties.", testField.field, testField.testValue, strings.Join(evidence, "; ")),
				URL:         t.URL,
				Method:      t.Method,
				Parameter:   testField.field,
				Evidence:    model.Evidence{RequestRaw: ex.RequestRaw, ResponseRaw: ex.ResponseRaw, Notes: fmt.Sprintf("Baseline status: %d, Modified status: %d. Evidence: %s", baseline.Response.StatusCode, ex.Response.StatusCode, strings.Join(evidence, "; "))},
				Remediation: "Implement strict input validation with allowlists. Use DTOs (Data Transfer Objects) that only include fields users should modify. Never bind user input directly to database models. Explicitly define which fields are mass-assignable and protect sensitive fields (role, permissions, price, etc.) from direct modification.",
			})
		}
	}

	return findings
}

// isJSONEndpoint checks if the target accepts JSON
func isJSONEndpoint(t model.Target) bool {
	return strings.Contains(strings.ToLower(t.ContentType), "json") ||
		strings.Contains(strings.ToLower(t.URL), "/api/") ||
		strings.HasSuffix(strings.ToLower(t.URL), ".json")
}

// isModifyingMethod checks if the HTTP method modifies resources
func isModifyingMethod(method string) bool {
	method = strings.ToUpper(method)
	return method == "POST" || method == "PUT" || method == "PATCH"
}

// createMassAssignmentPayload creates a JSON payload that includes the
// target's own declared body params (at their baseline values) plus the
// protected test field we want to inject. Preserving the legitimate
// fields matters: an endpoint is far more likely to reach the
// binding/serialization step (where mass assignment happens) when the
// request looks like a valid update rather than an empty stub.
func createMassAssignmentPayload(t model.Target, field, value string) string {
	payload := map[string]interface{}{}

	// Start from the target's declared body params so the request is valid.
	for _, p := range t.Params {
		if p.Location == model.LocBody {
			payload[p.Name] = parseValue(p.Sample)
		}
	}

	// If a raw JSON body template exists, fold its top-level keys in too.
	if t.BodyTemplate != "" {
		var existing map[string]interface{}
		if err := json.Unmarshal([]byte(t.BodyTemplate), &existing); err == nil {
			for k, v := range existing {
				if _, ok := payload[k]; !ok {
					payload[k] = v
				}
			}
		}
	}

	// Inject the protected field under test.
	payload[field] = parseValue(value)

	// If there were no legitimate fields at all, add harmless filler so
	// the body isn't a single-field stub that most validators reject early.
	if len(payload) <= 1 {
		payload["name"] = "test"
	}

	if data, err := json.Marshal(payload); err == nil {
		return string(data)
	}

	return ""
}

// parseValue converts string value to appropriate type
func parseValue(value string) interface{} {
	if value == "true" {
		return true
	}
	if value == "false" {
		return false
	}
	if strings.HasPrefix(value, "[") {
		// Try to parse as JSON array
		var arr []interface{}
		if err := json.Unmarshal([]byte(value), &arr); err == nil {
			return arr
		}
	}
	// Try to parse as number
	var num float64
	if _, err := fmt.Sscanf(value, "%f", &num); err == nil {
		return num
	}
	return value
}
