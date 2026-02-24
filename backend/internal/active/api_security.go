package active

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkRESTAPIEnumeration() {
	if !s.config.ShouldRunModule("rest_api") {
		return
	}

	s.log("Enumerating REST API endpoints...")

	apiPaths := []string{
		"/api",
		"/api/v1",
		"/api/v2",
		"/rest",
		"/rest/v1",
		"/v1",
		"/v2",
		"/api/docs",
	}

	foundAPIs := []string{}

	for _, path := range apiPaths {
		url := s.target + path

		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 404 {
			contentType := resp.Header.Get("Content-Type")
			if strings.Contains(contentType, "json") {
				foundAPIs = append(foundAPIs, path)
			}
		}
	}

	if len(foundAPIs) > 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "API Discovery",
			Confidence:  "High",
			Finding:     fmt.Sprintf("REST API endpoints discovered: %d", len(foundAPIs)),
			Remediation: "Secure all API endpoints with authentication; implement rate limiting; use API gateway; enable CORS restrictions",
			Evidence:    fmt.Sprintf("Found: %s", strings.Join(foundAPIs, ", ")),
			HTTPMethod:  "GET",
			Outcome:     "APIs discovered",
		})
	}
}

func (s *ActiveScanner) checkAPIRateLimiting() {
	if !s.config.ShouldRunModule("api_rate_limit") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking API rate limiting...")

	// Try common API endpoints
	apiEndpoints := []string{"/api", "/api/v1/users", "/api/v1/data"}

	for _, endpoint := range apiEndpoints {
		url := s.target + endpoint

		// Make rapid requests
		const testCount = 30
		rateLimited := false
		successes := 0
		errors := 0

		for i := 0; i < testCount; i++ {
			resp, err := s.makeRequest("GET", url, nil)
			if err != nil {
				errors++
				continue
			}
			successes++
			resp.Body.Close()

			if resp.StatusCode == 429 {
				rateLimited = true
				s.addFinding(Finding{
					Severity:    "Info",
					Category:    "API Rate Limiting",
					Confidence:  "High",
					Finding:     fmt.Sprintf("API rate limiting detected on %s after %d requests", endpoint, i+1),
					Remediation: "Continue enforcing rate limits; document rate limits in API docs",
					Evidence:    "HTTP 429 Too Many Requests",
					HTTPMethod:  "GET",
					Outcome:     "Protected",
				})
				break
			}
		}

		if successes == 0 {
			s.addFinding(Finding{
				Severity:    "Info",
				Category:    "API Rate Limiting",
				Confidence:  "High",
				Finding:     fmt.Sprintf("API rate limiting could not be tested on %s due to connectivity errors", endpoint),
				Remediation: "Ensure the target is reachable from the scanner host, then rerun",
				Evidence:    fmt.Sprintf("errors=%d successes=%d", errors, successes),
				HTTPMethod:  "GET",
				Outcome:     "Not Tested",
			})
			break
		}

		if !rateLimited {
			s.addFinding(Finding{
				Severity:    "Medium",
				Category:    "API Rate Limiting",
				Confidence:  "Medium",
				Finding:     fmt.Sprintf("No rate limiting detected on %s (%d/%d requests succeeded)", endpoint, successes, testCount),
				Remediation: "Implement API rate limiting: 1000/hour per user, 100/min burst; use token bucket algorithm",
				Evidence:    fmt.Sprintf("successes=%d errors=%d", successes, errors),
				HTTPMethod:  "GET",
				Outcome:     "No rate limit",
			})
		}
		break // Test first endpoint only
	}
}

func (s *ActiveScanner) checkAPIAuthBypass() {
	if !s.config.ShouldRunModule("api_auth_bypass") {
		return
	}

	s.log("Checking API authentication...")

	apiEndpoints := []string{"/api/users", "/api/admin", "/api/data", "/api/config"}

	for _, endpoint := range apiEndpoints {
		url := s.target + endpoint

		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		// If API returns data without authentication
		if resp.StatusCode == 200 {
			body := s.readBody(resp)

			// Check if it's actually data (JSON response)
			var jsonData interface{}
			if json.Unmarshal([]byte(body), &jsonData) == nil {
				s.addFinding(Finding{
					Severity:    "High",
					Category:    "API Authentication",
					Confidence:  "Medium",
					Finding:     fmt.Sprintf("API endpoint accessible without authentication: %s", endpoint),
					Remediation: "Implement authentication on all API endpoints; use OAuth 2.0 or JWT; validate tokens on every request",
					Evidence:    "Unauthenticated request returned data",
					HTTPMethod:  "GET",
					Outcome:     "No auth required",
				})
			}
		}
	}
}

func (s *ActiveScanner) checkMassAssignment() {
	if !s.config.ShouldRunModule("mass_assignment") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for mass assignment vulnerabilities...")

	// This requires POST/PUT testing, only in normal/aggressive mode
	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Mass Assignment",
		Confidence:  "Low",
		Finding:     "Mass assignment testing requires authenticated testing (manual review recommended)",
		Remediation: "Use allowlists for permitted fields; never bind user input directly to models; validate all field assignments",
		Evidence:    "Requires manual testing with valid account",
		HTTPMethod:  "POST",
		Outcome:     "Requires auth",
	})
}

func (s *ActiveScanner) checkAPIVersionDisclosure() {
	if !s.config.ShouldRunModule("api_version") {
		return
	}

	s.log("Checking API version disclosure...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check headers for version disclosure
	versionHeaders := []string{
		"X-API-Version",
		"API-Version",
		"X-Version",
		"X-App-Version",
	}

	for _, header := range versionHeaders {
		if val := resp.Header.Get(header); val != "" {
			s.addFinding(Finding{
				Severity:    "Low",
				Category:    "API Version Disclosure",
				Confidence:  "High",
				Finding:     fmt.Sprintf("API version disclosed in header: %s: %s", header, val),
				Remediation: "Remove version headers from production; use internal versioning only",
				Evidence:    fmt.Sprintf("%s: %s", header, val),
				HTTPMethod:  "GET",
				Outcome:     "Version exposed",
			})
		}
	}
}

func (s *ActiveScanner) checkExcessiveDataExposure() {
	if !s.config.ShouldRunModule("excessive_data") {
		return
	}

	s.log("Checking for excessive data exposure...")

	apiEndpoints := []string{"/api/users", "/api/me", "/api/profile"}

	for _, endpoint := range apiEndpoints {
		url := s.target + endpoint

		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := s.readBody(resp)

			// Check for sensitive fields in response
			sensitiveFields := []string{"password", "secret", "token", "ssn", "credit_card"}

			bodyLower := strings.ToLower(body)
			foundSensitive := []string{}

			for _, field := range sensitiveFields {
				if strings.Contains(bodyLower, field) {
					foundSensitive = append(foundSensitive, field)
				}
			}

			if len(foundSensitive) > 0 {
				s.addFinding(Finding{
					Severity:    "High",
					Category:    "Excessive Data Exposure",
					Confidence:  "Medium",
					Finding:     fmt.Sprintf("API may expose sensitive fields: %s", strings.Join(foundSensitive, ", ")),
					Remediation: "Return only necessary fields; use DTOs; implement field-level access control; never return passwords/secrets",
					Evidence:    fmt.Sprintf("Sensitive keywords detected: %s", strings.Join(foundSensitive, ", ")),
					HTTPMethod:  "GET",
					Outcome:     "Potential exposure",
				})
			}
		}
	}
}

func (s *ActiveScanner) checkCORSMisconfigAPI() {
	if !s.config.ShouldRunModule("api_cors") {
		return
	}

	s.log("Checking API CORS configuration...")

	// Make request with custom Origin header
	headers := map[string]string{
		"Origin": "https://evil.com",
	}

	resp, err := s.makeRequestWithHeaders("GET", s.target+"/api", nil, headers)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "*" && acac == "true" {
		s.addFinding(Finding{
			Severity:    "Critical",
			Category:    "API CORS",
			Confidence:  "High",
			Finding:     "API allows wildcard CORS with credentials (authentication bypass risk)",
			Remediation: "Never use '*' with credentials; whitelist specific trusted origins; validate Origin header",
			Evidence:    "ACAO: * with ACAC: true",
			HTTPMethod:  "GET",
			Outcome:     "Misconfigured",
		})
	} else if acao == "https://evil.com" {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "API CORS",
			Confidence:  "High",
			Finding:     "API reflects arbitrary Origin without validation",
			Remediation: "Implement strict Origin whitelist; validate against known domains only",
			Evidence:    "Origin reflected without validation",
			HTTPMethod:  "GET",
			Outcome:     "Origin reflection",
		})
	}
}
