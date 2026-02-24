package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkHTTPSplitting() {
	if !s.config.ShouldRunModule("http_splitting") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking HTTP Response Splitting...")

	// Test with CRLF injection
	payload := "%0d%0aSet-Cookie:%20evil=true"
	testURL := fmt.Sprintf("%s?redirect=%s", s.target, payload)

	resp, err := s.makeRequest("GET", testURL, nil)
	if err != nil {
		return
	}

	// Check if CRLF was injected into headers
	for _, values := range resp.Header {
		for _, value := range values {
			if strings.Contains(value, "evil=true") {
				s.addFinding(Finding{
					Severity:    "High",
					Category:    "HTTP Response Splitting",
					Confidence:  "High",
					Finding:     "HTTP Response Splitting vulnerability detected (CRLF injection)",
					Remediation: "Validate and sanitize all user input in headers; reject CRLF characters; use framework protections",
					Evidence:    "CRLF injection successful",
					HTTPMethod:  "GET",
					Outcome:     "Vulnerable",
				})
				return
			}
		}
	}
}

func (s *ActiveScanner) checkHostHeaderInjection() {
	if !s.config.ShouldRunModule("host_header_injection") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking Host Header Injection...")

	// Test with evil host
	headers := map[string]string{
		"Host": "evil.com",
	}

	resp, err := s.makeRequestWithHeaders("GET", s.target, nil, headers)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body := s.readBody(resp)

	// Check if evil host is reflected
	if strings.Contains(body, "evil.com") {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Host Header Injection",
			Confidence:  "Medium",
			Finding:     "Application reflects Host header value (potential password reset poisoning)",
			Remediation: "Validate Host header against whitelist; use absolute URLs; avoid Host header in email links",
			Evidence:    "Host header reflected in response",
			HTTPMethod:  "GET",
			Outcome:     "Host reflected",
		})
	}
}

func (s *ActiveScanner) checkDOMClobbering() {
	if !s.config.ShouldRunModule("dom_clobbering") {
		return
	}

	s.log("Checking DOM Clobbering vectors...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body := s.readBody(resp)

	// Check for vulnerable patterns
	if strings.Contains(body, "document.getElementById") ||
		strings.Contains(body, "window.name") {
		s.addFinding(Finding{
			Severity:    "Low",
			Category:    "DOM Clobbering",
			Confidence:  "Low",
			Finding:     "Potential DOM Clobbering vectors detected (requires manual verification)",
			Remediation: "Avoid using document.getElementById with user input; use setAttribute; validate DOM element IDs",
			Evidence:    "DOM manipulation code detected",
			HTTPMethod:  "GET",
			Outcome:     "Requires manual testing",
		})
	}
}

func (s *ActiveScanner) checkPrototypePollution() {
	if !s.config.ShouldRunModule("prototype_pollution") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking Prototype Pollution...")

	// Test with __proto__ payload
	payload := `{"__proto__":{"isAdmin":true}}`

	resp, err := s.makeRequest("POST", s.target, strings.NewReader(payload))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Prototype Pollution",
			Confidence:  "Low",
			Finding:     "Application accepts __proto__ in JSON (potential prototype pollution)",
			Remediation: "Sanitize JSON input; use Object.create(null); implement deep freeze; update dependencies",
			Evidence:    "__proto__ payload accepted",
			HTTPMethod:  "POST",
			Outcome:     "Payload accepted",
		})
	}
}

func (s *ActiveScanner) checkCSPBypass() {
	if !s.config.ShouldRunModule("csp_bypass") {
		return
	}

	s.log("Checking CSP bypass vectors...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")

	if csp != "" {
		// Check for unsafe CSP directives
		unsafeDirectives := []string{
			"unsafe-inline",
			"unsafe-eval",
			"*",
			"data:",
		}

		for _, directive := range unsafeDirectives {
			if strings.Contains(csp, directive) {
				s.addFinding(Finding{
					Severity:    "Medium",
					Category:    "CSP Bypass",
					Confidence:  "High",
					Finding:     fmt.Sprintf("Weak CSP directive detected: %s", directive),
					Remediation: "Remove unsafe-inline and unsafe-eval; use nonces or hashes; whitelist specific domains only",
					Evidence:    fmt.Sprintf("CSP contains: %s", directive),
					HTTPMethod:  "GET",
					Outcome:     "Weak CSP",
				})
			}
		}
	}
}
