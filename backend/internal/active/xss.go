package active

import (
	"fmt"
	"net/url"
	"strings"
)

func (s *ActiveScanner) checkXSS() {
	if !s.config.ShouldRunModule("xss") {
		return
	}

	s.log("Checking for XSS vulnerabilities...")

	// Safe mode: Only check for reflected input
	if s.config.Mode == "safe" {
		s.checkXSSPassive()
		return
	}

	testParams := []string{"search", "q", "query", "name", "comment", "message"}

	// Safe XSS payloads (non-executable)
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"'\"><script>alert('XSS')</script>",
	}

	for _, param := range testParams {
		for _, payload := range payloads {
			encoded := url.QueryEscape(payload)
			testURL := fmt.Sprintf("%s?%s=%s", s.target, param, encoded)

			resp, err := s.makeRequest("GET", testURL, nil)
			if err != nil {
				continue
			}

			body := s.readBody(resp)

			// Check if payload is reflected unescaped
			if strings.Contains(body, payload) {
				s.addFinding(Finding{
					Severity:    "High",
					Category:    "XSS",
					Confidence:  "High",
					Finding:     fmt.Sprintf("Reflected XSS in parameter '%s'", param),
					Remediation: "Encode all user input before rendering; implement Content-Security-Policy; use HTML sanitization libraries",
					Evidence:    fmt.Sprintf("Payload reflected: %s", payload),
					HTTPMethod:  "GET",
					Outcome:     "Reflected",
				})
				break
			}
		}
	}
}

func (s *ActiveScanner) checkXSSPassive() {
	// Check if any user input is reflected without encoding
	testValue := "NIGHTFALL_XSS_TEST_12345"
	testURL := fmt.Sprintf("%s?test=%s", s.target, testValue)

	resp, err := s.makeRequest("GET", testURL, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)
	if strings.Contains(body, testValue) {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "XSS",
			Confidence:  "Low",
			Finding:     "User input reflected in response (potential XSS risk)",
			Remediation: "Implement proper input encoding/escaping; review all user input handling",
			Evidence:    "Test value reflected unmodified",
			HTTPMethod:  "GET",
			Outcome:     "Input reflection detected",
		})
	}
}
