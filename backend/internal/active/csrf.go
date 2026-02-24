package active

import "strings"

func (s *ActiveScanner) checkCSRF() {
	if !s.config.ShouldRunModule("csrf") {
		return
	}

	s.log("Checking CSRF protection...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)
	hasForm := strings.Contains(body, "<form")
	hasCSRFToken := strings.Contains(body, "csrf") || strings.Contains(body, "_token") ||
		strings.Contains(body, "authenticity_token")

	if hasForm && !hasCSRFToken {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "CSRF",
			Confidence:  "Medium",
			Finding:     "Forms detected without obvious CSRF tokens",
			Remediation: "Implement CSRF tokens on all state-changing operations; validate Origin/Referer headers; use SameSite cookies",
			Evidence:    "Forms present, no CSRF token patterns found",
			HTTPMethod:  "GET",
			Outcome:     "No CSRF protection detected",
		})
	}
}
