package active

import (
	"fmt"
	"strings"
)

// checkClickjacking checks for clickjacking protection
func (s *ActiveScanner) checkClickjacking() {
	fmt.Println("[ActiveScanner] Checking clickjacking protection...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	headers := resp.Header

	xfo := headers.Get("X-Frame-Options")
	csp := headers.Get("Content-Security-Policy")

	// Check for frame-ancestors in CSP
	hasFrameAncestors := strings.Contains(strings.ToLower(csp), "frame-ancestors")

	// No protection
	if xfo == "" && !hasFrameAncestors {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Clickjacking",
			Confidence:  "Medium",
			Finding:     "Clickjacking protection not detected (no X-Frame-Options and no CSP frame-ancestors)",
			Remediation: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
			Evidence:    "XFO missing; CSP frame-ancestors missing",
			HTTPMethod:  "GET",
			Outcome:     "Not Protected",
		})
		return
	}

	// Has X-Frame-Options
	if xfo != "" {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Clickjacking",
			Confidence:  "High",
			Finding:     fmt.Sprintf("X-Frame-Options set: %s", xfo),
			Remediation: "Continue enforcing frame protection",
			Evidence:    xfo,
			HTTPMethod:  "GET",
			Outcome:     "Protected",
		})
	}

	// Has CSP frame-ancestors
	if hasFrameAncestors {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Clickjacking",
			Confidence:  "High",
			Finding:     "CSP frame-ancestors directive detected",
			Remediation: "Continue enforcing CSP frame protection",
			Evidence:    "frame-ancestors present in CSP",
			HTTPMethod:  "GET",
			Outcome:     "Protected",
		})
	}

	fmt.Printf("[ActiveScanner] Clickjacking check complete: %d findings\n", len(s.findings))
}
