package active

import (
	"fmt"
	"strings"
)

// checkHTTPMethods tests HTTP method configuration
func (s *ActiveScanner) checkHTTPMethods() {
	fmt.Println("[ActiveScanner] Checking HTTP methods...")

	// Try OPTIONS first
	resp, err := s.makeRequest("OPTIONS", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "HTTP Methods",
		Confidence:  "High",
		Finding:     fmt.Sprintf("OPTIONS request returned: %d", resp.StatusCode),
		Remediation: "Verify only necessary methods are allowed",
		Evidence:    fmt.Sprintf("Allow: %s", allow),
		HTTPMethod:  "OPTIONS",
		Outcome:     fmt.Sprintf("%d", resp.StatusCode),
	})

	// Check if TRACE is mentioned
	if strings.Contains(strings.ToUpper(allow), "TRACE") {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "HTTP Methods",
			Confidence:  "Medium",
			Finding:     "TRACE method appears to be allowed (potential XST risk)",
			Remediation: "Disable TRACE/TRACK at the web server level",
			Evidence:    fmt.Sprintf("Allow: %s", allow),
			HTTPMethod:  "OPTIONS",
			Outcome:     "Allowed",
		})
	}

	fmt.Printf("[ActiveScanner] HTTP methods check complete: %d findings\n", len(s.findings))
}
