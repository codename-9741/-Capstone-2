package active

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// checkEmailAddresses extracts email addresses from HTML
func (s *ActiveScanner) checkEmailAddresses() {
	fmt.Println("[ActiveScanner] Extracting email addresses...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Email regex
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	matches := emailRegex.FindAllString(bodyStr, -1)

	// Deduplicate
	seen := make(map[string]bool)
	unique := []string{}
	for _, email := range matches {
		emailLower := strings.ToLower(email)
		// Skip common false positives
		if strings.Contains(emailLower, "example.com") ||
			strings.Contains(emailLower, "example.org") ||
			strings.Contains(emailLower, "test.com") ||
			strings.Contains(emailLower, "sample.com") {
			continue
		}
		if !seen[emailLower] {
			seen[emailLower] = true
			unique = append(unique, email)
		}
	}

	if len(unique) > 0 {
		s.addFinding(Finding{

			Severity:    "Low",
			Category:    "Email Addresses",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Email addresses found in HTML (%d unique)", len(unique)),
			Remediation: "Obfuscate emails to prevent scraping; use contact forms instead; implement CAPTCHA; comply with GDPR",
			Evidence:    strings.Join(unique[:min(5, len(unique))], ", "),
			HTTPMethod:  "GET",
			Outcome:     "Exposed",
		})
	} else {
		s.addFinding(Finding{

			Severity:    "Info",
			Category:    "Email Addresses",
			Confidence:  "High",
			Finding:     "No email addresses found in HTML",
			Remediation: "Continue using obfuscation or contact forms",
			Evidence:    "No emails detected",
			HTTPMethod:  "GET",
			Outcome:     "Protected",
		})
	}

	fmt.Printf("[ActiveScanner] Email extraction complete: %d findings\n", len(s.findings))
}
