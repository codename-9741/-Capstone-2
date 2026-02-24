package active

import (
	"fmt"
	"strings"
)

// detectWAF attempts to fingerprint Web Application Firewall
func (s *ActiveScanner) detectWAF() {
	fmt.Println("[ActiveScanner] Detecting WAF/CDN...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	headers := resp.Header
	detected := []string{}

	// Cloudflare
	if headers.Get("CF-RAY") != "" || strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare") {
		detected = append(detected, "Cloudflare")
	}

	// Akamai
	if strings.Contains(strings.ToLower(headers.Get("Server")), "akamai") ||
		headers.Get("X-Akamai-Transformed") != "" {
		detected = append(detected, "Akamai")
	}

	// Imperva/Incapsula
	if strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "incap_ses") ||
		strings.Contains(strings.ToLower(headers.Get("Server")), "imperva") {
		detected = append(detected, "Imperva/Incapsula")
	}

	// F5 BIG-IP
	if strings.Contains(strings.ToLower(headers.Get("Set-Cookie")), "bigip") ||
		strings.Contains(strings.ToLower(headers.Get("Server")), "f5") {
		detected = append(detected, "F5 BIG-IP")
	}

	// Radware
	if strings.Contains(strings.ToLower(headers.Get("Server")), "radware") ||
		headers.Get("X-RDWR-ID") != "" {
		detected = append(detected, "Radware")
	}

	// Sucuri
	if strings.Contains(strings.ToLower(headers.Get("Server")), "sucuri") ||
		headers.Get("X-Sucuri-ID") != "" {
		detected = append(detected, "Sucuri")
	}

	if len(detected) > 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "WAF",
			Confidence:  "High",
			Finding:     fmt.Sprintf("WAF/CDN fingerprinted: %s", strings.Join(detected, ", ")),
			Remediation: "Validate OWASP rules coverage, tune false positives, ensure WAF logs feed SIEM",
			Evidence:    strings.Join(detected, "; "),
			HTTPMethod:  "GET",
			Outcome:     "Detected",
		})
	} else {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "WAF",
			Confidence:  "Low",
			Finding:     "No obvious WAF/CDN fingerprint detected (best-effort)",
			Remediation: "If WAF exists, ensure security headers are not stripped and logs are centralized",
			Evidence:    "No signatures found",
			HTTPMethod:  "GET",
			Outcome:     "Unknown",
		})
	}

	fmt.Printf("[ActiveScanner] WAF detection complete: %d findings\n", len(s.findings))
}
