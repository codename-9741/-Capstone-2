package active

import (
	"strings"
)

func (s *ActiveScanner) checkGDPRCompliance() {
	if !s.config.ShouldRunModule("gdpr") {
		return
	}

	s.log("Checking GDPR compliance indicators...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check for privacy policy
	hasPrivacyPolicy := strings.Contains(strings.ToLower(body), "privacy policy") ||
		strings.Contains(strings.ToLower(body), "data protection")

	// Check for cookie consent
	hasCookieConsent := strings.Contains(strings.ToLower(body), "cookie consent") ||
		strings.Contains(strings.ToLower(body), "accept cookies")

	if !hasPrivacyPolicy {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "GDPR",
			Confidence:  "Low",
			Finding:     "No privacy policy link detected",
			Remediation: "Implement privacy policy; provide data processing information; enable user data rights (access, deletion)",
			Evidence:    "Privacy policy not found",
			HTTPMethod:  "GET",
			Outcome:     "Missing privacy policy",
		})
	}

	if !hasCookieConsent {
		s.addFinding(Finding{
			Severity:    "Low",
			Category:    "GDPR",
			Confidence:  "Low",
			Finding:     "No cookie consent banner detected",
			Remediation: "Implement cookie consent mechanism; allow users to reject non-essential cookies",
			Evidence:    "Cookie consent not found",
			HTTPMethod:  "GET",
			Outcome:     "Missing consent",
		})
	}
}

func (s *ActiveScanner) checkCCPACompliance() {
	if !s.config.ShouldRunModule("ccpa") {
		return
	}

	s.log("Checking CCPA compliance indicators...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check for "Do Not Sell My Info" link
	hasDoNotSell := strings.Contains(strings.ToLower(body), "do not sell") ||
		strings.Contains(strings.ToLower(body), "ccpa")

	if !hasDoNotSell {
		s.addFinding(Finding{
			Severity:    "Low",
			Category:    "CCPA",
			Confidence:  "Low",
			Finding:     "No 'Do Not Sell My Info' link detected (required for California users)",
			Remediation: "Implement CCPA compliance: provide opt-out mechanism, data deletion requests, disclosure of data collection",
			Evidence:    "CCPA indicators not found",
			HTTPMethod:  "GET",
			Outcome:     "Missing CCPA link",
		})
	}
}

func (s *ActiveScanner) checkPCIDSS() {
	if !s.config.ShouldRunModule("pci_dss") {
		return
	}

	s.log("Checking PCI DSS indicators...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check for payment processing
	hasPayment := strings.Contains(strings.ToLower(body), "payment") ||
		strings.Contains(strings.ToLower(body), "credit card") ||
		strings.Contains(strings.ToLower(body), "checkout")

	if hasPayment {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "PCI DSS",
			Confidence:  "Low",
			Finding:     "Payment processing indicators detected (verify PCI DSS compliance)",
			Remediation: "PCI DSS requirements: encrypt cardholder data, maintain secure network, implement access controls, monitor networks, test security systems",
			Evidence:    "Payment indicators found",
			HTTPMethod:  "GET",
			Outcome:     "Payment detected",
		})
	}
}

func (s *ActiveScanner) checkHIPAACompliance() {
	if !s.config.ShouldRunModule("hipaa") {
		return
	}

	s.log("Checking HIPAA compliance indicators...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check for healthcare indicators
	hasHealthcare := strings.Contains(strings.ToLower(body), "medical") ||
		strings.Contains(strings.ToLower(body), "health") ||
		strings.Contains(strings.ToLower(body), "patient")

	if hasHealthcare {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "HIPAA",
			Confidence:  "Low",
			Finding:     "Healthcare indicators detected (verify HIPAA compliance)",
			Remediation: "HIPAA requirements: encrypt PHI, implement access controls, audit logs, business associate agreements, breach notification",
			Evidence:    "Healthcare indicators found",
			HTTPMethod:  "GET",
			Outcome:     "Healthcare detected",
		})
	}
}

func (s *ActiveScanner) checkDataRetention() {
	if !s.config.ShouldRunModule("data_retention") {
		return
	}

	s.log("Checking data retention policies...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Data Retention",
		Confidence:  "Low",
		Finding:     "Data retention requires policy review and backend verification",
		Remediation: "Implement data retention policies; auto-delete old data; provide user data deletion; document retention periods",
		Evidence:    "Requires policy review",
		HTTPMethod:  "N/A",
		Outcome:     "Manual review required",
	})
}
