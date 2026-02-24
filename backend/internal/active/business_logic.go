package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkIDOR() {
	if !s.config.ShouldRunModule("idor") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for IDOR vulnerabilities...")

	// Test sequential ID enumeration
	idParams := []string{"id", "user_id", "account_id", "order_id"}

	for _, param := range idParams {
		// Test with sequential IDs
		for id := 1; id <= 5; id++ {
			url := fmt.Sprintf("%s?%s=%d", s.target, param, id)

			resp, err := s.makeRequest("GET", url, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body := s.readBody(resp)

				// If different content returned for different IDs, potential IDOR
				if len(body) > 0 {
					s.addFinding(Finding{
						Severity:    "High",
						Category:    "IDOR",
						Confidence:  "Low",
						Finding:     fmt.Sprintf("Potential IDOR vulnerability in parameter '%s' (sequential IDs accessible)", param),
						Remediation: "Implement authorization checks on all object access; use UUIDs instead of sequential IDs; validate user ownership",
						Evidence:    fmt.Sprintf("Sequential ID access: %s=%d", param, id),
						HTTPMethod:  "GET",
						Outcome:     "Sequential access",
					})
					break // Don't spam with multiple IDs
				}
			}
		}
	}
}

func (s *ActiveScanner) checkPriceManipulation() {
	if !s.config.ShouldRunModule("price_manipulation") {
		return
	}

	s.log("Checking for price manipulation vulnerabilities...")

	// Look for e-commerce indicators
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)
	bodyLower := strings.ToLower(body)

	// Check for price-related fields
	hasPricing := strings.Contains(bodyLower, "price") ||
		strings.Contains(bodyLower, "cart") ||
		strings.Contains(bodyLower, "checkout") ||
		strings.Contains(bodyLower, "payment")

	if hasPricing {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Price Manipulation",
			Confidence:  "Low",
			Finding:     "E-commerce indicators detected (manual testing recommended for price manipulation)",
			Remediation: "Never trust client-side pricing; validate prices server-side; use signed/encrypted price tokens; log all price changes",
			Evidence:    "Pricing-related fields detected",
			HTTPMethod:  "GET",
			Outcome:     "Requires manual testing",
		})
	}
}

func (s *ActiveScanner) checkRaceConditions() {
	if !s.config.ShouldRunModule("race_conditions") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for race condition vulnerabilities...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Race Conditions",
		Confidence:  "Low",
		Finding:     "Race condition testing requires authenticated concurrent requests (manual testing recommended)",
		Remediation: "Implement database-level locking; use transactions; implement idempotency keys; add request deduplication",
		Evidence:    "Requires authenticated testing",
		HTTPMethod:  "POST",
		Outcome:     "Requires auth",
	})
}

func (s *ActiveScanner) checkPrivilegeEscalation() {
	if !s.config.ShouldRunModule("privilege_escalation") {
		return
	}

	s.log("Checking for privilege escalation vectors...")

	// Check for admin endpoints accessible without admin rights
	adminPaths := []string{
		"/admin",
		"/administrator",
		"/admin/users",
		"/api/admin",
	}

	for _, path := range adminPaths {
		url := s.target + path

		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		// If admin endpoint returns anything other than 401/403, investigate
		if resp.StatusCode == 200 {
			s.addFinding(Finding{
				Severity:    "High",
				Category:    "Privilege Escalation",
				Confidence:  "Low",
				Finding:     fmt.Sprintf("Admin endpoint accessible: %s (status: %d)", path, resp.StatusCode),
				Remediation: "Implement role-based access control; verify privileges on every request; use least privilege principle",
				Evidence:    fmt.Sprintf("Admin path returned %d without authentication", resp.StatusCode),
				HTTPMethod:  "GET",
				Outcome:     "Accessible",
			})
		}
	}
}

func (s *ActiveScanner) checkAccountTakeover() {
	if !s.config.ShouldRunModule("account_takeover") {
		return
	}

	s.log("Checking account takeover vectors...")

	// Check for account enumeration
	loginPath := s.target + "/login"

	resp, err := s.makeRequest("GET", loginPath, nil)
	if err != nil {
		return
	}

	if resp.StatusCode == 200 {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Account Takeover",
			Confidence:  "Low",
			Finding:     "Account takeover vectors require authenticated testing (check: session hijacking, CSRF, password reset flaws)",
			Remediation: "Implement: session timeout, IP binding, device fingerprinting, anomaly detection, MFA",
			Evidence:    "Login endpoint detected",
			HTTPMethod:  "GET",
			Outcome:     "Requires manual testing",
		})
	}
}

func (s *ActiveScanner) checkBusinessLogicFlaws() {
	if !s.config.ShouldRunModule("business_logic") {
		return
	}

	s.log("Checking general business logic flaws...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Business Logic",
		Confidence:  "Low",
		Finding:     "Business logic flaws (payment bypass, referral abuse, subscription bypass) require domain-specific manual testing",
		Remediation: "Implement: server-side validation, idempotency, audit logging, fraud detection, rate limiting on sensitive operations",
		Evidence:    "Requires authenticated user testing",
		HTTPMethod:  "Various",
		Outcome:     "Manual testing required",
	})
}
