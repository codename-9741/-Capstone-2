package active

import (
	"fmt"
	"strings"
	"time"
)

func (s *ActiveScanner) checkWeakPasswordPolicy() {
	if !s.config.ShouldRunModule("password_policy") {
		return
	}

	s.log("Checking password policy...")

	// Look for registration/password change forms
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check for password input fields
	hasPasswordField := strings.Contains(body, `type="password"`) ||
		strings.Contains(body, `type='password'`)

	if hasPasswordField {
		// Check for password requirements indicators
		hasRequirements := strings.Contains(strings.ToLower(body), "minimum") ||
			strings.Contains(strings.ToLower(body), "character") ||
			strings.Contains(strings.ToLower(body), "uppercase") ||
			strings.Contains(strings.ToLower(body), "special")

		if !hasRequirements {
			s.addFinding(Finding{
				Severity:    "Medium",
				Category:    "Password Policy",
				Confidence:  "Low",
				Finding:     "No visible password complexity requirements",
				Remediation: "Implement strong password policy: min 12 chars, uppercase, lowercase, numbers, special chars; use password strength meter",
				Evidence:    "Password field detected without visible requirements",
				HTTPMethod:  "GET",
				Outcome:     "Weak policy indicators",
			})
		}
	}
}

func (s *ActiveScanner) checkRateLimiting() {
	if !s.config.ShouldRunModule("rate_limiting") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking rate limiting...")

	// Test with rapid requests
	const testRequests = 20
	var responses []int

	start := time.Now()
	for i := 0; i < testRequests; i++ {
		resp, err := s.makeRequest("GET", s.target, nil)
		if err != nil {
			continue
		}
		responses = append(responses, resp.StatusCode)

		// Check for rate limit response (429)
		if resp.StatusCode == 429 {
			s.addFinding(Finding{
				Severity:    "Info",
				Category:    "Rate Limiting",
				Confidence:  "High",
				Finding:     fmt.Sprintf("Rate limiting detected after %d requests", i+1),
				Remediation: "Continue enforcing rate limits on all sensitive endpoints",
				Evidence:    "HTTP 429 received",
				HTTPMethod:  "GET",
				Outcome:     "Protected",
			})
			return
		}

		time.Sleep(50 * time.Millisecond) // Small delay between requests
	}

	elapsed := time.Since(start)

	// If all requests succeeded quickly, rate limiting may be missing
	successCount := 0
	for _, status := range responses {
		if status == 200 {
			successCount++
		}
	}

	if successCount == testRequests && elapsed < 5*time.Second {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Rate Limiting",
			Confidence:  "Medium",
			Finding:     fmt.Sprintf("No rate limiting detected (%d rapid requests succeeded)", testRequests),
			Remediation: "Implement rate limiting per IP/user: 100 req/min for general, 5 req/min for login/auth endpoints",
			Evidence:    fmt.Sprintf("All %d requests succeeded in %v", testRequests, elapsed),
			HTTPMethod:  "GET",
			Outcome:     "No protection",
		})
	}
}

func (s *ActiveScanner) checkBruteForceProtection() {
	if !s.config.ShouldRunModule("brute_force") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking brute force protection...")

	// Look for login endpoints
	loginPaths := []string{"/login", "/api/login", "/auth/login", "/signin", "/api/auth"}

	for _, path := range loginPaths {
		loginURL := s.target + path

		resp, err := s.makeRequest("GET", loginURL, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 405 {
			// Found a login endpoint, test for account lockout
			s.addFinding(Finding{
				Severity:    "Info",
				Category:    "Brute Force Protection",
				Confidence:  "Low",
				Finding:     fmt.Sprintf("Login endpoint detected: %s", path),
				Remediation: "Implement: account lockout after 5 failed attempts, exponential backoff, CAPTCHA after 3 attempts, MFA",
				Evidence:    fmt.Sprintf("Endpoint accessible: %s (status: %d)", path, resp.StatusCode),
				HTTPMethod:  "GET",
				Outcome:     "Login endpoint found",
			})
			break // Only report once
		}
	}
}
