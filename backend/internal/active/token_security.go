package active

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

func (s *ActiveScanner) checkJWT() {
	if !s.config.ShouldRunModule("jwt") {
		return
	}

	s.log("Analyzing JWT tokens...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	// Check Authorization header and response body for JWTs
	authHeader := resp.Header.Get("Authorization")
	body := s.readBody(resp)

	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	tokens := jwtPattern.FindAllString(authHeader+" "+body, -1)

	for _, token := range tokens {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			continue
		}

		// Decode header
		headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}
		header := string(headerBytes)

		// Check for weak algorithms
		if strings.Contains(header, `"alg":"none"`) {
			s.addFinding(Finding{
				Severity:    "Critical",
				Category:    "JWT",
				Confidence:  "High",
				Finding:     "JWT uses 'none' algorithm (no signature verification)",
				Remediation: "Enforce strong algorithms (RS256, ES256); reject 'none' algorithm",
				Evidence:    "Algorithm: none",
				HTTPMethod:  "GET",
				Outcome:     "Weak algorithm",
			})
		}

		if strings.Contains(header, `"alg":"HS256"`) {
			s.addFinding(Finding{
				Severity:    "Medium",
				Category:    "JWT",
				Confidence:  "High",
				Finding:     "JWT uses symmetric HMAC (consider asymmetric RSA/ECDSA for better security)",
				Remediation: "Use RS256 or ES256 for better key management; rotate secrets regularly",
				Evidence:    "Algorithm: HS256",
				HTTPMethod:  "GET",
				Outcome:     "Symmetric signature",
			})
		}

		// Check payload for sensitive data
		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		payload := strings.ToLower(string(payloadBytes))

		if strings.Contains(payload, "password") || strings.Contains(payload, "secret") {
			s.addFinding(Finding{
				Severity:    "High",
				Category:    "JWT",
				Confidence:  "High",
				Finding:     "JWT contains sensitive data in payload",
				Remediation: "Never store sensitive data in JWT payload (it's base64, not encrypted); use opaque tokens for sensitive data",
				Evidence:    "Sensitive keywords detected in payload",
				HTTPMethod:  "GET",
				Outcome:     "Sensitive data exposure",
			})
		}
	}
}

func (s *ActiveScanner) checkAPIKeyExposure() {
	if !s.config.ShouldRunModule("api_key_exposure") {
		return
	}

	s.log("Checking for exposed API keys...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// API key patterns
	patterns := map[string]*regexp.Regexp{
		"AWS Access Key":   regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"Google API Key":   regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"Slack Token":      regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`),
		"Stripe Secret":    regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24,}`),
		"GitHub Token":     regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
		"Twilio API Key":   regexp.MustCompile(`SK[a-z0-9]{32}`),
		"SendGrid API Key": regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
	}

	for keyType, pattern := range patterns {
		if pattern.MatchString(body) {
			s.addFinding(Finding{
				Severity:    "Critical",
				Category:    "API Key Exposure",
				Confidence:  "High",
				Finding:     fmt.Sprintf("%s detected in response", keyType),
				Remediation: "Remove API keys from client-side code; rotate exposed keys immediately; use environment variables; implement secrets manager",
				Evidence:    fmt.Sprintf("%s pattern found (masked)", keyType),
				HTTPMethod:  "GET",
				Outcome:     "Key exposed",
			})
		}
	}
}

func (s *ActiveScanner) checkDefaultCredentials() {
	if !s.config.ShouldRunModule("default_creds") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for default credentials...")

	// Common default credentials
	_ = []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"root", "root"},
		{"administrator", "administrator"},
		{"admin", ""},
		{"guest", "guest"},
	}

	loginPaths := []string{"/login", "/admin/login", "/api/login"}

	for _, path := range loginPaths {
		loginURL := s.target + path

		resp, err := s.makeRequest("GET", loginURL, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			// Only test in aggressive mode to avoid account lockouts
			if s.config.Mode == "aggressive" {
				// Test first default cred only to minimize impact
				s.addFinding(Finding{
					Severity:    "Medium",
					Category:    "Default Credentials",
					Confidence:  "Low",
					Finding:     fmt.Sprintf("Login endpoint detected: %s (manual testing recommended for default credentials)", path),
					Remediation: "Force password change on first login; disable default accounts; implement account lockout",
					Evidence:    "Login form accessible",
					HTTPMethod:  "GET",
					Outcome:     "Login form found",
				})
			}
			break
		}
	}
}

func (s *ActiveScanner) checkPasswordReset() {
	if !s.config.ShouldRunModule("password_reset") {
		return
	}

	s.log("Checking password reset security...")

	resetPaths := []string{
		"/forgot-password",
		"/reset-password",
		"/password/reset",
		"/api/password/reset",
	}

	for _, path := range resetPaths {
		url := s.target + path

		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := s.readBody(resp)

			// Check for insecure reset mechanisms
			if strings.Contains(strings.ToLower(body), "security question") {
				s.addFinding(Finding{
					Severity:    "Medium",
					Category:    "Password Reset",
					Confidence:  "Medium",
					Finding:     "Password reset uses security questions (weak authentication)",
					Remediation: "Use time-limited email tokens (15-30 min expiry); require email verification; log all reset attempts",
					Evidence:    "Security questions detected",
					HTTPMethod:  "GET",
					Outcome:     "Weak reset method",
				})
			}
		}
	}
}

func (s *ActiveScanner) checkMFABypass() {
	if !s.config.ShouldRunModule("mfa_bypass") {
		return
	}

	s.log("Checking MFA implementation...")

	// Look for 2FA/MFA indicators
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	hasMFA := strings.Contains(strings.ToLower(body), "two-factor") ||
		strings.Contains(strings.ToLower(body), "2fa") ||
		strings.Contains(strings.ToLower(body), "mfa") ||
		strings.Contains(strings.ToLower(body), "authenticator")

	if hasMFA {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "MFA",
			Confidence:  "High",
			Finding:     "Multi-Factor Authentication detected",
			Remediation: "Ensure MFA is enforced for all users (especially admins); prevent MFA bypass via password reset; log MFA events",
			Evidence:    "MFA indicators present",
			HTTPMethod:  "GET",
			Outcome:     "MFA available",
		})
	} else {
		// Check if it's a login page without MFA
		if strings.Contains(strings.ToLower(body), "login") || strings.Contains(strings.ToLower(body), "sign in") {
			s.addFinding(Finding{
				Severity:    "Medium",
				Category:    "MFA",
				Confidence:  "Low",
				Finding:     "No MFA indicators detected on login page",
				Remediation: "Implement MFA for all accounts; use TOTP (Google Authenticator), WebAuthn (FIDO2), or SMS as fallback",
				Evidence:    "Login page without MFA indicators",
				HTTPMethod:  "GET",
				Outcome:     "No MFA detected",
			})
		}
	}
}
