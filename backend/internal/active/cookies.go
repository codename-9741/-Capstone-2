package active

import (
	"fmt"
	"strings"
)

// checkCookies analyzes cookie security attributes
func (s *ActiveScanner) checkCookies() {
	fmt.Println("[ActiveScanner] Checking cookie security...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Get Set-Cookie headers
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Cookies",
			Confidence:  "High",
			Finding:     "No cookies set by server",
			Remediation: "If authentication is used, ensure secure cookie flags are set",
			Evidence:    "No Set-Cookie headers",
			HTTPMethod:  "GET",
			Outcome:     "None",
		})
		return
	}

	// Check each cookie
	for _, cookie := range cookies {
		s.analyzeCookie(cookie)
	}

	fmt.Printf("[ActiveScanner] Cookie check complete: %d findings\n", len(s.findings))
}

// analyzeCookie checks security attributes of a single cookie
func (s *ActiveScanner) analyzeCookie(cookieHeader string) {
	// Extract cookie name
	parts := strings.Split(cookieHeader, ";")
	if len(parts) == 0 {
		return
	}

	cookieName := strings.Split(parts[0], "=")[0]
	cookieLower := strings.ToLower(cookieHeader)

	// Check if it's a session/auth cookie
	isSessionCookie := strings.Contains(strings.ToLower(cookieName), "session") ||
		strings.Contains(strings.ToLower(cookieName), "auth") ||
		strings.Contains(strings.ToLower(cookieName), "token") ||
		strings.Contains(strings.ToLower(cookieName), "jwt") ||
		strings.Contains(strings.ToLower(cookieName), "csrf")

	// Check for missing security flags
	hasSecure := strings.Contains(cookieLower, "secure")
	hasHttpOnly := strings.Contains(cookieLower, "httponly")
	hasSameSite := strings.Contains(cookieLower, "samesite")

	missingFlags := []string{}
	if !hasSecure {
		missingFlags = append(missingFlags, "Secure")
	}
	if !hasHttpOnly {
		missingFlags = append(missingFlags, "HttpOnly")
	}
	if !hasSameSite {
		missingFlags = append(missingFlags, "SameSite")
	}

	if len(missingFlags) > 0 {
		severity := "Low"
		confidence := "Low"
		if isSessionCookie {
			severity = "Medium"
			confidence = "High"
		}

		s.addFinding(Finding{
			Severity:    severity,
			Category:    "Cookies",
			Confidence:  confidence,
			Finding:     fmt.Sprintf("Cookie '%s' missing flags: %s", cookieName, strings.Join(missingFlags, ", ")),
			Remediation: "Set Secure; HttpOnly; SameSite=Strict on authentication cookies",
			Evidence:    truncate(cookieHeader, 200),
			HTTPMethod:  "GET",
			Outcome:     "Insecure",
		})
	} else if isSessionCookie {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Cookies",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Cookie '%s' has all security flags", cookieName),
			Remediation: "Continue enforcing secure cookie attributes",
			Evidence:    truncate(cookieHeader, 200),
			HTTPMethod:  "GET",
			Outcome:     "Secure",
		})
	}
}

// truncate limits string length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
