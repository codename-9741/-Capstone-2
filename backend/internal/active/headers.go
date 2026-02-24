package active

import "fmt"

// checkSecurityHeaders analyzes HTTP security headers
func (s *ActiveScanner) checkSecurityHeaders() {
	fmt.Println("[ActiveScanner] Checking security headers...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Connectivity",
			Confidence:  "High",
			Finding:     "Target is not reachable",
			Remediation: "Check DNS, connectivity, and firewall rules",
			Evidence:    err.Error(),
			HTTPMethod:  "GET",
			Outcome:     "Failed",
		})
		return
	}
	defer resp.Body.Close()

	headers := resp.Header

	// Critical security headers to check
	criticalHeaders := map[string]struct {
		severity    string
		remediation string
	}{
		"Content-Security-Policy": {
			"High",
			"Implement CSP: default-src 'self'; script-src 'self'",
		},
		"Strict-Transport-Security": {
			"Medium",
			"Enable HSTS: max-age=31536000; includeSubDomains; preload",
		},
		"X-Content-Type-Options": {
			"Low",
			"Set X-Content-Type-Options: nosniff",
		},
		"X-Frame-Options": {
			"Medium",
			"Set X-Frame-Options: DENY or SAMEORIGIN",
		},
		"Referrer-Policy": {
			"Low",
			"Set Referrer-Policy: strict-origin-when-cross-origin",
		},
		"Permissions-Policy": {
			"Low",
			"Define Permissions-Policy with least privilege",
		},
	}

	// Check each critical header
	for headerName, config := range criticalHeaders {
		if headers.Get(headerName) == "" {
			s.addFinding(Finding{
				Severity:    config.severity,
				Category:    "Headers",
				Confidence:  "High",
				Finding:     fmt.Sprintf("Missing security header: %s", headerName),
				Remediation: config.remediation,
				Evidence:    "Header not present",
				HTTPMethod:  "GET",
				Outcome:     "Missing",
			})
		}
	}

	// Check for information disclosure
	serverHeader := headers.Get("Server")
	if serverHeader != "" {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Headers",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Server header discloses software: %s", serverHeader),
			Remediation: "Remove or obfuscate Server header to prevent version disclosure",
			Evidence:    serverHeader,
			HTTPMethod:  "GET",
			Outcome:     "Disclosed",
		})
	}

	xPoweredBy := headers.Get("X-Powered-By")
	if xPoweredBy != "" {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Headers",
			Confidence:  "High",
			Finding:     fmt.Sprintf("X-Powered-By header discloses technology: %s", xPoweredBy),
			Remediation: "Remove X-Powered-By header to prevent technology disclosure",
			Evidence:    xPoweredBy,
			HTTPMethod:  "GET",
			Outcome:     "Disclosed",
		})
	}

	fmt.Printf("[ActiveScanner] Headers check complete: %d findings\n", len(s.findings))
}
