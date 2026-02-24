package active

import (
	"fmt"
	"strings"
)

// checkCORS analyzes CORS policy configuration
func (s *ActiveScanner) checkCORS() {
	fmt.Println("[ActiveScanner] Checking CORS policy...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	headers := resp.Header

	acao := headers.Get("Access-Control-Allow-Origin")
	acac := headers.Get("Access-Control-Allow-Credentials")

	// No CORS headers
	if acao == "" {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "CORS",
			Confidence:  "High",
			Finding:     "No CORS headers detected",
			Remediation: "If API is public, configure CORS with explicit allowed origins",
			Evidence:    "No Access-Control-Allow-Origin header",
			HTTPMethod:  "GET",
			Outcome:     "None",
		})
		return
	}

	// Wildcard with credentials (CRITICAL)
	if strings.TrimSpace(acao) == "*" && strings.ToLower(strings.TrimSpace(acac)) == "true" {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "CORS",
			Confidence:  "High",
			Finding:     "CORS allows wildcard '*' with credentials enabled",
			Remediation: "Never use '*' with credentials. Set explicit allowed origins and validate per request",
			Evidence:    fmt.Sprintf("ACAO=%s | ACAC=%s", acao, acac),
			HTTPMethod:  "GET",
			Outcome:     "Misconfigured",
		})
		return
	}

	// Wildcard without credentials (Medium)
	if strings.TrimSpace(acao) == "*" {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "CORS",
			Confidence:  "Low",
			Finding:     "CORS allows wildcard origin '*'",
			Remediation: "Prefer explicit trusted origins; avoid wildcard when not required",
			Evidence:    fmt.Sprintf("ACAO=%s", acao),
			HTTPMethod:  "GET",
			Outcome:     "Permissive",
		})
		return
	}

	// Specific origin (good)
	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "CORS",
		Confidence:  "High",
		Finding:     fmt.Sprintf("CORS configured with specific origin: %s", acao),
		Remediation: "Validate allowed origins on server-side and maintain allowlist",
		Evidence:    fmt.Sprintf("ACAO=%s", acao),
		HTTPMethod:  "GET",
		Outcome:     "Configured",
	})

	fmt.Printf("[ActiveScanner] CORS check complete: %d findings\n", len(s.findings))
}
