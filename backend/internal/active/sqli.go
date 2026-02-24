package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkSQLInjection() {
	if !s.config.ShouldRunModule("sqli") {
		return
	}

	s.log("Checking for SQL Injection vulnerabilities...")

	// Safe mode: Only passive detection
	if s.config.Mode == "safe" {
		s.checkSQLIPassive()
		return
	}

	// Normal/Aggressive: Test common injection points
	testParams := []string{"id", "user", "page", "category", "search", "q", "item"}

	// SQL injection payloads (safe, non-destructive)
	payloads := []string{
		"'",             // Basic syntax error
		"''",            // Double quote
		"1' OR '1'='1",  // Classic SQLi
		"1' AND '1'='2", // False condition
		"admin'--",      // Comment injection
	}

	// Only use aggressive payloads in aggressive mode
	if s.config.Mode == "aggressive" {
		payloads = append(payloads,
			"1' UNION SELECT NULL--",
			"' OR 1=1--",
			"'; WAITFOR DELAY '00:00:05'--", // Time-based (SQL Server)
		)
	}

	for _, param := range testParams {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", s.target, param, payload)

			resp, err := s.makeRequest("GET", testURL, nil)
			if err != nil {
				continue
			}

			body := s.readBody(resp)

			// Check for SQL error signatures
			if s.detectSQLError(body) {
				s.addFinding(Finding{
					Severity:    "High",
					Category:    "SQL Injection",
					Confidence:  "Medium",
					Finding:     fmt.Sprintf("Potential SQL Injection in parameter '%s'", param),
					Remediation: "Use parameterized queries/prepared statements; validate all user input; implement WAF",
					Evidence:    fmt.Sprintf("Payload: %s | Response contains SQL error", payload),
					HTTPMethod:  "GET",
					Outcome:     "Error detected",
				})
				break // Don't spam with multiple payloads
			}
		}
	}
}

func (s *ActiveScanner) checkSQLIPassive() {
	// Passive detection: Look for error messages in normal responses
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)
	if s.detectSQLError(body) {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "SQL Injection",
			Confidence:  "Low",
			Finding:     "SQL error message detected in response (passive detection)",
			Remediation: "Review application error handling; disable detailed error messages in production",
			Evidence:    "SQL error signature found",
			HTTPMethod:  "GET",
			Outcome:     "Error message exposed",
		})
	}
}

func (s *ActiveScanner) detectSQLError(body string) bool {
	errorSignatures := []string{
		"SQL syntax",
		"mysql_fetch",
		"ORA-",
		"PostgreSQL",
		"SQLite",
		"SQLSTATE",
		"Unclosed quotation mark",
		"quoted string not properly terminated",
		"mysql_num_rows",
		"pg_query",
		"SQLException",
	}

	bodyLower := strings.ToLower(body)
	for _, sig := range errorSignatures {
		if strings.Contains(bodyLower, strings.ToLower(sig)) {
			return true
		}
	}
	return false
}
