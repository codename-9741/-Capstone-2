package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkCommandInjection() {
	if !s.config.ShouldRunModule("command_injection") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for Command Injection...")

	params := []string{"cmd", "exec", "command", "ping", "host"}

	// Safe command injection tests
	payloads := []string{
		"; whoami",
		"| whoami",
		"` whoami `",
		"$( whoami )",
	}

	for _, param := range params {
		for _, payload := range payloads {
			target := fmt.Sprintf("%s?%s=%s", s.target, param, payload)

			resp, err := s.makeRequest("GET", target, nil)
			if err != nil {
				continue
			}

			body := s.readBody(resp)

			// Check for command output signatures
			if strings.Contains(body, "uid=") || strings.Contains(body, "gid=") {
				s.addFinding(Finding{
					Severity:    "Critical",
					Category:    "Command Injection",
					Confidence:  "High",
					Finding:     fmt.Sprintf("Command Injection in parameter '%s'", param),
					Remediation: "Never execute user input; use parameterized APIs; implement strict input validation",
					Evidence:    "Command output detected in response",
					HTTPMethod:  "GET",
					Outcome:     "Command executed",
				})
				break
			}
		}
	}
}

func (s *ActiveScanner) checkLDAPInjection() {
	if !s.config.ShouldRunModule("ldap_injection") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for LDAP Injection...")

	params := []string{"username", "user", "login"}
	payloads := []string{"*", "admin*", "*)(uid=*))(|(uid=*"}

	for _, param := range params {
		for _, payload := range payloads {
			target := fmt.Sprintf("%s?%s=%s", s.target, param, payload)

			resp, err := s.makeRequest("GET", target, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				body := s.readBody(resp)
				if strings.Contains(body, "ldap") || len(body) > 5000 {
					s.addFinding(Finding{
						Severity:    "High",
						Category:    "LDAP Injection",
						Confidence:  "Low",
						Finding:     "Potential LDAP Injection",
						Remediation: "Escape LDAP special characters; use parameterized LDAP queries",
						Evidence:    fmt.Sprintf("LDAP payload: %s", payload),
						HTTPMethod:  "GET",
						Outcome:     "Suspicious response",
					})
				}
			}
		}
	}
}

func (s *ActiveScanner) checkTemplateInjection() {
	if !s.config.ShouldRunModule("ssti") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for Server-Side Template Injection...")

	params := []string{"name", "template", "view", "page"}

	// SSTI payloads (safe math operations)
	payloads := []string{
		"{{7*7}}",    // Jinja2/Twig
		"${7*7}",     // Many template engines
		"<%= 7*7 %>", // ERB
		"#{7*7}",     // Ruby
	}

	for _, param := range params {
		for _, payload := range payloads {
			target := fmt.Sprintf("%s?%s=%s", s.target, param, payload)

			resp, err := s.makeRequest("GET", target, nil)
			if err != nil {
				continue
			}

			body := s.readBody(resp)

			// Check if math was executed (49 = 7*7)
			if strings.Contains(body, "49") {
				s.addFinding(Finding{
					Severity:    "Critical",
					Category:    "SSTI",
					Confidence:  "High",
					Finding:     fmt.Sprintf("Template Injection in parameter '%s'", param),
					Remediation: "Never render user input directly in templates; use sandboxed template engines",
					Evidence:    fmt.Sprintf("Math executed: %s = 49", payload),
					HTTPMethod:  "GET",
					Outcome:     "Template executed",
				})
				break
			}
		}
	}
}
