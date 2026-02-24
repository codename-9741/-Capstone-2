package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkFileInclusion() {
	if !s.config.ShouldRunModule("file_inclusion") {
		return
	}

	s.log("Checking for File Inclusion vulnerabilities...")

	if s.config.Mode == "safe" {
		return // Skip in safe mode
	}

	fileParams := []string{"file", "page", "include", "path", "dir", "load"}

	// LFI payloads
	lfiPayloads := []string{
		"../../../../etc/passwd",
		"..\\..\\..\\..\\windows\\win.ini",
		"/etc/passwd",
		"C:\\windows\\win.ini",
	}

	for _, param := range fileParams {
		for _, payload := range lfiPayloads {
			target := fmt.Sprintf("%s?%s=%s", s.target, param, payload)

			resp, err := s.makeRequest("GET", target, nil)
			if err != nil {
				continue
			}

			body := s.readBody(resp)

			// Check for file content signatures
			if strings.Contains(body, "root:x:") || strings.Contains(body, "[extensions]") {
				s.addFinding(Finding{
					Severity:    "Critical",
					Category:    "Local File Inclusion",
					Confidence:  "High",
					Finding:     fmt.Sprintf("LFI vulnerability in parameter '%s'", param),
					Remediation: "Never include files based on user input; use whitelist of allowed files; disable allow_url_include",
					Evidence:    fmt.Sprintf("File content exposed: %s", payload),
					HTTPMethod:  "GET",
					Outcome:     "File read successful",
				})
				break
			}
		}
	}
}

func (s *ActiveScanner) checkPathTraversal() {
	if !s.config.ShouldRunModule("path_traversal") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for Path Traversal...")

	// Test common traversal patterns
	paths := []string{
		"../",
		"..\\",
		"....//",
		"..;/",
	}

	for _, path := range paths {
		target := fmt.Sprintf("%s%s", s.target, path)
		resp, err := s.makeRequest("GET", target, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := s.readBody(resp)
			if len(body) > 0 {
				s.addFinding(Finding{
					Severity:    "High",
					Category:    "Path Traversal",
					Confidence:  "Low",
					Finding:     "Path traversal characters accepted",
					Remediation: "Sanitize file paths; use basename(); reject traversal characters",
					Evidence:    fmt.Sprintf("Traversal pattern: %s", path),
					HTTPMethod:  "GET",
					Outcome:     "Accepted",
				})
			}
		}
	}
}
