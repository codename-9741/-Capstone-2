package active

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// checkHTMLComments scans for sensitive data in HTML comments
func (s *ActiveScanner) checkHTMLComments() {
	fmt.Println("[ActiveScanner] Scanning HTML comments...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Extract HTML comments
	commentRegex := regexp.MustCompile(`<!--(.*?)-->`)
	comments := commentRegex.FindAllStringSubmatch(bodyStr, -1)

	if len(comments) == 0 {
		s.addFinding(Finding{

			Severity:    "Info",
			Category:    "HTML Comments",
			Confidence:  "High",
			Finding:     "No HTML comments found",
			Remediation: "Continue removing comments in production builds",
			Evidence:    "No comments detected",
			HTTPMethod:  "GET",
			Outcome:     "Clean",
		})
		return
	}

	// Analyze comments for sensitive data
	sensitivePatterns := map[string]*regexp.Regexp{
		"Password":     regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*[\w!@#$%^&*()]+`),
		"API Key":      regexp.MustCompile(`(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*[\w-]{16,}`),
		"Secret":       regexp.MustCompile(`(?i)(secret|token)\s*[:=]\s*[\w-]{16,}`),
		"Email":        regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		"IP Address":   regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		"Internal URL": regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.local|\.internal)`),
		"TODO":         regexp.MustCompile(`(?i)(todo|fixme|hack|bug|xxx|temp|debug)`),
	}

	findings := make(map[string][]string)

	for _, match := range comments {
		if len(match) < 2 {
			continue
		}
		comment := match[1]

		for category, pattern := range sensitivePatterns {
			if pattern.MatchString(comment) {
				evidence := strings.TrimSpace(comment)
				if len(evidence) > 100 {
					evidence = evidence[:100] + "..."
				}
				findings[category] = append(findings[category], evidence)
			}
		}
	}

	// Report findings
	if len(findings) > 0 {
		for category, evidenceList := range findings {
			severity := "Low"
			if category == "Password" || category == "API Key" || category == "Secret" {
				severity = "High"
			} else if category == "Email" || category == "Internal URL" {
				severity = "Medium"
			}

			s.addFinding(Finding{

				Severity:    severity,
				Category:    "HTML Comments",
				Confidence:  "High",
				Finding:     fmt.Sprintf("Sensitive data in HTML comments: %s (%d occurrences)", category, len(evidenceList)),
				Remediation: "Remove all comments from production HTML; use build tools to strip comments automatically",
				Evidence:    evidenceList[0],
				HTTPMethod:  "GET",
				Outcome:     "Found",
			})
		}
	} else {
		s.addFinding(Finding{

			Severity:    "Info",
			Category:    "HTML Comments",
			Confidence:  "Medium",
			Finding:     fmt.Sprintf("HTML comments found (%d) but no obvious sensitive data", len(comments)),
			Remediation: "Review comments manually; remove in production",
			Evidence:    fmt.Sprintf("%d comments", len(comments)),
			HTTPMethod:  "GET",
			Outcome:     "Clean",
		})
	}

	fmt.Printf("[ActiveScanner] HTML comment check complete: %d findings\n", len(s.findings))
}
