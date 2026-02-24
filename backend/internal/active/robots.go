package active

import "strings"

func (s *ActiveScanner) checkRobotsTxt() {
	if !s.config.ShouldRunModule("robots") {
		return
	}
	s.log("Checking robots.txt...")

	resp, err := s.makeRequest("GET", s.target+"/robots.txt", nil)
	if err != nil {
		return
	}

	if resp.StatusCode == 200 {
		body := s.readBody(resp)

		// Check for sensitive paths
		sensitive := []string{"admin", "backup", "config", "database", "private"}
		found := []string{}

		for _, word := range sensitive {
			if strings.Contains(strings.ToLower(body), word) {
				found = append(found, word)
			}
		}

		severity := "Info"
		if len(found) > 0 {
			severity = "Low"
		}

		s.addFinding(Finding{
			Severity:    severity,
			Category:    "robots.txt",
			Confidence:  "High",
			Finding:     "robots.txt accessible. Sensitive paths detected: " + strings.Join(found, ", "),
			Remediation: "Review robots.txt for sensitive path disclosure",
			Evidence:    "Status 200",
			HTTPMethod:  "GET",
			Outcome:     "Found",
		})
	} else {
		resp.Body.Close()
	}
}
