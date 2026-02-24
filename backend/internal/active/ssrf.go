package active

import "fmt"

func (s *ActiveScanner) checkSSRF() {
	if !s.config.ShouldRunModule("ssrf") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for SSRF vulnerabilities...")

	ssrfParams := []string{"url", "link", "redirect", "uri", "path", "dest", "callback"}

	// Safe SSRF test: Try to access local metadata (AWS, GCP, Azure)
	testURLs := []string{
		"http://169.254.169.254/latest/meta-data/", // AWS metadata
		"http://metadata.google.internal/",         // GCP
		"http://169.254.169.254/metadata/instance", // Azure
	}

	for _, param := range ssrfParams {
		for _, testURL := range testURLs {
			target := fmt.Sprintf("%s?%s=%s", s.target, param, testURL)

			resp, err := s.makeRequest("GET", target, nil)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				s.addFinding(Finding{
					Severity:    "Critical",
					Category:    "SSRF",
					Confidence:  "Medium",
					Finding:     fmt.Sprintf("Potential SSRF in parameter '%s'", param),
					Remediation: "Validate and whitelist allowed URLs; block internal IP ranges; implement network segmentation",
					Evidence:    fmt.Sprintf("Attempted to fetch: %s (status: %d)", testURL, resp.StatusCode),
					HTTPMethod:  "GET",
					Outcome:     "Request accepted",
				})
				break
			}
		}
	}
}
