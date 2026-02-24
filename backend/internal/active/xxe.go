package active

import (
	"bytes"
	"strings"
)

func (s *ActiveScanner) checkXXE() {
	if !s.config.ShouldRunModule("xxe") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking for XXE vulnerabilities...")

	// Safe XXE payload (reads /etc/hostname, non-destructive)
	payload := `<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<foo>&xxe;</foo>`

	resp, err := s.makeRequest("POST", s.target, bytes.NewBufferString(payload))
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check if file content is reflected
	if len(body) > 0 && !strings.Contains(body, "error") && len(body) < 1000 {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "XXE",
			Confidence:  "Low",
			Finding:     "Potential XXE vulnerability (XML parsing detected)",
			Remediation: "Disable external entity processing in XML parsers; use JSON instead of XML where possible",
			Evidence:    "XML payload accepted",
			HTTPMethod:  "POST",
			Outcome:     "XML processed",
		})
	}
}
