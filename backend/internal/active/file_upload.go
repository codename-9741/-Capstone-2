package active

import (
	"bytes"
	"mime/multipart"
	"strings"
)

func (s *ActiveScanner) checkFileUpload() {
	if !s.config.ShouldRunModule("file_upload") || s.config.Mode == "safe" {
		return
	}
	s.log("Checking file upload security...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	if strings.Contains(body, "type=\"file\"") || strings.Contains(body, "upload") {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "File Upload",
			Confidence:  "Low",
			Finding:     "File upload functionality detected",
			Remediation: "Validate file types, scan for malware, restrict extensions, use random filenames",
			Evidence:    "File input detected in HTML",
			HTTPMethod:  "GET",
			Outcome:     "Detected",
		})
	}
}

func (s *ActiveScanner) checkUnrestrictedFileUpload() {
	if !s.config.ShouldRunModule("unrestricted_upload") || s.config.Mode != "aggressive" {
		return
	}
	s.log("Testing unrestricted file upload (aggressive)...")

	// Only test if we detect upload endpoint
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)
	if !strings.Contains(body, "upload") {
		return
	}

	// Create test payload
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.WriteField("test", "value")
	writer.Close()

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "File Upload",
		Confidence:  "Low",
		Finding:     "File upload endpoint requires manual testing",
		Remediation: "Test with various file extensions, double extensions, content-type bypass",
		Evidence:    "Upload form detected",
		HTTPMethod:  "POST",
		Outcome:     "Requires manual test",
	})
}
