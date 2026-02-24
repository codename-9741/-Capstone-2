package active

import (
	"fmt"
	"io"
	"strings"
)

// checkDirectoryListing checks for open directory listings
func (s *ActiveScanner) checkDirectoryListing() {
	fmt.Println("[ActiveScanner] Checking for directory listings...")

	// Common directories that might have listings enabled
	directories := []string{
		"/uploads/",
		"/assets/",
		"/images/",
		"/files/",
		"/documents/",
		"/media/",
		"/static/",
		"/public/",
		"/backup/",
		"/temp/",
		"/tmp/",
		"/logs/",
		"/admin/uploads/",
		"/wp-content/uploads/",
	}

	openDirs := []string{}

	for _, dir := range directories {
		if len(openDirs) >= 5 {
			break
		}

		if s.checkDirectoryListingPath(dir) {
			openDirs = append(openDirs, dir)
		}
	}

	if len(openDirs) > 0 {
		s.addFinding(Finding{

			Severity:    "Medium",
			Category:    "Directory Listing",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Open directory listings detected (%d directories)", len(openDirs)),
			Remediation: "Disable directory indexing in web server config; add index.html to all directories; use Options -Indexes in .htaccess",
			Evidence:    strings.Join(openDirs, ", "),
			HTTPMethod:  "GET",
			Outcome:     "Open",
		})
	} else {
		s.addFinding(Finding{

			Severity:    "Info",
			Category:    "Directory Listing",
			Confidence:  "High",
			Finding:     "No open directory listings detected",
			Remediation: "Continue blocking directory indexing",
			Evidence:    "All directories protected",
			HTTPMethod:  "GET",
			Outcome:     "Protected",
		})
	}

	fmt.Printf("[ActiveScanner] Directory listing check complete: %d findings\n", len(s.findings))
}

// checkDirectoryListingPath checks if a directory has listing enabled
func (s *ActiveScanner) checkDirectoryListingPath(dir string) bool {
	resp, err := s.makeRequest("GET", dir, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := strings.ToLower(string(body))

	// Check for directory listing signatures
	signatures := []string{
		"index of /",
		"<title>index of",
		"directory listing for",
		"parent directory",
		"<a href=\"?c=n;o=d\">name</a>",          // Apache
		"<th><a href=\"?c=n;o=a\">name</a></th>", // Apache
		"last modified",                          // Generic
	}

	for _, sig := range signatures {
		if strings.Contains(bodyStr, sig) {
			s.addFinding(Finding{

				Severity:    "Medium",
				Category:    "Directory Listing",
				Confidence:  "High",
				Finding:     fmt.Sprintf("Directory listing enabled: %s", dir),
				Remediation: "Disable directory indexing for this path",
				Evidence:    fmt.Sprintf("Signature: %s", sig),
				HTTPMethod:  "GET",
				Outcome:     "200 OK",
			})
			return true
		}
	}

	return false
}
