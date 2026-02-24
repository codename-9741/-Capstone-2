package active

import (
	"fmt"
	"io"
	"strings"
)

// checkExposures probes for sensitive file exposure
func (s *ActiveScanner) checkExposures() {
	fmt.Println("[ActiveScanner] Checking for sensitive file exposures...")

	// Common sensitive paths
	exposurePaths := []string{
		"/.env",
		"/.git/config",
		"/backup.sql",
		"/backup.zip",
		"/db.sql",
		"/config.php~",
		"/.aws/credentials",
		"/composer.json",
		"/package.json",
	}

	for _, path := range exposurePaths {
		s.checkExposurePath(path)
	}

	fmt.Printf("[ActiveScanner] Exposure check complete: %d findings\n", len(s.findings))
}

// checkExposurePath checks a single path for exposure
func (s *ActiveScanner) checkExposurePath(path string) {
	// Try HEAD first
	resp, err := s.makeRequest("HEAD", path, nil)
	if err != nil {
		return
	}
	resp.Body.Close()

	// If not accessible, skip
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return
	}

	// GET with range header (partial content)
	resp, err = s.makeRequest("GET", path, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read first 4KB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return
	}

	bodyStr := strings.ToLower(string(body))
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))

	// Signature-based validation
	confirmed := false
	if path == "/.env" {
		confirmed = strings.Contains(bodyStr, "db_password") ||
			strings.Contains(bodyStr, "database_url") ||
			strings.Contains(bodyStr, "aws_secret") ||
			strings.Contains(bodyStr, "secret_key") ||
			strings.Contains(bodyStr, "api_key")
	} else if path == "/.git/config" {
		confirmed = strings.Contains(bodyStr, "[core]") ||
			strings.Contains(bodyStr, "repositoryformatversion") ||
			strings.Contains(bodyStr, "[remote")
	} else if strings.HasSuffix(path, ".sql") {
		confirmed = strings.Contains(bodyStr, "create table") ||
			strings.Contains(bodyStr, "insert into") ||
			strings.Contains(bodyStr, "database")
	} else if strings.HasSuffix(path, ".json") {
		confirmed = strings.Contains(bodyStr, "dependencies") ||
			strings.Contains(bodyStr, "devdependencies") ||
			strings.Contains(bodyStr, "require")
	}

	severity := "Medium"
	confidence := "Low"
	if confirmed {
		severity = "High"
		confidence = "High"
		if path == "/.env" || path == "/.git/config" {
			severity = "Critical"
		}
	}

	outcome := fmt.Sprintf("%d", resp.StatusCode)
	if confirmed {
		outcome += " (Confirmed)"
	} else {
		outcome += " (Unconfirmed)"
	}

	finding := fmt.Sprintf("Potential sensitive exposure: %s", path)
	if confirmed {
		finding = fmt.Sprintf("Confirmed sensitive exposure: %s", path)
	}

	s.addFinding(Finding{
		Severity:    severity,
		Category:    "Exposure",
		Confidence:  confidence,
		Finding:     finding,
		Remediation: "Remove from web root; block via server rules; rotate any exposed secrets",
		Evidence:    fmt.Sprintf("status=%d ct=%s", resp.StatusCode, contentType),
		HTTPMethod:  "GET",
		Outcome:     outcome,
	})
}
