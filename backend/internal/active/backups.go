package active

import (
	"fmt"
	"path"
	"strings"
)

// checkBackupFiles probes for backup file exposure
func (s *ActiveScanner) checkBackupFiles() {
	fmt.Println("[ActiveScanner] Checking for backup files...")

	// Common backup extensions and patterns
	backupPatterns := []struct {
		path        string
		description string
	}{
		{"/.env.backup", "Environment config backup"},
		{"/.env.bak", "Environment config backup"},
		{"/.env.old", "Old environment config"},
		{"/config.php.bak", "PHP config backup"},
		{"/config.php~", "PHP config temp"},
		{"/config.php.old", "Old PHP config"},
		{"/web.config.bak", "IIS config backup"},
		{"/wp-config.php.bak", "WordPress config backup"},
		{"/database.sql", "Database dump"},
		{"/backup.sql", "Database backup"},
		{"/db.sql", "Database file"},
		{"/dump.sql", "Database dump"},
		{"/backup.zip", "Backup archive"},
		{"/backup.tar.gz", "Backup archive"},
		{"/site-backup.zip", "Site backup"},
		{"/www.zip", "WWW backup"},
		{"/public_html.zip", "Public HTML backup"},
		{"/index.php.bak", "Index backup"},
		{"/index.html.bak", "Index backup"},
		{"/composer.json.bak", "Composer backup"},
		{"/package.json.bak", "NPM package backup"},
	}

	// Also check common filenames with backup extensions
	commonFiles := []string{
		"/index.php", "/index.html", "/config.php", "/settings.php",
		"/app.js", "/main.js", "/config.js",
	}

	backupExts := []string{".bak", ".backup", ".old", ".tmp", "~", ".save", ".copy"}

	for _, file := range commonFiles {
		for _, ext := range backupExts {
			backupPatterns = append(backupPatterns, struct {
				path        string
				description string
			}{
				path:        file + ext,
				description: fmt.Sprintf("%s backup", path.Base(file)),
			})
		}
	}

	foundBackups := []string{}

	// Check each pattern
	for _, pattern := range backupPatterns {
		if len(foundBackups) >= 10 {
			break
		}

		if s.checkBackupFile(pattern.path, pattern.description) {
			foundBackups = append(foundBackups, pattern.path)
		}
	}

	if len(foundBackups) > 0 {
		s.addFinding(Finding{

			Severity:    "High",
			Category:    "Backup Files",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Backup files exposed (%d found)", len(foundBackups)),
			Remediation: "Remove all backup files from web root; use .htaccess or server config to block backup extensions; store backups outside web root",
			Evidence:    strings.Join(foundBackups[:min(5, len(foundBackups))], ", "),
			HTTPMethod:  "GET",
			Outcome:     "Exposed",
		})
	} else {
		s.addFinding(Finding{

			Severity:    "Info",
			Category:    "Backup Files",
			Confidence:  "High",
			Finding:     "No backup files detected",
			Remediation: "Continue blocking backup file access",
			Evidence:    "No backup files found",
			HTTPMethod:  "GET",
			Outcome:     "Protected",
		})
	}

	fmt.Printf("[ActiveScanner] Backup file check complete: %d findings\n", len(s.findings))
}

// checkBackupFile checks if a backup file is accessible
func (s *ActiveScanner) checkBackupFile(path, description string) bool {
	resp, err := s.makeRequest("HEAD", path, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		s.addFinding(Finding{

			Severity:    "High",
			Category:    "Backup Files",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Backup file accessible: %s", path),
			Remediation: fmt.Sprintf("Remove %s from web root immediately", path),
			Evidence:    description,
			HTTPMethod:  "HEAD",
			Outcome:     "200 OK",
		})
		return true
	}

	return false
}
