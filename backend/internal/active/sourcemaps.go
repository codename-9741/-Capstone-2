package active

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// checkSourceMaps detects exposed source map files
func (s *ActiveScanner) checkSourceMaps() {
	fmt.Println("[ActiveScanner] Checking for source map exposure...")

	// Get main page
	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Find .js and .css file references
	jsRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js)["']`)
	cssRegex := regexp.MustCompile(`<link[^>]+href=["']([^"']+\.css)["']`)

	jsFiles := jsRegex.FindAllStringSubmatch(bodyStr, -1)
	cssFiles := cssRegex.FindAllStringSubmatch(bodyStr, -1)

	foundMaps := []string{}

	// Check each JS file for .map
	for _, match := range jsFiles {
		if len(match) < 2 {
			continue
		}
		jsPath := match[1]
		mapPath := jsPath + ".map"

		if s.checkMapFile(mapPath) {
			foundMaps = append(foundMaps, mapPath)
		}

		if len(foundMaps) >= 5 {
			break
		}
	}

	// Check each CSS file for .map
	for _, match := range cssFiles {
		if len(match) < 2 {
			continue
		}
		cssPath := match[1]
		mapPath := cssPath + ".map"

		if s.checkMapFile(mapPath) {
			foundMaps = append(foundMaps, mapPath)
		}

		if len(foundMaps) >= 5 {
			break
		}
	}

	if len(foundMaps) > 0 {
		s.addFinding(Finding{

			Severity:    "High",
			Category:    "Source Maps",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Source map files exposed (%d found)", len(foundMaps)),
			Remediation: "Remove .map files from production; disable source maps in build config; add server rule to block .map requests",
			Evidence:    strings.Join(foundMaps[:min(3, len(foundMaps))], ", "),
			HTTPMethod:  "GET",
			Outcome:     "Exposed",
		})
	} else {
		s.addFinding(Finding{

			Severity:    "Info",
			Category:    "Source Maps",
			Confidence:  "High",
			Finding:     "No source map files detected",
			Remediation: "Continue blocking source maps in production",
			Evidence:    "No .map files found",
			HTTPMethod:  "GET",
			Outcome:     "Protected",
		})
	}

	fmt.Printf("[ActiveScanner] Source map check complete: %d findings\n", len(s.findings))
}

// checkMapFile checks if a .map file is accessible
func (s *ActiveScanner) checkMapFile(path string) bool {
	// Make path relative if needed
	if !strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "http") {
		path = "/" + path
	}

	resp, err := s.makeRequest("HEAD", path, nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
