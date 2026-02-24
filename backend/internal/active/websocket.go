package active

import (
	"fmt"
	"io"
	"regexp"
)

// detectWebSockets checks for WebSocket references
func (s *ActiveScanner) detectWebSockets() {
	fmt.Println("[ActiveScanner] Detecting WebSocket references...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	bodyStr := string(body)

	// Find ws:// and wss:// URLs
	wsRegex := regexp.MustCompile(`\bwss?://[^\s"'<>]+`)
	matches := wsRegex.FindAllString(bodyStr, -1)

	// Deduplicate
	seen := make(map[string]bool)
	unique := []string{}
	for _, match := range matches {
		if !seen[match] && len(unique) < 10 {
			seen[match] = true
			unique = append(unique, match)
		}
	}

	if len(unique) > 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "WebSocket",
			Confidence:  "Medium",
			Finding:     fmt.Sprintf("WebSocket references detected (ws/wss): %d", len(unique)),
			Remediation: "Enforce WSS only, authenticate socket handshake, validate Origin, apply message rate limits",
			Evidence:    fmt.Sprintf("%v", unique[:min(3, len(unique))]),
			HTTPMethod:  "GET",
			Outcome:     "Detected",
		})
	} else {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "WebSocket",
			Confidence:  "High",
			Finding:     "No WebSocket references detected in initial HTML (best-effort)",
			Remediation: "If used dynamically, ensure WSS + auth + origin checks + monitoring",
			Evidence:    "No refs found",
			HTTPMethod:  "GET",
			Outcome:     "None",
		})
	}

	fmt.Printf("[ActiveScanner] WebSocket detection complete: %d findings\n", len(s.findings))
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
