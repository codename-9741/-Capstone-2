package active

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// GenerateCorrelationID creates a deterministic hash for cross-tool finding deduplication.
// Findings with the same correlation ID are considered the same vulnerability found by different tools.
func GenerateCorrelationID(category, findingText, target string) string {
	normalized := strings.ToLower(strings.TrimSpace(category)) + "|" +
		normalizeFindingText(strings.ToLower(strings.TrimSpace(findingText))) + "|" +
		strings.ToLower(strings.TrimSpace(target))

	hash := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%x", hash[:16]) // 32 hex chars
}

// normalizeFindingText strips tool-specific prefixes and variations to improve matching.
func normalizeFindingText(text string) string {
	// Remove common tool prefixes
	prefixes := []string{
		"external nmap ",
		"external nikto ",
		"external nuclei ",
		"external adapter ",
		"nmap-compatible ",
		"heuristic ",
	}
	for _, prefix := range prefixes {
		text = strings.TrimPrefix(text, prefix)
	}

	// Normalize whitespace
	fields := strings.Fields(text)
	return strings.Join(fields, " ")
}
