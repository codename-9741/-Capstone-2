package active

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// checkFingerprinting performs deep technology stack detection
func (s *ActiveScanner) checkFingerprinting() {
	fmt.Println("[ActiveScanner] Performing technology fingerprinting...")

	resp, err := s.makeRequest("GET", "/", nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	headers := resp.Header
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	techs := []string{}

	// Server header
	server := headers.Get("Server")
	if server != "" {
		techs = append(techs, fmt.Sprintf("Server: %s", server))
	}

	// X-Powered-By
	xpb := headers.Get("X-Powered-By")
	if xpb != "" {
		techs = append(techs, fmt.Sprintf("Framework: %s", xpb))
	}

	// CMS Detection
	cms := detectCMS(bodyStr, headers)
	if cms != "" {
		techs = append(techs, fmt.Sprintf("CMS: %s", cms))
	}

	// JavaScript frameworks
	frameworks := detectJSFrameworks(bodyStr)
	for _, fw := range frameworks {
		techs = append(techs, fmt.Sprintf("JS Framework: %s", fw))
	}

	// CDN Detection
	cdn := detectCDN(headers)
	if cdn != "" {
		techs = append(techs, fmt.Sprintf("CDN: %s", cdn))
	}

	if len(techs) > 0 {
		s.addFinding(Finding{

			Severity:    "Info",
			Category:    "Technology Stack",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Technology stack detected (%d components)", len(techs)),
			Remediation: "Review exposed technology versions; remove version disclosure headers; keep all software updated",
			Evidence:    strings.Join(techs, " | "),
			HTTPMethod:  "GET",
			Outcome:     "Detected",
		})
	}

	fmt.Printf("[ActiveScanner] Fingerprinting complete: %d findings\n", len(s.findings))
}

// detectCMS detects Content Management System
func detectCMS(body string, headers http.Header) string {
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wordpress") {
		versionRegex := regexp.MustCompile(`generator.*?wordpress\s+([\d.]+)`)
		if match := versionRegex.FindStringSubmatch(bodyLower); len(match) > 1 {
			return fmt.Sprintf("WordPress %s", match[1])
		}
		return "WordPress"
	}

	if strings.Contains(bodyLower, "joomla") {
		return "Joomla"
	}

	if strings.Contains(bodyLower, "drupal") {
		versionRegex := regexp.MustCompile(`drupal\s+([\d.]+)`)
		if match := versionRegex.FindStringSubmatch(bodyLower); len(match) > 1 {
			return fmt.Sprintf("Drupal %s", match[1])
		}
		return "Drupal"
	}

	if strings.Contains(bodyLower, "shopify") {
		return "Shopify"
	}

	if strings.Contains(bodyLower, "wix.com") {
		return "Wix"
	}

	return ""
}

// detectJSFrameworks detects JavaScript frameworks
func detectJSFrameworks(body string) []string {
	frameworks := []string{}
	bodyLower := strings.ToLower(body)

	if strings.Contains(bodyLower, "react") || regexp.MustCompile(`/__reactcontainer`).MatchString(bodyLower) {
		frameworks = append(frameworks, "React")
	}

	if strings.Contains(bodyLower, "vue") || regexp.MustCompile(`data-v-[\da-f]{8}`).MatchString(bodyLower) {
		frameworks = append(frameworks, "Vue.js")
	}

	if strings.Contains(bodyLower, "angular") || strings.Contains(bodyLower, "ng-") {
		frameworks = append(frameworks, "Angular")
	}

	if strings.Contains(bodyLower, "jquery") {
		versionRegex := regexp.MustCompile(`jquery[/-]([\d.]+)`)
		if match := versionRegex.FindStringSubmatch(bodyLower); len(match) > 1 {
			frameworks = append(frameworks, fmt.Sprintf("jQuery %s", match[1]))
		} else {
			frameworks = append(frameworks, "jQuery")
		}
	}

	return frameworks
}

// detectCDN detects Content Delivery Network
func detectCDN(headers http.Header) string {
	if headers.Get("CF-RAY") != "" {
		return "Cloudflare"
	}

	if strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare") {
		return "Cloudflare"
	}

	if strings.Contains(strings.ToLower(headers.Get("X-Amz-Cf-Id")), "cloudfront") || headers.Get("X-Amz-Cf-Id") != "" {
		return "Amazon CloudFront"
	}

	if strings.Contains(strings.ToLower(headers.Get("Server")), "akamai") {
		return "Akamai"
	}

	if headers.Get("X-CDN") != "" {
		return headers.Get("X-CDN")
	}

	return ""
}
