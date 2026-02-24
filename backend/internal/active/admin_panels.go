package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkAdminPanels() {
	if !s.config.ShouldRunModule("admin_panels") {
		return
	}

	s.log("Checking for admin panels...")

	adminPaths := []string{
		"/admin",
		"/administrator",
		"/admin.php",
		"/wp-admin",
		"/admin/login",
		"/adminpanel",
		"/controlpanel",
		"/admin/index.php",
		"/admin/dashboard",
		"/backend",
		"/cms",
		"/management",
		"/moderator",
		"/webadmin",
	}

	foundPanels := []string{}

	for _, path := range adminPaths {
		url := s.target + path
		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := s.readBody(resp)

			// Check for admin indicators
			adminIndicators := []string{
				"login",
				"username",
				"password",
				"admin",
				"dashboard",
				"control panel",
			}

			bodyLower := strings.ToLower(body)
			isAdmin := false
			for _, indicator := range adminIndicators {
				if strings.Contains(bodyLower, indicator) {
					isAdmin = true
					break
				}
			}

			if isAdmin {
				foundPanels = append(foundPanels, path)
			}
		} else {
			resp.Body.Close()
		}
	}

	if len(foundPanels) > 0 {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Admin Panel",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Admin panels discovered: %v", foundPanels),
			Remediation: "Implement: strong authentication, IP whitelisting, rename default paths, enable rate limiting, use CAPTCHA",
			Evidence:    strings.Join(foundPanels, ", "),
			HTTPMethod:  "GET",
			Outcome:     "Accessible",
		})
	}
}
