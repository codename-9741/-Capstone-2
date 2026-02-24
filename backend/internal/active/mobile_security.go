package active

import (
	"strings"
)

func (s *ActiveScanner) checkMobileAppLinks() {
	if !s.config.ShouldRunModule("mobile_app_links") {
		return
	}

	s.log("Checking for mobile app deep links...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check for deep link schemes
	mobileSchemes := []string{
		"intent://",
		"market://",
		"app://",
		"myapp://",
		"android-app://",
		"ios-app://",
	}

	for _, scheme := range mobileSchemes {
		if strings.Contains(body, scheme) {
			s.addFinding(Finding{
				Severity:    "Medium",
				Category:    "Mobile App Links",
				Confidence:  "Medium",
				Finding:     "Mobile app deep links detected (validate URL schemes to prevent hijacking)",
				Remediation: "Validate deep link URLs; implement App Links (Android) or Universal Links (iOS); verify domain ownership",
				Evidence:    "Deep link scheme detected",
				HTTPMethod:  "GET",
				Outcome:     "Deep links found",
			})
			break
		}
	}
}

func (s *ActiveScanner) checkAppConfiguration() {
	if !s.config.ShouldRunModule("app_config") {
		return
	}

	s.log("Checking for exposed app configuration...")

	configPaths := []string{
		"/app-ads.txt",
		"/.well-known/assetlinks.json",
		"/.well-known/apple-app-site-association",
		"/manifest.json",
		"/app.config",
	}

	for _, path := range configPaths {
		url := s.target + path
		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			s.addFinding(Finding{
				Severity:    "Info",
				Category:    "App Configuration",
				Confidence:  "High",
				Finding:     "App configuration file accessible: " + path,
				Remediation: "Review configuration for sensitive data; ensure proper permissions",
				Evidence:    "Config file found",
				HTTPMethod:  "GET",
				Outcome:     "Accessible",
			})
		}
	}
}

func (s *ActiveScanner) checkCertificatePinning() {
	if !s.config.ShouldRunModule("cert_pinning") {
		return
	}

	s.log("Checking certificate pinning indicators...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Certificate Pinning",
		Confidence:  "Low",
		Finding:     "Certificate pinning requires mobile app analysis (static/dynamic)",
		Remediation: "Implement certificate pinning in mobile apps; use public key pinning; include backup pins",
		Evidence:    "Requires mobile app testing",
		HTTPMethod:  "N/A",
		Outcome:     "Manual testing required",
	})
}

func (s *ActiveScanner) checkRootDetection() {
	if !s.config.ShouldRunModule("root_detection") {
		return
	}

	s.log("Checking root/jailbreak detection...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Root Detection",
		Confidence:  "Low",
		Finding:     "Root/jailbreak detection requires mobile app analysis",
		Remediation: "Implement root/jailbreak detection in mobile apps; use SafetyNet (Android) or jailbreak detection libraries",
		Evidence:    "Requires mobile app testing",
		HTTPMethod:  "N/A",
		Outcome:     "Manual testing required",
	})
}

func (s *ActiveScanner) checkAppHardening() {
	if !s.config.ShouldRunModule("app_hardening") {
		return
	}

	s.log("Checking app hardening measures...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "App Hardening",
		Confidence:  "Low",
		Finding:     "App hardening (obfuscation, anti-debugging, tamper detection) requires binary analysis",
		Remediation: "Implement: code obfuscation, anti-debugging, tamper detection, string encryption",
		Evidence:    "Requires APK/IPA analysis",
		HTTPMethod:  "N/A",
		Outcome:     "Manual testing required",
	})
}
