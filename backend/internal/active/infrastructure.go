package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkLoadBalancer() {
	if !s.config.ShouldRunModule("load_balancer") {
		return
	}

	s.log("Detecting load balancer...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	// Check for load balancer headers
	lbHeaders := map[string]string{
		"X-Forwarded-For":  "Proxy/LB detected",
		"X-Real-IP":        "Proxy detected",
		"X-Load-Balancer":  "Load balancer",
		"X-Backend-Server": "Backend routing",
		"X-Served-By":      "CDN/LB",
	}

	for header, description := range lbHeaders {
		if val := resp.Header.Get(header); val != "" {
			s.addFinding(Finding{
				Severity:    "Info",
				Category:    "Load Balancer",
				Confidence:  "High",
				Finding:     fmt.Sprintf("%s: %s", description, header),
				Remediation: "Ensure load balancer passes client IP; configure health checks; use sticky sessions if needed",
				Evidence:    fmt.Sprintf("%s: %s", header, val),
				HTTPMethod:  "GET",
				Outcome:     "Detected",
			})
		}
	}
}

func (s *ActiveScanner) checkCDNBypass() {
	if !s.config.ShouldRunModule("cdn_bypass") {
		return
	}

	s.log("Checking for CDN bypass opportunities...")

	// Check for origin server disclosure
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Look for origin server IPs
	if strings.Contains(body, "origin") || strings.Contains(resp.Header.Get("Server"), "origin") {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "CDN Bypass",
			Confidence:  "Low",
			Finding:     "Potential origin server disclosure (CDN bypass risk)",
			Remediation: "Hide origin server IP; implement origin authentication; use firewall rules to allow only CDN IPs",
			Evidence:    "Origin indicators detected",
			HTTPMethod:  "GET",
			Outcome:     "Potential bypass",
		})
	}
}

func (s *ActiveScanner) checkDNSSEC() {
	if !s.config.ShouldRunModule("dnssec") {
		return
	}

	s.log("Checking DNSSEC...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "DNSSEC",
		Confidence:  "Low",
		Finding:     "DNSSEC validation requires DNS query tools (dig +dnssec)",
		Remediation: "Enable DNSSEC on domain; sign DNS records; ensure DNSSEC validation on resolvers",
		Evidence:    "Requires DNS testing",
		HTTPMethod:  "N/A",
		Outcome:     "Manual verification required",
	})
}

func (s *ActiveScanner) checkSubresourceIntegrity() {
	if !s.config.ShouldRunModule("sri") {
		return
	}

	s.log("Checking Subresource Integrity...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Check for external scripts without SRI
	hasExternalScripts := strings.Contains(body, "<script src=\"http") ||
		strings.Contains(body, "<link rel=\"stylesheet\" href=\"http")

	hasSRI := strings.Contains(body, "integrity=") && strings.Contains(body, "sha")

	if hasExternalScripts && !hasSRI {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Subresource Integrity",
			Confidence:  "Medium",
			Finding:     "External resources loaded without Subresource Integrity (SRI)",
			Remediation: "Add integrity and crossorigin attributes to external scripts/stylesheets; generate SRI hashes",
			Evidence:    "External resources without SRI detected",
			HTTPMethod:  "GET",
			Outcome:     "Missing SRI",
		})
	}
}

func (s *ActiveScanner) checkSecurityMonitoring() {
	if !s.config.ShouldRunModule("security_monitoring") {
		return
	}

	s.log("Checking security monitoring indicators...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Security Monitoring",
		Confidence:  "Low",
		Finding:     "Security monitoring requires verification of logging, SIEM, IDS/IPS, and alerting systems",
		Remediation: "Implement: centralized logging, SIEM integration, anomaly detection, incident response playbooks, 24/7 monitoring",
		Evidence:    "Requires infrastructure review",
		HTTPMethod:  "N/A",
		Outcome:     "Manual verification required",
	})
}
