package active

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func dialTLSWithTimeout(hostport string, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", hostport)
	if err != nil {
		return nil, err
	}
	// Ensure the TLS handshake can't hang forever.
	_ = raw.SetDeadline(time.Now().Add(timeout))

	c := tls.Client(raw, cfg)
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	// Clear deadline for callers that may read state/certs.
	_ = raw.SetDeadline(time.Time{})
	return c, nil
}

// checkTLS analyzes TLS/SSL configuration
func (s *ActiveScanner) checkTLS() {
	fmt.Println("[ActiveScanner] Checking TLS/SSL configuration...")

	parsedURL, err := url.Parse(s.target)
	if err != nil {
		return
	}

	// Only check HTTPS targets
	if parsedURL.Scheme != "https" {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "TLS",
			Confidence:  "High",
			Finding:     "Target is not using HTTPS",
			Remediation: "Enable HTTPS with valid TLS certificate and enforce HSTS",
			Evidence:    "Scheme is HTTP",
			HTTPMethod:  "N/A",
			Outcome:     "HTTP",
		})
		return
	}

	// Extract hostname
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return
	}

	// Connect with TLS
	timeout := time.Duration(s.config.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn, err := dialTLSWithTimeout(hostname+":443", &tls.Config{
		InsecureSkipVerify: false, // Validate certificate
	}, timeout)
	if err != nil {
		// Check if it's a certificate error
		if strings.Contains(err.Error(), "certificate") {
			s.addFinding(Finding{
				Severity:    "High",
				Category:    "TLS",
				Confidence:  "High",
				Finding:     "TLS certificate validation failed",
				Remediation: "Install valid certificate from trusted CA",
				Evidence:    err.Error(),
				HTTPMethod:  "TLS",
				Outcome:     "Invalid",
			})
		}
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Check TLS version
	tlsVersion := getTLSVersionString(state.Version)
	if state.Version < tls.VersionTLS12 {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "TLS",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Weak TLS version in use: %s", tlsVersion),
			Remediation: "Require TLS 1.2+ (prefer TLS 1.3)",
			Evidence:    tlsVersion,
			HTTPMethod:  "TLS",
			Outcome:     "Weak",
		})
	} else {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "TLS",
			Confidence:  "High",
			Finding:     fmt.Sprintf("TLS version: %s", tlsVersion),
			Remediation: "Continue using TLS 1.2+",
			Evidence:    tlsVersion,
			HTTPMethod:  "TLS",
			Outcome:     "Secure",
		})
	}

	// Check certificate expiry
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

		if daysLeft <= 0 {
			s.addFinding(Finding{
				Severity:    "Critical",
				Category:    "TLS",
				Confidence:  "High",
				Finding:     "TLS certificate has expired",
				Remediation: "Renew certificate immediately",
				Evidence:    fmt.Sprintf("Expired: %s", cert.NotAfter),
				HTTPMethod:  "TLS",
				Outcome:     "Expired",
			})
		} else if daysLeft <= 30 {
			s.addFinding(Finding{
				Severity:    "High",
				Category:    "TLS",
				Confidence:  "High",
				Finding:     fmt.Sprintf("Certificate expires soon: %d days left", daysLeft),
				Remediation: "Renew certificate before expiry",
				Evidence:    fmt.Sprintf("Expires: %s", cert.NotAfter),
				HTTPMethod:  "TLS",
				Outcome:     "Expiring",
			})
		}

		// Check certificate subject
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "TLS",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Certificate subject: %s", cert.Subject.CommonName),
			Remediation: "Verify certificate matches domain",
			Evidence:    getCertInfo(cert),
			HTTPMethod:  "TLS",
			Outcome:     "Valid",
		})
	}

	fmt.Printf("[ActiveScanner] TLS check complete: %d findings\n", len(s.findings))
}

// getTLSVersionString converts TLS version constant to string
func getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

// getCertInfo returns formatted certificate information
func getCertInfo(cert *x509.Certificate) string {
	return fmt.Sprintf("Subject: %s | Issuer: %s | Valid: %s - %s",
		cert.Subject.CommonName,
		cert.Issuer.CommonName,
		cert.NotBefore.Format("2006-01-02"),
		cert.NotAfter.Format("2006-01-02"),
	)
}
