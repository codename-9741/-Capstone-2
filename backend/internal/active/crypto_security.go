package active

import (
	"crypto/tls"
	"net/url"
	"strings"
	"time"
)

func (s *ActiveScanner) checkWeakCiphers() {
	if !s.config.ShouldRunModule("weak_ciphers") {
		return
	}

	s.log("Checking for weak cipher suites...")

	// This is partially covered in tls.go, but adding more specific checks
	parsedURL, err := url.Parse(s.target)
	if err != nil {
		return
	}
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return
	}

	timeout := time.Duration(s.config.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	conn, err := dialTLSWithTimeout(hostname+":443", &tls.Config{InsecureSkipVerify: true}, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)

	// Check for weak ciphers
	weakCiphers := []string{
		"RC4",
		"DES",
		"3DES",
		"MD5",
		"EXPORT",
		"NULL",
		"anon",
	}

	for _, weak := range weakCiphers {
		if strings.Contains(cipherSuite, weak) {
			s.addFinding(Finding{
				Severity:    "High",
				Category:    "Weak Cipher",
				Confidence:  "High",
				Finding:     "Weak cipher suite in use: " + cipherSuite,
				Remediation: "Disable weak ciphers; use AES-GCM or ChaCha20-Poly1305; prefer ECDHE for forward secrecy",
				Evidence:    cipherSuite,
				HTTPMethod:  "TLS",
				Outcome:     "Weak cipher detected",
			})
			break
		}
	}
}

func (s *ActiveScanner) checkSSLv3() {
	if !s.config.ShouldRunModule("sslv3") {
		return
	}

	s.log("Checking for SSLv3 support...")

	// Try to connect with SSLv3
	parsedURL, err := url.Parse(s.target)
	if err != nil {
		return
	}
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return
	}

	timeout := time.Duration(s.config.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	conn, err := dialTLSWithTimeout(hostname+":443", &tls.Config{
		MaxVersion:         tls.VersionSSL30,
		InsecureSkipVerify: true,
	}, timeout)

	if err == nil {
		conn.Close()
		s.addFinding(Finding{
			Severity:    "Critical",
			Category:    "SSLv3",
			Confidence:  "High",
			Finding:     "SSLv3 is supported (POODLE attack vulnerable)",
			Remediation: "Disable SSLv3; require TLS 1.2 minimum (prefer TLS 1.3)",
			Evidence:    "SSLv3 connection successful",
			HTTPMethod:  "TLS",
			Outcome:     "Vulnerable",
		})
	}
}

func (s *ActiveScanner) checkInsecureRenegotiation() {
	if !s.config.ShouldRunModule("tls_renegotiation") {
		return
	}

	s.log("Checking TLS renegotiation...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "TLS Renegotiation",
		Confidence:  "Low",
		Finding:     "TLS renegotiation requires specialized tools (testssl.sh, sslyze)",
		Remediation: "Disable insecure renegotiation; use RFC 5746 secure renegotiation",
		Evidence:    "Requires advanced testing",
		HTTPMethod:  "TLS",
		Outcome:     "Manual testing required",
	})
}

func (s *ActiveScanner) checkRandomnessQuality() {
	if !s.config.ShouldRunModule("randomness") {
		return
	}

	s.log("Checking randomness quality...")

	// Check for predictable tokens in session IDs or CSRFs
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	sessionID := s.extractSessionID(resp)
	if sessionID != "" && len(sessionID) < 16 {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Weak Randomness",
			Confidence:  "Medium",
			Finding:     "Session ID appears short (< 16 chars), may have weak entropy",
			Remediation: "Use cryptographically secure random number generators; session IDs should be 128+ bits",
			Evidence:    "Short session ID detected",
			HTTPMethod:  "GET",
			Outcome:     "Weak entropy suspected",
		})
	}
}

func (s *ActiveScanner) checkEncryptionAtRest() {
	if !s.config.ShouldRunModule("encryption_at_rest") {
		return
	}

	s.log("Checking encryption at rest indicators...")

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Encryption at Rest",
		Confidence:  "Low",
		Finding:     "Encryption at rest requires backend/database access for verification",
		Remediation: "Encrypt sensitive data at rest: use AES-256, encrypt database columns, encrypt file storage",
		Evidence:    "Requires backend access",
		HTTPMethod:  "N/A",
		Outcome:     "Cannot verify remotely",
	})
}
