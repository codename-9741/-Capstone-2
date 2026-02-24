package active

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

func (s *ActiveScanner) checkNmapTopPorts() {
	if output, ok := s.tryExternalModule("nmap_top1000"); ok {
		s.processNmapTopPortsOutput(output)
		return
	}

	host := s.targetHostname()
	if host == "" {
		return
	}

	ports := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5000, 5432, 5900, 6379, 8080, 8443, 9200, 9300, 11211, 27017}
	openPorts := s.scanTCPPorts(host, ports, 800*time.Millisecond)
	if len(openPorts) == 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Nmap-Compatible Port Scan",
			Confidence:  "Medium",
			Finding:     "No open ports detected in aggressive baseline set",
			Remediation: "Keep perimeter exposure minimal",
			Evidence:    "No responsive TCP ports in aggressive baseline",
			HTTPMethod:  "TCP Connect",
			Outcome:     "No Open Ports",
		})
		return
	}

	riskPorts := map[int]string{23: "Telnet", 445: "SMB", 3389: "RDP", 2375: "Docker API", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
	risky := []string{}
	for _, p := range openPorts {
		if svc, ok := riskPorts[p]; ok {
			risky = append(risky, fmt.Sprintf("%d (%s)", p, svc))
		}
	}

	if len(risky) > 0 {
		sort.Strings(risky)
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Nmap-Compatible Port Scan",
			Confidence:  "High",
			Finding:     "High-risk network services exposed",
			Remediation: "Restrict high-risk ports with firewall allowlists and segmentation",
			Evidence:    strings.Join(risky, ", "),
			HTTPMethod:  "TCP Connect",
			Outcome:     "Risky Ports Exposed",
		})
	}

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Nmap-Compatible Port Scan",
		Confidence:  "High",
		Finding:     fmt.Sprintf("Aggressive network sweep found %d open ports", len(openPorts)),
		Remediation: "Audit external services and close non-essential exposure",
		Evidence:    intsToCSV(openPorts),
		HTTPMethod:  "TCP Connect",
		Outcome:     "Open Ports Found",
	})
}

func (s *ActiveScanner) checkNmapServiceDetection() {
	if output, ok := s.tryExternalModule("nmap_service_detection"); ok {
		s.processNmapServiceDetectionOutput(output)
		return
	}

	host := s.targetHostname()
	if host == "" {
		return
	}

	ports := []int{21, 22, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 9200}
	openPorts := s.scanTCPPorts(host, ports, 900*time.Millisecond)
	if len(openPorts) == 0 {
		return
	}

	banners := []string{}
	for _, p := range openPorts {
		if banner := s.grabServiceBanner(host, p); banner != "" {
			banners = append(banners, fmt.Sprintf("%d: %s", p, banner))
		}
	}
	if len(banners) > 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Nmap-Compatible Service Detection",
			Confidence:  "Medium",
			Finding:     fmt.Sprintf("Service banners collected from %d ports", len(banners)),
			Remediation: "Reduce banner disclosure and keep services patched",
			Evidence:    limitList(banners, 8),
			HTTPMethod:  "TCP Banner Grab",
			Outcome:     "Service Fingerprinted",
		})
	}

	outdatedHints := []string{"openssh_5", "openssh_6", "apache/2.2", "php/5", "openssl/1.0", "iis/6.0"}
	hits := []string{}
	for _, b := range banners {
		lower := strings.ToLower(b)
		for _, h := range outdatedHints {
			if strings.Contains(lower, h) {
				hits = append(hits, b)
				break
			}
		}
	}
	if len(hits) > 0 {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Nmap-Compatible Service Detection",
			Confidence:  "Medium",
			Finding:     "Potentially outdated service versions detected in banners",
			Remediation: "Validate service versions and upgrade unsupported software",
			Evidence:    limitList(hits, 6),
			HTTPMethod:  "TCP Banner Grab",
			Outcome:     "Outdated Version Hints",
		})
	}
}

func (s *ActiveScanner) checkNmapVulnScripts() {
	if output, ok := s.tryExternalModule("nmap_vuln_scripts"); ok {
		s.processNmapVulnOutput(output)
		return
	}

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	headers := strings.ToLower(fmt.Sprintf("%v", resp.Header))
	server := strings.ToLower(resp.Header.Get("Server"))
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

	hints := []string{}
	if strings.Contains(server, "apache/2.2") || strings.Contains(server, "nginx/1.1") || strings.Contains(poweredBy, "php/5") {
		hints = append(hints, "legacy web stack version exposure")
	}
	if strings.Contains(headers, "trace") || strings.Contains(headers, "server") {
		hints = append(hints, "verbose header disclosure")
	}

	if len(hints) > 0 {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Nmap-Compatible Vulnerability Scripts",
			Confidence:  "Low",
			Finding:     "Heuristic vulnerability indicators detected",
			Remediation: "Run authenticated vulnerability validation and patch vulnerable components",
			Evidence:    strings.Join(unique(hints), ", "),
			HTTPMethod:  "Heuristic",
			Outcome:     "Potential Vuln Indicators",
		})
	} else {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Nmap-Compatible Vulnerability Scripts",
			Confidence:  "Low",
			Finding:     "No immediate heuristic vulnerability indicators detected",
			Remediation: "Continue with deeper authenticated testing",
			Evidence:    "No weak-version keywords found in headers",
			HTTPMethod:  "Heuristic",
			Outcome:     "No Immediate Indicators",
		})
	}
}

func (s *ActiveScanner) checkNmapUDPTopPorts() {
	if output, ok := s.tryExternalModule("nmap_udp_top"); ok {
		s.processNmapUDPOutput(output)
		return
	}

	host := s.targetHostname()
	if host == "" {
		return
	}

	udpPorts := []int{53, 67, 68, 69, 123, 137, 138, 161, 500, 514, 1900, 5353}
	responsive := []string{}
	for _, p := range udpPorts {
		conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, p), 800*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
		_, _ = conn.Write([]byte("\x00"))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		_ = conn.Close()
		if err == nil && n > 0 {
			responsive = append(responsive, fmt.Sprintf("%d", p))
		}
	}

	if len(responsive) > 0 {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Nmap-Compatible UDP Scan",
			Confidence:  "Low",
			Finding:     "UDP services responded to probes",
			Remediation: "Restrict UDP services and validate they are internet-exposed by design",
			Evidence:    strings.Join(responsive, ", "),
			HTTPMethod:  "UDP Probe",
			Outcome:     "UDP Responsive",
		})
	}
}

func (s *ActiveScanner) checkNmapTLSCiphers() {
	if output, ok := s.tryExternalModule("nmap_tls_ciphers"); ok {
		s.processNmapTLSOutput(output)
		return
	}

	host := s.targetHostname()
	if host == "" {
		return
	}

	legacy := []string{}
	checks := []struct {
		id   uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
	}

	for _, c := range checks {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", host+":443", &tls.Config{
			MinVersion:         c.id,
			MaxVersion:         c.id,
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err == nil {
			legacy = append(legacy, c.name)
			_ = conn.Close()
		}
	}

	if len(legacy) > 0 {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Nmap-Compatible TLS Cipher Check",
			Confidence:  "High",
			Finding:     "Legacy TLS protocols are enabled",
			Remediation: "Disable TLS 1.0/1.1 and enforce TLS 1.2+",
			Evidence:    strings.Join(legacy, ", "),
			HTTPMethod:  "TLS Handshake",
			Outcome:     "Weak TLS Supported",
		})
	}
}

func (s *ActiveScanner) checkNmapFirewallEvasion() {
	if output, ok := s.tryExternalModule("nmap_firewall_bypass"); ok {
		s.processNmapFirewallOutput(output)
		return
	}

	host := s.targetHostname()
	if host == "" {
		return
	}

	ports := []int{22, 80, 443, 3389, 8080}
	fast := s.scanTCPPorts(host, ports, 250*time.Millisecond)
	slow := s.scanTCPPorts(host, ports, 1200*time.Millisecond)
	if len(slow) > len(fast)+1 {
		s.addFinding(Finding{
			Severity:    "Low",
			Category:    "Nmap-Compatible Firewall Evasion",
			Confidence:  "Low",
			Finding:     "Inconsistent port responsiveness under timing variance",
			Remediation: "Validate firewall/IDS behavior across timing and fragmented traffic profiles",
			Evidence:    fmt.Sprintf("fast=%s slow=%s", intsToCSV(fast), intsToCSV(slow)),
			HTTPMethod:  "Timing Differential",
			Outcome:     "Behavior Variance",
		})
	}
}

func (s *ActiveScanner) processNmapTopPortsOutput(output string) {
	open := regexp.MustCompile(`(?m)^(\d+)/tcp\s+open\s+([^\s]+)`).FindAllStringSubmatch(output, -1)
	if len(open) == 0 {
		return
	}
	ports := []string{}
	for _, m := range open {
		ports = append(ports, fmt.Sprintf("%s/%s", m[1], m[2]))
	}
	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Nmap External",
		Confidence:  "High",
		Finding:     fmt.Sprintf("External nmap top-port scan found %d open services", len(ports)),
		Remediation: "Review and close unnecessary services",
		Evidence:    limitList(ports, 15),
		HTTPMethod:  "Nmap External",
		Outcome:     "Open Ports Found",
	})
}

func (s *ActiveScanner) processNmapServiceDetectionOutput(output string) {
	lines := regexp.MustCompile(`(?m)^\d+/tcp\s+open\s+.+$`).FindAllString(output, -1)
	if len(lines) == 0 {
		return
	}
	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Nmap External",
		Confidence:  "High",
		Finding:     fmt.Sprintf("External service detection identified %d services", len(lines)),
		Remediation: "Patch identified service versions and reduce banner disclosure",
		Evidence:    limitList(lines, 8),
		HTTPMethod:  "Nmap External",
		Outcome:     "Services Identified",
	})
}

func (s *ActiveScanner) processNmapVulnOutput(output string) {
	vulnMarkers := regexp.MustCompile(`(?im)VULNERABLE|CVE-\d{4}-\d+`).FindAllString(output, -1)
	if len(vulnMarkers) == 0 {
		return
	}
	s.addFinding(Finding{
		Severity:    "High",
		Category:    "Nmap External",
		Confidence:  "Medium",
		Finding:     "External nmap vuln script output reported vulnerability markers",
		Remediation: "Validate and patch all confirmed vulnerabilities",
		Evidence:    fmt.Sprintf("markers=%d", len(vulnMarkers)),
		HTTPMethod:  "Nmap External",
		Outcome:     "Potential Vulnerabilities",
	})
}

func (s *ActiveScanner) processNmapUDPOutput(output string) {
	udp := regexp.MustCompile(`(?m)^(\d+)/udp\s+(open|open\|filtered)\s+([^\s]+)`).FindAllStringSubmatch(output, -1)
	if len(udp) == 0 {
		return
	}
	ports := []string{}
	for _, m := range udp {
		ports = append(ports, fmt.Sprintf("%s/%s", m[1], m[3]))
	}
	s.addFinding(Finding{
		Severity:    "Medium",
		Category:    "Nmap External",
		Confidence:  "Medium",
		Finding:     fmt.Sprintf("External UDP scan found %d responsive services", len(ports)),
		Remediation: "Restrict UDP exposure and monitor for abuse",
		Evidence:    limitList(ports, 10),
		HTTPMethod:  "Nmap External",
		Outcome:     "UDP Exposure",
	})
}

func (s *ActiveScanner) processNmapTLSOutput(output string) {
	lower := strings.ToLower(output)
	weakHints := []string{"3des", "rc4", "md5", "export", "des-cbc", "tlsv1.0", "tlsv1.1"}
	matches := []string{}
	for _, hint := range weakHints {
		if strings.Contains(lower, hint) {
			matches = append(matches, hint)
		}
	}
	if len(matches) == 0 {
		return
	}
	s.addFinding(Finding{
		Severity:    "High",
		Category:    "Nmap External",
		Confidence:  "Medium",
		Finding:     "External TLS cipher scan detected weak crypto indicators",
		Remediation: "Disable weak protocols/ciphers and enforce modern TLS baseline",
		Evidence:    strings.Join(unique(matches), ", "),
		HTTPMethod:  "Nmap External",
		Outcome:     "Weak TLS Indicators",
	})
}

func (s *ActiveScanner) processNmapFirewallOutput(output string) {
	open := regexp.MustCompile(`(?m)^\d+/tcp\s+open\s+`).FindAllString(output, -1)
	if len(open) == 0 {
		return
	}
	s.addFinding(Finding{
		Severity:    "Low",
		Category:    "Nmap External",
		Confidence:  "Low",
		Finding:     "External firewall-evasion profile reported reachable services",
		Remediation: "Validate IDS/IPS behavior against evasive scanning techniques",
		Evidence:    fmt.Sprintf("open_ports=%d", len(open)),
		HTTPMethod:  "Nmap External",
		Outcome:     "Reachable",
	})
}

func (s *ActiveScanner) checkNetworkPortExposure() {
	host := s.targetHostname()
	if host == "" {
		return
	}

	ports := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 6379, 8080, 9200, 27017, 11211}
	dialer := net.Dialer{Timeout: 800 * time.Millisecond}
	openPorts := []string{}
	for _, p := range ports {
		conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, p))
		if err == nil {
			openPorts = append(openPorts, fmt.Sprintf("%d", p))
			_ = conn.Close()
		}
	}

	if len(openPorts) == 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Network Exposure",
			Confidence:  "Medium",
			Finding:     "No open ports detected in baseline exposure set",
			Remediation: "Keep inbound ports closed by default",
			Evidence:    "Baseline port sweep found no open services",
			HTTPMethod:  "TCP Dial",
			Outcome:     "No Baseline Exposure",
		})
		return
	}

	highRiskPorts := map[string]string{"23": "Telnet", "445": "SMB", "3389": "RDP", "2375": "Docker API", "6379": "Redis", "9200": "Elasticsearch", "27017": "MongoDB", "11211": "Memcached"}
	risky := []string{}
	for _, p := range openPorts {
		if name, ok := highRiskPorts[p]; ok {
			risky = append(risky, fmt.Sprintf("%s (%s)", p, name))
		}
	}

	sort.Strings(openPorts)
	if len(risky) > 0 {
		sort.Strings(risky)
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Network Exposure",
			Confidence:  "High",
			Finding:     "High-risk services exposed on common ports",
			Remediation: "Apply strict firewall controls and service-level authentication",
			Evidence:    strings.Join(risky, ", "),
			HTTPMethod:  "TCP Dial",
			Outcome:     "High-Risk Exposure",
		})
	}

	s.addFinding(Finding{
		Severity:    "Info",
		Category:    "Network Exposure",
		Confidence:  "High",
		Finding:     fmt.Sprintf("Baseline network exposure found %d open ports", len(openPorts)),
		Remediation: "Review and minimize external service footprint",
		Evidence:    limitList(openPorts, 20),
		HTTPMethod:  "TCP Dial",
		Outcome:     "Ports Exposed",
	})
}

func (s *ActiveScanner) checkTLSVersionMatrix() {
	host := s.targetHostname()
	if host == "" {
		return
	}

	versions := []struct {
		id   uint16
		name string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	supported := []string{}
	for _, v := range versions {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", host+":443", &tls.Config{
			MinVersion:         v.id,
			MaxVersion:         v.id,
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err == nil {
			supported = append(supported, v.name)
			_ = conn.Close()
		}
	}

	if len(supported) == 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "TLS Matrix",
			Confidence:  "Medium",
			Finding:     "TLS version matrix scan could not establish TLS handshakes",
			Remediation: "Verify HTTPS availability and certificate chain",
			Evidence:    "No TLS versions negotiated on :443",
			HTTPMethod:  "TLS Handshake",
			Outcome:     "No TLS",
		})
		return
	}

	if contains(supported, "TLS 1.0") || contains(supported, "TLS 1.1") {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "TLS Matrix",
			Confidence:  "High",
			Finding:     "Legacy TLS protocols are still supported",
			Remediation: "Disable TLS 1.0/1.1 and enforce TLS 1.2+",
			Evidence:    strings.Join(supported, ", "),
			HTTPMethod:  "TLS Handshake",
			Outcome:     "Legacy TLS Enabled",
		})
	} else {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "TLS Matrix",
			Confidence:  "High",
			Finding:     "TLS protocol support is limited to modern versions",
			Remediation: "Maintain strong TLS baseline",
			Evidence:    strings.Join(supported, ", "),
			HTTPMethod:  "TLS Handshake",
			Outcome:     "Modern TLS",
		})
	}
}

func (s *ActiveScanner) checkHTTPMethodOverride() {
	headers := map[string]string{
		"X-HTTP-Method-Override": "DELETE",
		"X-Method-Override":      "DELETE",
		"Content-Type":           "application/x-www-form-urlencoded",
	}
	resp, err := s.makeRequestWithHeaders("POST", s.target, strings.NewReader("id=1"), headers)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 400 {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "HTTP Method Override",
			Confidence:  "Medium",
			Finding:     "Method override headers accepted by endpoint",
			Remediation: "Disable unsafe method override behavior at gateway and app layers",
			Evidence:    fmt.Sprintf("POST + override returned status %d", resp.StatusCode),
			HTTPMethod:  "POST",
			Outcome:     "Override Accepted",
		})
	}
}

func (s *ActiveScanner) checkHostHeaderInjectionAdvanced() {
	marker := "attacker.example"
	resp, err := s.makeRequestWithHost("GET", s.target, marker, nil, map[string]string{
		"X-Forwarded-Host": marker,
		"X-Original-Host":  marker,
	})
	if err != nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	body := strings.ToLower(string(bodyBytes))
	location := strings.ToLower(resp.Header.Get("Location"))
	if strings.Contains(body, marker) || strings.Contains(location, marker) {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Host Header Injection",
			Confidence:  "Medium",
			Finding:     "Host header value reflected in response",
			Remediation: "Validate host headers against strict allowlist at reverse proxy/application",
			Evidence:    fmt.Sprintf("status=%d location=%s", resp.StatusCode, resp.Header.Get("Location")),
			HTTPMethod:  "GET",
			Outcome:     "Reflected",
		})
	}
}

func (s *ActiveScanner) checkOpenRedirectAdvanced() {
	payload := "https://attacker.example"
	paths := []string{"/redirect", "/login", "/logout", "/auth", "/oauth/authorize", "/signin"}
	params := []string{"next", "url", "redirect", "return", "continue", "dest"}

	for _, p := range paths {
		for _, q := range params {
			testURL := fmt.Sprintf("%s%s?%s=%s", s.target, p, q, url.QueryEscape(payload))
			resp, err := s.makeRequest("GET", testURL, nil)
			if err != nil {
				continue
			}
			location := resp.Header.Get("Location")
			_ = resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.HasPrefix(location, payload) {
				s.addFinding(Finding{
					Severity:    "High",
					Category:    "Open Redirect",
					Confidence:  "High",
					Finding:     fmt.Sprintf("Open redirect behavior detected at %s", p),
					Remediation: "Use allowlisted redirect destinations and relative redirects only",
					Evidence:    fmt.Sprintf("param=%s location=%s", q, location),
					HTTPMethod:  "GET",
					Outcome:     "Confirmed",
				})
				return
			}
		}
	}
}

func (s *ActiveScanner) checkSubdomainTakeoverIndicators() {
	host := s.targetHostname()
	if host == "" {
		return
	}

	subLabels := []string{"www", "dev", "staging", "api", "blog", "app"}
	providers := []string{"github.io", "herokudns.com", "azurewebsites.net", "cloudfront.net", "fastly.net"}
	indicators := []string{}

	for _, label := range subLabels {
		sub := label + "." + host
		cname, err := net.LookupCNAME(sub)
		if err != nil || cname == sub+"." {
			continue
		}
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		matchedProvider := ""
		for _, p := range providers {
			if strings.Contains(cname, p) {
				matchedProvider = p
				break
			}
		}
		if matchedProvider == "" {
			continue
		}
		if _, err := net.LookupHost(cname); err != nil {
			indicators = append(indicators, fmt.Sprintf("%s -> %s (%s unresolved)", sub, cname, matchedProvider))
		}
	}

	if len(indicators) > 0 {
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Subdomain Takeover",
			Confidence:  "Medium",
			Finding:     "Potential subdomain takeover indicators detected",
			Remediation: "Remove stale DNS records or claim/decommission referenced third-party resources",
			Evidence:    limitList(indicators, 6),
			HTTPMethod:  "DNS",
			Outcome:     "Indicators Found",
		})
	}
}

func (s *ActiveScanner) checkVirtualHostEnumeration() {
	host := s.targetHostname()
	if host == "" {
		return
	}

	baseResp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}
	baseBody, _ := io.ReadAll(io.LimitReader(baseResp.Body, 8192))
	baseStatus := baseResp.StatusCode
	baseLen := len(baseBody)
	_ = baseResp.Body.Close()

	vhosts := []string{"admin." + host, "dev." + host, "staging." + host, "internal." + host}
	deltas := []string{}
	for _, vh := range vhosts {
		resp, err := s.makeRequestWithHost("GET", s.target, vh, nil, nil)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		if resp.StatusCode != baseStatus || abs(len(body)-baseLen) > 512 {
			deltas = append(deltas, fmt.Sprintf("%s status=%d len=%d", vh, resp.StatusCode, len(body)))
		}
	}

	if len(deltas) > 0 {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "Virtual Host Enumeration",
			Confidence:  "Low",
			Finding:     "Alternate virtual host responses detected",
			Remediation: "Harden host-routing rules and restrict access to internal vhosts",
			Evidence:    strings.Join(deltas, " | "),
			HTTPMethod:  "GET",
			Outcome:     "VHost Delta",
		})
	}
}

func (s *ActiveScanner) checkDirectoryBruteforceLite() {
	paths := []string{"/admin", "/admin/login", "/dashboard", "/debug", "/.git/", "/backup", "/internal", "/swagger", "/actuator", "/metrics", "/console", "/phpmyadmin"}
	hits := []string{}
	for _, p := range paths {
		resp, err := s.makeRequest("GET", s.target+p, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			hits = append(hits, fmt.Sprintf("%s (%d)", p, resp.StatusCode))
		}
		_ = resp.Body.Close()
	}

	if len(hits) > 0 {
		severity := "Medium"
		if containsPrefix(hits, "/.git") || containsPrefix(hits, "/debug") {
			severity = "High"
		}
		s.addFinding(Finding{
			Severity:    severity,
			Category:    "Directory Discovery",
			Confidence:  "Medium",
			Finding:     fmt.Sprintf("Sensitive paths discovered (%d)", len(hits)),
			Remediation: "Restrict sensitive endpoints and block direct internet exposure",
			Evidence:    limitList(hits, 10),
			HTTPMethod:  "GET",
			Outcome:     "Sensitive Paths Exposed",
		})
	}
}

func (s *ActiveScanner) checkCredentialEndpointDiscovery() {
	paths := []string{"/login", "/signin", "/auth", "/oauth/token", "/api/auth/login", "/api/token", "/admin/login", "/administrator"}
	hits := []string{}
	for _, p := range paths {
		resp, err := s.makeRequest("GET", s.target+p, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			hits = append(hits, fmt.Sprintf("%s (%d)", p, resp.StatusCode))
		}
		_ = resp.Body.Close()
	}

	if len(hits) > 0 {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Credential Surface",
			Confidence:  "High",
			Finding:     fmt.Sprintf("Authentication endpoints discovered (%d)", len(hits)),
			Remediation: "Apply MFA, brute-force protections, and strong monitoring on auth endpoints",
			Evidence:    limitList(hits, 12),
			HTTPMethod:  "GET",
			Outcome:     "Auth Surface Mapped",
		})
	}
}

func (s *ActiveScanner) targetHostname() string {
	parsed, err := url.Parse(s.target)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}

	candidate := strings.TrimSpace(s.target)
	candidate = strings.TrimPrefix(candidate, "http://")
	candidate = strings.TrimPrefix(candidate, "https://")
	if idx := strings.Index(candidate, "/"); idx >= 0 {
		candidate = candidate[:idx]
	}
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		return host
	}
	return candidate
}

func (s *ActiveScanner) makeRequestWithHost(method, targetURL, hostOverride string, body io.Reader, headers map[string]string) (*http.Response, error) {
	resolvedURL := s.resolveTargetURL(targetURL)
	req, err := http.NewRequest(method, resolvedURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.config.GetUserAgent())
	if hostOverride != "" {
		req.Host = hostOverride
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	time.Sleep(s.config.GetRandomDelay())
	atomic.AddInt64(&s.requestsTotal, 1)
	resp, err := s.client.Do(req)
	if err == nil && resp != nil {
		atomic.AddInt64(&s.successfulReqs, 1)
	} else if err != nil {
		atomic.AddInt64(&s.requestsErrored, 1)
	}
	return resp, err
}

func (s *ActiveScanner) scanTCPPorts(host string, ports []int, timeout time.Duration) []int {
	openPorts := []int{}
	dialer := net.Dialer{Timeout: timeout}
	for _, p := range ports {
		conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, p))
		if err == nil {
			openPorts = append(openPorts, p)
			_ = conn.Close()
		}
	}
	sort.Ints(openPorts)
	return openPorts
}

func (s *ActiveScanner) grabServiceBanner(host string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 1200*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	switch port {
	case 80, 8080, 443:
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
	case 21:
		// FTP usually sends banner on connect
	case 25:
		// SMTP usually sends banner on connect
	default:
		_, _ = conn.Write([]byte("\r\n"))
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.ReplaceAll(banner, "\n", " ")
	banner = strings.ReplaceAll(banner, "\r", " ")
	banner = regexp.MustCompile(`\s+`).ReplaceAllString(banner, " ")
	if len(banner) > 140 {
		banner = banner[:140]
	}
	return banner
}

func unique(in []string) []string {
	set := map[string]struct{}{}
	for _, v := range in {
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func limitList(in []string, max int) string {
	if len(in) <= max {
		return strings.Join(in, ", ")
	}
	return fmt.Sprintf("%s ... (+%d more)", strings.Join(in[:max], ", "), len(in)-max)
}

func contains(in []string, needle string) bool {
	for _, v := range in {
		if v == needle {
			return true
		}
	}
	return false
}

func containsPrefix(in []string, prefix string) bool {
	for _, v := range in {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func intsToCSV(in []int) string {
	if len(in) == 0 {
		return ""
	}
	parts := make([]string, 0, len(in))
	for _, v := range in {
		parts = append(parts, fmt.Sprintf("%d", v))
	}
	return strings.Join(parts, ", ")
}
