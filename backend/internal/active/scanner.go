package active

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"time"
)

// ActiveScanner performs security scans
type ActiveScanner struct {
	target           string
	scanID           uint
	config           *ScanConfig
	client           *http.Client
	findings         []Finding
	externalAdapters []ExternalScannerAdapter
	findingsMu       sync.Mutex
	successfulReqs   int64
	requestsTotal    int64
	requestsErrored  int64
	modulesAttempted int64
	modulesCompleted int64
	modulesErrored   int64
	modulesSkipped   int64
	connectivityOK   int32
}

// SetScanID associates the scanner with a DB scan record for per-module tracking.
func (s *ActiveScanner) SetScanID(id uint) { s.scanID = id }

// setModuleStatus updates the module status in the global registry when a scanID is set.
func (s *ActiveScanner) setModuleStatus(moduleID, status string) {
	if s.scanID != 0 {
		SetModuleStatus(s.scanID, moduleID, status)
	}
}

// Finding represents a security finding
type Finding struct {
	Severity    string
	Category    string
	Confidence  string
	Finding     string
	Remediation string
	Evidence    string
	HTTPMethod  string
	Outcome     string
	Score       int
	Occurrences int
}

// ScanResult contains scan results
type ScanResult struct {
	Target    string
	Findings  []Finding
	StartTime time.Time
	EndTime   time.Time
	Duration  time.Duration

	// Execution telemetry (helps confirm module execution even when no findings are emitted)
	EnabledModules     int
	AttemptedModules   int
	CompletedModules   int
	ErroredModules     int
	SkippedModules     int
	SuccessfulRequests int64
	TotalRequests      int64
	ErroredRequests    int64
}

// NewScanner creates a new scanner instance
func NewScanner(target string, config *ScanConfig) *ActiveScanner {
	if config == nil {
		config = DefaultConfig()
	}

	// Tuned transport for high-concurrency scanning.
	// Defaults are too conservative (very low per-host idle conns) and can cause slowdowns/timeouts.
	maxConns := config.MaxConcurrentRequests * 4
	if maxConns < 20 {
		maxConns = 20
	}
	dnsServers := parseDNSServers(os.Getenv("NIGHTFALL_DNS_SERVERS"))
	resolver := resolverFromServers(dnsServers)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.TimeoutSeconds) * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  resolver,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Scanner must connect to any target regardless of cert validity
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxConns * 2,
		MaxIdleConnsPerHost:   maxConns,
		MaxConnsPerHost:       maxConns,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	return &ActiveScanner{
		target: target,
		config: config,
		client: &http.Client{
			Timeout:   time.Duration(config.TimeoutSeconds) * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		findings: []Finding{},
	}
}

// InitExternalTools detects and registers available external security tools.
func (s *ActiveScanner) InitExternalTools() {
	// Import is done via the tools sub-package; caller wires this.
	s.log("Detecting external security tools...")
}

// Scan executes the security scan
func (s *ActiveScanner) Scan() (*ScanResult, error) {
	startTime := time.Now()
	s.log(fmt.Sprintf("Starting %s mode scan of: %s", s.config.Mode, s.target))
	atomic.StoreInt32(&s.connectivityOK, 1)
	s.preflightConnectivity()

	// ============================================
	// PHASE 1: CORE SECURITY (1-20)
	// Always run regardless of mode
	// ============================================
	s.log("Phase 1: Core Security Checks (20 modules)")

	s.runIf("robots", s.checkRobotsTxt)
	s.runIf("headers", s.checkSecurityHeaders)
	s.runIf("tls", s.checkTLS)
	s.runIf("cookies", s.checkCookies)
	s.runIf("cors", s.checkCORS)
	s.runIf("clickjacking", s.checkClickjacking)
	s.runIf("waf", s.checkWAF)
	s.runIf("websocket", s.checkWebSocket)
	s.runIf("exposure", s.checkExposures)
	s.runIf("http_methods", s.checkHTTPMethods)
	s.runIf("sourcemaps", s.checkSourceMaps)
	s.runIf("comments", s.checkHTMLComments)
	s.runIf("backups", s.checkBackupFiles)
	s.runIf("directory_listing", s.checkDirectoryListing)
	s.runIf("admin_panels", s.checkAdminPanels)
	s.runIf("api_docs", s.checkAPIDocs)
	s.runIf("emails", s.checkEmailAddresses)
	s.runIf("fingerprinting", s.checkFingerprinting)
	s.runIf("graphql", s.discoverGraphQL)

	// ============================================
	// PHASE 2: WEB VULNERABILITIES (21-35)
	// Normal & Aggressive modes only
	// ============================================
	if s.config.Mode != "safe" {
		s.log("Phase 2: Web Vulnerabilities (15 modules)")

		s.runIf("sqli", s.checkSQLInjection)
		s.runIf("xss", s.checkXSS)
		s.runIf("csrf", s.checkCSRF)
		s.runIf("xxe", s.checkXXE)
		s.runIf("ssrf", s.checkSSRF)
		s.runIf("file_inclusion", s.checkFileInclusion)
		s.runIf("path_traversal", s.checkPathTraversal)
		s.runIf("command_injection", s.checkCommandInjection)
		s.runIf("ldap_injection", s.checkLDAPInjection)
		s.runIf("ssti", s.checkTemplateInjection)
		s.runIf("http_splitting", s.checkHTTPSplitting)
		s.runIf("host_header_injection", s.checkHostHeaderInjection)
	}

	// ============================================
	// PHASE 3: AUTHENTICATION & SESSION (36-45)
	// ============================================
	s.log("Phase 3: Authentication & Session Security (10 modules)")

	s.runIf("password_policy", s.checkWeakPasswordPolicy)
	s.runIf("rate_limiting", s.checkRateLimiting)
	s.runIf("brute_force", s.checkBruteForceProtection)
	s.runIf("session_fixation", s.checkSessionFixation)
	s.runIf("session_hijacking", s.checkSessionHijacking)
	s.runIf("oauth", s.checkOAuthMisconfig)
	s.runIf("jwt", s.checkJWT)
	s.runIf("api_key_exposure", s.checkAPIKeyExposure)
	s.runIf("default_creds", s.checkDefaultCredentials)
	s.runIf("password_reset", s.checkPasswordReset)
	s.runIf("mfa_bypass", s.checkMFABypass)

	// ============================================
	// PHASE 4: API SECURITY (46-55)
	// ============================================
	s.log("Phase 4: API Security (10 modules)")

	s.runIf("rest_api", s.checkRESTAPIEnumeration)
	s.runIf("api_rate_limit", s.checkAPIRateLimiting)
	s.runIf("api_auth_bypass", s.checkAPIAuthBypass)
	s.runIf("mass_assignment", s.checkMassAssignment)
	s.runIf("api_version", s.checkAPIVersionDisclosure)
	s.runIf("excessive_data", s.checkExcessiveDataExposure)
	s.runIf("api_cors", s.checkCORSMisconfigAPI)

	// ============================================
	// PHASE 5: FILE UPLOAD & BUSINESS LOGIC (56-70)
	// ============================================
	// Passive business logic checks run in all modes
	s.runIf("price_manipulation", s.checkPriceManipulation)
	s.runIf("privilege_escalation", s.checkPrivilegeEscalation)

	// Active file upload & business logic: Normal & Aggressive only
	if s.config.Mode != "safe" {
		s.log("Phase 5: File Upload & Business Logic (15 modules)")

		s.runIf("file_upload", s.checkFileUpload)
		s.runIf("unrestricted_upload", s.checkUnrestrictedFileUpload)
		s.runIf("idor", s.checkIDOR)
		s.runIf("race_conditions", s.checkRaceConditions)
		s.runIf("account_takeover", s.checkAccountTakeover)
		s.runIf("business_logic", s.checkBusinessLogicFlaws)
	}

	// ============================================
	// PHASE 6: MOBILE, CRYPTO, CLOUD (71-85)
	// Aggressive mode only
	// ============================================
	if s.config.Mode == "aggressive" {
		s.log("Phase 6: Mobile, Crypto & Cloud Security (15 modules)")

		// Mobile (71-75)
		s.runIf("mobile_app_links", s.checkMobileAppLinks)
		s.runIf("app_config", s.checkAppConfiguration)
		s.runIf("cert_pinning", s.checkCertificatePinning)
		s.runIf("root_detection", s.checkRootDetection)
		s.runIf("app_hardening", s.checkAppHardening)

		// Crypto (76-80)
		s.runIf("weak_ciphers", s.checkWeakCiphers)
		s.runIf("sslv3", s.checkSSLv3)
		s.runIf("tls_renegotiation", s.checkInsecureRenegotiation)
		s.runIf("randomness", s.checkRandomnessQuality)
		s.runIf("encryption_at_rest", s.checkEncryptionAtRest)

		// Cloud (81-85)
		s.runIf("cloud_metadata", s.checkCloudMetadata)
		s.runIf("s3_permissions", s.checkS3BucketPermissions)
		s.runIf("docker_exposure", s.checkDockerExposure)
		s.runIf("k8s_exposure", s.checkKubernetesExposure)
		s.runIf("cloud_provider", s.checkCloudProvider)
	}

	// ============================================
	// PHASE 7: COMPLIANCE & ADVANCED (86-95)
	// All modes (informational)
	// ============================================
	s.log("Phase 7: Compliance & Advanced Attacks (10 modules)")

	s.runIf("gdpr", s.checkGDPRCompliance)
	s.runIf("ccpa", s.checkCCPACompliance)
	s.runIf("pci_dss", s.checkPCIDSS)
	s.runIf("hipaa", s.checkHIPAACompliance)
	s.runIf("data_retention", s.checkDataRetention)

	if s.config.Mode != "safe" {
		s.runIf("dom_clobbering", s.checkDOMClobbering)
		s.runIf("prototype_pollution", s.checkPrototypePollution)
		s.runIf("csp_bypass", s.checkCSPBypass)
	}

	// ============================================
	// PHASE 8: INFRASTRUCTURE (96-100)
	// All modes (informational)
	// ============================================
	s.log("Phase 8: Infrastructure & Monitoring (5 modules)")

	s.runIf("load_balancer", s.checkLoadBalancer)
	s.runIf("cdn_bypass", s.checkCDNBypass)
	s.runIf("dnssec", s.checkDNSSEC)
	s.runIf("sri", s.checkSubresourceIntegrity)
	s.runIf("security_monitoring", s.checkSecurityMonitoring)

	// ============================================
	// PHASE 8.5: EXTERNAL TOOLS — SAFE/PASSIVE
	// All modes (passive external tools)
	// ============================================
	s.log("Phase 8.5: External Tool Scans — Passive (5 modules)")

	s.runIf("whatweb_fingerprint", func() { s.tryExternalModule("whatweb_fingerprint") })
	s.runIf("sslscan_ciphers", func() { s.tryExternalModule("sslscan_ciphers") })
	s.runIf("sslscan_protocols", func() { s.tryExternalModule("sslscan_protocols") })
	s.runIf("sslscan_certs", func() { s.tryExternalModule("sslscan_certs") })
	s.runIf("fierce_dns_enum", func() { s.tryExternalModule("fierce_dns_enum") })
	s.runIf("amass_passive", func() { s.tryExternalModule("amass_passive") })
	s.runIf("amass_intel", func() { s.tryExternalModule("amass_intel") })
	s.runIf("gau_urls", func() { s.tryExternalModule("gau_urls") })
	s.runIf("dnsx_resolve", func() { s.tryExternalModule("dnsx_resolve") })
	s.runIf("crtsh_lookup", func() { s.tryExternalModule("crtsh_lookup") })
	s.runIf("alterx_permute", func() { s.tryExternalModule("alterx_permute") })
	s.runIf("uncover_search", func() { s.tryExternalModule("uncover_search") })

	// ============================================
	// PHASE 8.6: EXTERNAL TOOLS — NORMAL
	// Normal & Aggressive modes
	// ============================================
	if s.config.Mode != "safe" {
		s.log("Phase 8.6: External Tool Scans — Active")

		s.runIf("nikto_scan", func() { s.tryExternalModule("nikto_scan") })
		s.runIf("nikto_outdated", func() { s.tryExternalModule("nikto_outdated") })
		s.runIf("nikto_misconfig", func() { s.tryExternalModule("nikto_misconfig") })
		s.runIf("nuclei_cves", func() { s.tryExternalModule("nuclei_cves") })
		s.runIf("nuclei_misconfig", func() { s.tryExternalModule("nuclei_misconfig") })
		s.runIf("nuclei_exposed", func() { s.tryExternalModule("nuclei_exposed") })
		s.runIf("nuclei_takeover", func() { s.tryExternalModule("nuclei_takeover") })
		s.runIf("httpx_probe", func() { s.tryExternalModule("httpx_probe") })
		s.runIf("httpx_tech", func() { s.tryExternalModule("httpx_tech") })
		s.runIf("subfinder_passive", func() { s.tryExternalModule("subfinder_passive") })
		s.runIf("gobuster_dir", func() { s.tryExternalModule("gobuster_dir") })
	}

	// ============================================
	// PHASE 9: EXTERNAL AGGRESSIVE (101-115)
	// Aggressive mode only
	// ============================================
	if s.config.Mode == "aggressive" {
		s.log("Phase 9: External Aggressive Scanning (15 modules)")

		s.runIf("nmap_top1000", s.checkNmapTopPorts)
		s.runIf("nmap_service_detection", s.checkNmapServiceDetection)
		s.runIf("nmap_vuln_scripts", s.checkNmapVulnScripts)
		s.runIf("nmap_udp_top", s.checkNmapUDPTopPorts)
		s.runIf("nmap_tls_ciphers", s.checkNmapTLSCiphers)
		s.runIf("nmap_firewall_bypass", s.checkNmapFirewallEvasion)
		s.runIf("network_port_exposure", s.checkNetworkPortExposure)
		s.runIf("tls_version_matrix", s.checkTLSVersionMatrix)
		s.runIf("http_method_override", s.checkHTTPMethodOverride)
		s.runIf("host_header_injection_adv", s.checkHostHeaderInjectionAdvanced)
		s.runIf("open_redirect_adv", s.checkOpenRedirectAdvanced)
		s.runIf("subdomain_takeover", s.checkSubdomainTakeoverIndicators)
		s.runIf("virtual_host_enum", s.checkVirtualHostEnumeration)
		s.runIf("directory_bruteforce", s.checkDirectoryBruteforceLite)
		s.runIf("credential_endpoint_discovery", s.checkCredentialEndpointDiscovery)

		// Aggressive-only external tools
		s.log("Phase 9.5: Heavy External Tool Scans")
		s.runIf("wapiti_sqli", func() { s.tryExternalModule("wapiti_sqli") })
		s.runIf("wapiti_xss", func() { s.tryExternalModule("wapiti_xss") })
		s.runIf("wapiti_ssrf", func() { s.tryExternalModule("wapiti_ssrf") })
		s.runIf("wapiti_xxe", func() { s.tryExternalModule("wapiti_xxe") })
		s.runIf("skipfish_recon", func() { s.tryExternalModule("skipfish_recon") })
		s.runIf("sqlmap_detect", func() { s.tryExternalModule("sqlmap_detect") })
		s.runIf("sqlmap_deep", func() { s.tryExternalModule("sqlmap_deep") })
		s.runIf("ffuf_dirs", func() { s.tryExternalModule("ffuf_dirs") })
		s.runIf("ffuf_api", func() { s.tryExternalModule("ffuf_api") })
		s.runIf("testssl_basic", func() { s.tryExternalModule("testssl_basic") })
		s.runIf("testssl_vulns", func() { s.tryExternalModule("testssl_vulns") })
		s.runIf("dalfox_url", func() { s.tryExternalModule("dalfox_url") })
		s.runIf("dalfox_param", func() { s.tryExternalModule("dalfox_param") })
		s.runIf("gobuster_vhost", func() { s.tryExternalModule("gobuster_vhost") })
		s.runIf("kiterunner_scan", func() { s.tryExternalModule("kiterunner_scan") })
	}

	// ============================================
	// PHASE 10: ULTRA FAST AGGRESSIVE (116-215)
	// Aggressive mode only
	// ============================================
	if s.config.Mode == "aggressive" {
		s.log("Phase 10: Ultra Fast Aggressive Checks (100 modules)")
		s.runFastAggressiveModules()
	}

	// ============================================
	// PHASE 11: PROTOCOL MATRIX (216-315)
	// Aggressive mode only
	// ============================================
	if s.config.Mode == "aggressive" {
		s.log("Phase 11: Protocol Method Matrix (100 modules)")
		s.runProtocolAggressiveModules()
	}

	endTime := time.Now()
	duration := endTime.Sub(startTime)
	s.postProcessFindings()

	s.log(fmt.Sprintf("Scan complete! Found %d findings in %v", len(s.findings), duration))

	return &ScanResult{
		Target:    s.target,
		Findings:  s.findings,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		EnabledModules: func() int {
			if s.config == nil || s.config.EnabledModules == nil {
				return 0
			}
			return len(s.config.EnabledModules)
		}(),
		AttemptedModules:   int(atomic.LoadInt64(&s.modulesAttempted)),
		CompletedModules:   int(atomic.LoadInt64(&s.modulesCompleted)),
		ErroredModules:     int(atomic.LoadInt64(&s.modulesErrored)),
		SkippedModules:     int(atomic.LoadInt64(&s.modulesSkipped)),
		SuccessfulRequests: atomic.LoadInt64(&s.successfulReqs),
		TotalRequests:      atomic.LoadInt64(&s.requestsTotal),
		ErroredRequests:    atomic.LoadInt64(&s.requestsErrored),
	}, nil
}

func (s *ActiveScanner) preflightConnectivity() {
	// Fast preflight so we can distinguish “logic bugs” from “no network/DNS”.
	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		atomic.StoreInt32(&s.connectivityOK, 0)
		s.addFinding(Finding{
			Severity:    "High",
			Category:    "Connectivity",
			Confidence:  "High",
			Finding:     "Target is not reachable",
			Remediation: "Check DNS, connectivity, and firewall rules (from the scanner host/runtime)",
			Evidence:    err.Error(),
			HTTPMethod:  "GET",
			Outcome:     "Failed",
		})
		return
	}
	resp.Body.Close()
}

func parseDNSServers(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Allow specifying either "ip" or "ip:port".
		if !strings.Contains(p, ":") {
			p = p + ":53"
		}
		out = append(out, p)
	}
	return out
}

func resolverFromServers(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Use TCP DNS to avoid UDP restrictions in some runtimes.
			var lastErr error
			for _, s := range servers {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", s)
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// Helper methods
func (s *ActiveScanner) addFinding(f Finding) {
	if f.Occurrences <= 0 {
		f.Occurrences = 1
	}
	s.findingsMu.Lock()
	s.findings = append(s.findings, f)
	s.findingsMu.Unlock()
	s.log(fmt.Sprintf("[%s] %s: %s", f.Severity, f.Category, f.Finding))
}

func (s *ActiveScanner) log(message string) {
	log.Printf("[ActiveScanner] %s", message)
}

// Progress returns live module and request counters — safe to call concurrently.
func (s *ActiveScanner) Progress() (attempted, completed, errored, skipped, enabled int, totalReqs, successReqs, errorReqs int64) {
	return int(atomic.LoadInt64(&s.modulesAttempted)),
		int(atomic.LoadInt64(&s.modulesCompleted)),
		int(atomic.LoadInt64(&s.modulesErrored)),
		int(atomic.LoadInt64(&s.modulesSkipped)),
		func() int {
			if s.config == nil || s.config.EnabledModules == nil {
				return 0
			}
			return len(s.config.EnabledModules)
		}(),
		atomic.LoadInt64(&s.requestsTotal),
		atomic.LoadInt64(&s.successfulReqs),
		atomic.LoadInt64(&s.requestsErrored)
}

func (s *ActiveScanner) makeRequest(method, targetURL string, body io.Reader) (*http.Response, error) {
	// Fast-fail if connectivity is known to be down — avoids hanging for TimeoutSeconds per module.
	if atomic.LoadInt32(&s.connectivityOK) == 0 {
		atomic.AddInt64(&s.requestsTotal, 1)
		atomic.AddInt64(&s.requestsErrored, 1)
		return nil, fmt.Errorf("target unreachable (connectivity check failed)")
	}

	resolvedURL := s.resolveTargetURL(targetURL)
	req, err := http.NewRequest(method, resolvedURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", s.config.GetUserAgent())

	// Add delay for stealth
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

func (s *ActiveScanner) makeRequestWithHeaders(method, targetURL string, body io.Reader, headers map[string]string) (*http.Response, error) {
	// Fast-fail if connectivity is known to be down.
	if atomic.LoadInt32(&s.connectivityOK) == 0 {
		atomic.AddInt64(&s.requestsTotal, 1)
		atomic.AddInt64(&s.requestsErrored, 1)
		return nil, fmt.Errorf("target unreachable (connectivity check failed)")
	}

	resolvedURL := s.resolveTargetURL(targetURL)
	req, err := http.NewRequest(method, resolvedURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", s.config.GetUserAgent())

	for key, value := range headers {
		req.Header.Set(key, value)
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

func (s *ActiveScanner) resolveTargetURL(targetURL string) string {
	if targetURL == "" {
		return s.target
	}
	if strings.HasPrefix(targetURL, "http://") || strings.HasPrefix(targetURL, "https://") {
		return targetURL
	}
	base, err := url.Parse(s.target)
	if err != nil {
		return targetURL
	}
	if strings.HasPrefix(targetURL, "/") {
		return base.ResolveReference(&url.URL{Path: targetURL}).String()
	}
	rel, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	return base.ResolveReference(rel).String()
}

func (s *ActiveScanner) readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

func (s *ActiveScanner) checkWAF() {
	// Implementation in waf.go
	s.log("WAF check - implementation in waf.go")
}

func (s *ActiveScanner) checkWebSocket() {
	// Implementation in websocket.go
	s.log("WebSocket check - implementation in websocket.go")
}

func (s *ActiveScanner) postProcessFindings() {
	s.findingsMu.Lock()
	defer s.findingsMu.Unlock()
	if len(s.findings) == 0 {
		return
	}

	reachable := atomic.LoadInt64(&s.successfulReqs) > 0

	type agg struct {
		finding Finding
	}
	dedup := make(map[string]*agg, len(s.findings))
	for _, f := range s.findings {
		// If any requests succeeded, suppress the initial connectivity false-positive.
		if reachable && strings.EqualFold(strings.TrimSpace(f.Category), "Connectivity") &&
			strings.Contains(strings.ToLower(f.Finding), "not reachable") {
			continue
		}

		f.Score = calculateFindingScore(f)
		if f.Occurrences <= 0 {
			f.Occurrences = 1
		}

		key := strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
			strings.ToLower(strings.TrimSpace(f.Finding)) + "|" +
			strings.ToLower(strings.TrimSpace(f.HTTPMethod)) + "|" +
			strings.ToLower(strings.TrimSpace(f.Outcome))

		if existing, ok := dedup[key]; ok {
			existing.finding.Occurrences += f.Occurrences
			if f.Score > existing.finding.Score {
				existing.finding.Score = f.Score
				existing.finding.Severity = f.Severity
				existing.finding.Confidence = f.Confidence
				if strings.TrimSpace(f.Remediation) != "" {
					existing.finding.Remediation = f.Remediation
				}
			}
			if strings.TrimSpace(f.Evidence) != "" && !strings.Contains(existing.finding.Evidence, f.Evidence) {
				if existing.finding.Evidence == "" {
					existing.finding.Evidence = f.Evidence
				} else if len(existing.finding.Evidence) < 700 {
					existing.finding.Evidence += " | " + f.Evidence
				}
			}
			continue
		}
		copyFinding := f
		dedup[key] = &agg{finding: copyFinding}
	}

	out := make([]Finding, 0, len(dedup))
	for _, a := range dedup {
		out = append(out, a.finding)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if severityWeight(out[i].Severity) != severityWeight(out[j].Severity) {
			return severityWeight(out[i].Severity) > severityWeight(out[j].Severity)
		}
		if out[i].Occurrences != out[j].Occurrences {
			return out[i].Occurrences > out[j].Occurrences
		}
		return out[i].Finding < out[j].Finding
	})

	s.findings = out
}

func calculateFindingScore(f Finding) int {
	score := severityWeight(f.Severity)
	switch strings.ToLower(strings.TrimSpace(f.Confidence)) {
	case "high":
		score += 10
	case "medium":
		score += 5
	}

	outcome := strings.ToLower(strings.TrimSpace(f.Outcome))
	if strings.Contains(outcome, "confirmed") || strings.Contains(outcome, "enabled") || strings.Contains(outcome, "exposed") || strings.Contains(outcome, "accepted") {
		score += 8
	} else if strings.Contains(outcome, "potential") || strings.Contains(outcome, "indicator") {
		score += 3
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

func severityWeight(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 45
	case "low":
		return 25
	default:
		return 10
	}
}
