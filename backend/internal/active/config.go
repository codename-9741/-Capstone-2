package active

import (
	"math/rand"
	"time"
)

// ScanConfig holds scan configuration
type ScanConfig struct {
	Mode                  string // "safe", "normal", "aggressive"
	TimeoutSeconds        int
	DelayMin              int // milliseconds
	DelayMax              int // milliseconds
	RespectRobotsTxt      bool
	EnabledModules        map[string]bool
	UserAgent             string
	StealthEnabled        bool
	MaxConcurrentRequests int
}

// DefaultConfig returns normal mode configuration
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		Mode:                  "normal",
		TimeoutSeconds:        15,
		DelayMin:              100,
		DelayMax:              300,
		RespectRobotsTxt:      true,
		EnabledModules:        normalModeModules(),
		UserAgent:             "NIGHTFALL-TSUKUYOMI/1.0 (Security Audit)",
		StealthEnabled:        true,
		MaxConcurrentRequests: 5,
	}
}

// SafeConfig returns safe mode (minimal detection risk)
func SafeConfig() *ScanConfig {
	return &ScanConfig{
		Mode:                  "safe",
		TimeoutSeconds:        20,
		DelayMin:              500,
		DelayMax:              1000,
		RespectRobotsTxt:      true,
		EnabledModules:        safeModeModules(),
		UserAgent:             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		StealthEnabled:        true,
		MaxConcurrentRequests: 1,
	}
}

// AggressiveConfig returns aggressive mode (comprehensive testing)
func AggressiveConfig() *ScanConfig {
	return &ScanConfig{
		Mode:                  "aggressive",
		TimeoutSeconds:        30,
		DelayMin:              50,
		DelayMax:              150,
		RespectRobotsTxt:      false,
		EnabledModules:        aggressiveModeModules(),
		UserAgent:             "NIGHTFALL-TSUKUYOMI/1.0 (Authorized Security Test)",
		StealthEnabled:        false,
		MaxConcurrentRequests: 40,
	}
}

// safeModeModules returns modules for safe mode (~40 modules)
func safeModeModules() map[string]bool {
	return map[string]bool{
		// Core security (passive detection)
		"robots":            true,
		"headers":           true,
		"tls":               true,
		"cookies":           true,
		"cors":              true,
		"clickjacking":      true,
		"waf":               true,
		"websocket":         true,
		"exposure":          true,
		"http_methods":      true,
		"sourcemaps":        true,
		"comments":          true,
		"backups":           true,
		"directory_listing": true,
		"admin_panels":      true,
		"api_docs":          true,
		"emails":            true,
		"fingerprinting":    true,
		"graphql":           true,

		// Authentication (passive)
		"password_policy":  true,
		"oauth":            true,
		"jwt":              true,
		"api_key_exposure": true,
		"password_reset":   true,
		"mfa_bypass":       true,

		// API Security (passive)
		"rest_api":       true,
		"api_version":    true,
		"excessive_data": true,
		"api_cors":       true,

		// Business Logic (passive)
		"price_manipulation":   true,
		"privilege_escalation": true,

		// Compliance (informational)
		"gdpr":           true,
		"ccpa":           true,
		"pci_dss":        true,
		"hipaa":          true,
		"data_retention": true,

		// Infrastructure (informational)
		"load_balancer":       true,
		"cdn_bypass":          true,
		"dnssec":              true,
		"sri":                 true,
		"security_monitoring": true,

		// External tools (safe/passive)
		"whatweb_fingerprint": true,
		"sslscan_ciphers":     true,
		"sslscan_protocols":   true,
		"sslscan_certs":       true,
		"fierce_dns_enum":     true,
		"amass_passive":       true,
		"amass_intel":         true,
		"gau_urls":            true,
		"dnsx_resolve":        true,
		"crtsh_lookup":        true,
		"alterx_permute":      true,
		"uncover_search":      true,
	}
}

// normalModeModules returns modules for normal mode (~70 modules)
func normalModeModules() map[string]bool {
	modules := safeModeModules()

	// Add web vulnerabilities
	modules["sqli"] = true
	modules["xss"] = true
	modules["csrf"] = true
	modules["xxe"] = true
	modules["ssrf"] = true
	modules["file_inclusion"] = true
	modules["path_traversal"] = true
	modules["command_injection"] = true
	modules["ldap_injection"] = true
	modules["ssti"] = true
	modules["http_splitting"] = true
	modules["host_header_injection"] = true

	// Add active auth tests
	modules["rate_limiting"] = true
	modules["brute_force"] = true
	modules["session_fixation"] = true
	modules["session_hijacking"] = true
	modules["default_creds"] = true

	// Add API security tests
	modules["api_rate_limit"] = true
	modules["api_auth_bypass"] = true
	modules["mass_assignment"] = true

	// Add file upload & business logic
	modules["file_upload"] = true
	modules["unrestricted_upload"] = true
	modules["idor"] = true
	modules["race_conditions"] = true
	modules["account_takeover"] = true
	modules["business_logic"] = true

	// Add advanced attacks
	modules["dom_clobbering"] = true
	modules["prototype_pollution"] = true
	modules["csp_bypass"] = true

	// Add exposure tests
	modules["exposure"] = true
	modules["http_methods"] = true

	// External tools (normal mode)
	modules["nikto_scan"] = true
	modules["nikto_outdated"] = true
	modules["nikto_misconfig"] = true
	modules["nuclei_cves"] = true
	modules["nuclei_misconfig"] = true
	modules["nuclei_exposed"] = true
	modules["nuclei_takeover"] = true
	modules["nmap_top1000"] = true
	modules["nmap_service_detection"] = true
	modules["httpx_probe"] = true
	modules["httpx_tech"] = true
	modules["subfinder_passive"] = true
	modules["gobuster_dir"] = true
	modules["amass_passive"] = true
	modules["gau_urls"] = true
	modules["dnsx_resolve"] = true
	modules["crtsh_lookup"] = true

	return modules
}

// aggressiveModeModules returns ALL aggressive modules
func aggressiveModeModules() map[string]bool {
	modules := normalModeModules()

	// Add mobile security
	modules["mobile_app_links"] = true
	modules["app_config"] = true
	modules["cert_pinning"] = true
	modules["root_detection"] = true
	modules["app_hardening"] = true

	// Add crypto
	modules["weak_ciphers"] = true
	modules["sslv3"] = true
	modules["tls_renegotiation"] = true
	modules["randomness"] = true
	modules["encryption_at_rest"] = true

	// Add cloud security
	modules["cloud_metadata"] = true
	modules["s3_permissions"] = true
	modules["docker_exposure"] = true
	modules["k8s_exposure"] = true
	modules["cloud_provider"] = true

	// Add external aggressive scanners (nmap + heavy tools)
	modules["nmap_top1000"] = true
	modules["nmap_service_detection"] = true
	modules["nmap_vuln_scripts"] = true
	modules["nmap_udp_top"] = true
	modules["nmap_tls_ciphers"] = true
	modules["nmap_firewall_bypass"] = true

	// Aggressive-only external tools
	modules["wapiti_sqli"] = true
	modules["wapiti_xss"] = true
	modules["wapiti_ssrf"] = true
	modules["wapiti_xxe"] = true
	modules["skipfish_recon"] = true
	modules["sqlmap_detect"] = true
	modules["sqlmap_deep"] = true
	modules["ffuf_dirs"] = true
	modules["ffuf_api"] = true
	modules["testssl_basic"] = true
	modules["testssl_vulns"] = true
	modules["dalfox_url"] = true
	modules["dalfox_param"] = true
	modules["gobuster_vhost"] = true
	modules["kiterunner_scan"] = true
	modules["network_port_exposure"] = true
	modules["tls_version_matrix"] = true
	modules["http_method_override"] = true
	modules["host_header_injection_adv"] = true
	modules["open_redirect_adv"] = true
	modules["subdomain_takeover"] = true
	modules["virtual_host_enum"] = true
	modules["directory_bruteforce"] = true
	modules["credential_endpoint_discovery"] = true

	// Add ultra-fast aggressive modules (+100)
	for _, moduleID := range fastAggressiveModuleIDs() {
		modules[moduleID] = true
	}

	// Add protocol matrix modules (+100)
	for _, moduleID := range protocolAggressiveModuleIDs() {
		modules[moduleID] = true
	}

	return modules
}

// ShouldRunModule checks if a module should run based on mode
func (c *ScanConfig) ShouldRunModule(module string) bool {
	enabled, exists := c.EnabledModules[module]
	return exists && enabled
}

// GetRandomDelay returns a random delay within configured range
func (c *ScanConfig) GetRandomDelay() time.Duration {
	if !c.StealthEnabled {
		return 0
	}

	delay := c.DelayMin + rand.Intn(c.DelayMax-c.DelayMin)
	return time.Duration(delay) * time.Millisecond
}

// GetUserAgent returns the configured user agent
func (c *ScanConfig) GetUserAgent() string {
	return c.UserAgent
}
