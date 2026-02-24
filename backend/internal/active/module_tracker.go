package active

import "sync"

// ModuleStatus represents the current status of a single scan module.
type ModuleStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pending | running | completed | failed | skipped
}

// scanModuleRegistry stores per-scanID module status maps.
// Key: scanID (uint), Value: *sync.Map (moduleID -> string status)
var scanModuleRegistry sync.Map

// RegisterScanModules pre-populates a registry entry for the given scan with all
// expected module IDs in "pending" state.
func RegisterScanModules(scanID uint, moduleIDs []string) {
	m := &sync.Map{}
	for _, id := range moduleIDs {
		m.Store(id, "pending")
	}
	scanModuleRegistry.Store(scanID, m)
}

// SetModuleStatus updates the status of a single module within a scan's registry.
// It is a no-op if the scan has not been registered.
func SetModuleStatus(scanID uint, moduleID, status string) {
	if v, ok := scanModuleRegistry.Load(scanID); ok {
		v.(*sync.Map).Store(moduleID, status)
	}
}

// GetModuleStatuses returns a snapshot of all module statuses for a given scan.
func GetModuleStatuses(scanID uint) []ModuleStatus {
	v, ok := scanModuleRegistry.Load(scanID)
	if !ok {
		return nil
	}
	m := v.(*sync.Map)
	var out []ModuleStatus
	m.Range(func(k, val interface{}) bool {
		out = append(out, ModuleStatus{
			ID:     k.(string),
			Status: val.(string),
		})
		return true
	})
	return out
}

// ClearScanModules removes the module registry for a completed or cancelled scan.
func ClearScanModules(scanID uint) {
	scanModuleRegistry.Delete(scanID)
}

// AllModuleIDs returns all module IDs known to the scanner for a given mode.
// mode: "safe" | "normal" | "aggressive"
func AllModuleIDs(mode string) []string {
	ids := []string{
		// Phase 1 – Core (all modes)
		"robots", "headers", "tls", "cookies", "cors", "clickjacking", "waf",
		"websocket", "exposure", "http_methods", "sourcemaps", "comments",
		"backups", "directory_listing", "admin_panels", "api_docs", "emails",
		"fingerprinting", "graphql",
	}

	if mode == "normal" || mode == "aggressive" {
		// Phase 2 – Web Vulnerabilities
		ids = append(ids,
			"sqli", "xss", "csrf", "xxe", "ssrf", "file_inclusion",
			"path_traversal", "command_injection", "ldap_injection", "ssti",
			"http_splitting", "host_header_injection",
		)
	}

	// Phase 3 – Auth (all modes)
	ids = append(ids,
		"password_policy", "rate_limiting", "brute_force", "session_fixation",
		"session_hijacking", "oauth", "jwt", "api_key_exposure", "default_creds",
		"password_reset", "mfa_bypass",
	)

	// Phase 4 – API Security (all modes)
	ids = append(ids,
		"rest_api", "api_rate_limit", "api_auth_bypass", "mass_assignment",
		"api_version", "excessive_data", "api_cors",
	)

	// Phase 5 – Business Logic (all modes)
	ids = append(ids,
		"price_manipulation", "privilege_escalation", "file_upload",
		"unrestricted_upload", "idor", "race_conditions", "account_takeover",
		"business_logic",
	)

	if mode == "aggressive" {
		// Phase 6 – Mobile / Crypto / Cloud
		ids = append(ids,
			"mobile_app_links", "app_config", "cert_pinning", "root_detection",
			"app_hardening", "weak_ciphers", "sslv3", "tls_renegotiation",
			"randomness", "encryption_at_rest", "cloud_metadata", "s3_permissions",
			"docker_exposure", "k8s_exposure", "cloud_provider",
		)
	}

	// Phase 7 – Compliance (all modes)
	ids = append(ids,
		"gdpr", "ccpa", "pci_dss", "hipaa", "data_retention",
		"dom_clobbering", "prototype_pollution", "csp_bypass",
	)

	// Phase 8 – Infrastructure (all modes)
	ids = append(ids,
		"load_balancer", "cdn_bypass", "dnssec", "sri", "security_monitoring",
	)

	if mode == "safe" || mode == "normal" || mode == "aggressive" {
		// Phase 8.5 – External Passive (all modes)
		ids = append(ids,
			"whatweb_fingerprint", "sslscan_ciphers", "sslscan_protocols",
			"sslscan_certs", "fierce_dns_enum", "amass_passive", "amass_intel",
			"gau_urls", "dnsx_resolve", "crtsh_lookup", "alterx_permute",
			"uncover_search",
		)
	}

	if mode == "normal" || mode == "aggressive" {
		// Phase 8.6 – External Normal
		ids = append(ids,
			"nikto_scan", "nikto_outdated", "nikto_misconfig",
			"nuclei_cves", "nuclei_misconfig", "nuclei_exposed", "nuclei_takeover",
			"httpx_probe", "httpx_tech", "subfinder_passive", "gobuster_dir",
		)
	}

	if mode == "aggressive" {
		// Phase 9 – External Aggressive (30)
		ids = append(ids,
			"nmap_top1000", "nmap_service_detection", "nmap_vuln_scripts",
			"nmap_udp_top", "nmap_tls_ciphers", "nmap_firewall_bypass",
			"network_port_exposure", "tls_version_matrix", "http_method_override",
			"host_header_injection_adv", "open_redirect_adv", "subdomain_takeover",
			"virtual_host_enum", "directory_bruteforce", "credential_endpoint_discovery",
			"wapiti_sqli", "wapiti_xss", "wapiti_ssrf", "wapiti_xxe",
			"skipfish_recon", "sqlmap_detect", "sqlmap_deep",
			"ffuf_dirs", "ffuf_api", "testssl_basic", "testssl_vulns",
			"dalfox_url", "dalfox_param", "gobuster_vhost", "kiterunner_scan",
		)

		// Phase 10 – Fast Aggressive (100)
		for _, id := range fastAggressiveModuleIDs() {
			ids = append(ids, id)
		}

		// Phase 11 – Protocol Matrix (100)
		for _, id := range protocolAggressiveModuleIDs() {
			ids = append(ids, id)
		}
	}

	return ids
}
