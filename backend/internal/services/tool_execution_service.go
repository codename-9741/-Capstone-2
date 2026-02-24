package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/active"
	"nightfall-tsukuyomi/internal/active/tools"
	"nightfall-tsukuyomi/internal/models"
)

// moduleArgs maps tool_name -> module_id -> base CLI args (before target).
// Target is appended at the end except where noted.
var moduleArgs = map[string]map[string][]string{
	"nmap": {
		"nmap_top1000":           {"-sT", "--top-ports", "1000", "-T4", "--open", "-oN", "-"},
		"nmap_service_detection": {"-sV", "--top-ports", "100", "-T4", "-oN", "-"},
		"nmap_vuln_scripts":      {"-sV", "--script", "vuln", "--top-ports", "50", "-T4", "-oN", "-"},
		"nmap_udp_top":           {"-sU", "--top-ports", "20", "-T4", "-oN", "-"},
		"nmap_tls_ciphers":       {"-sV", "--script", "ssl-enum-ciphers", "-p", "443", "-oN", "-"},
		"nmap_firewall_bypass":   {"-sA", "--top-ports", "100", "-T4", "-oN", "-"},
	},
	"nikto": {
		"nikto_scan":      {"-h", "__TARGET__", "-Format", "txt"},
		"nikto_outdated":  {"-h", "__TARGET__", "-Format", "txt", "-Tuning", "9"},
		"nikto_misconfig": {"-h", "__TARGET__", "-Format", "txt", "-Tuning", "2"},
	},
	"nuclei": {
		"nuclei_cves":      {"-u", "__TARGET__", "-silent", "-t", "cves/"},
		"nuclei_misconfig": {"-u", "__TARGET__", "-silent", "-t", "misconfiguration/"},
		"nuclei_exposed":   {"-u", "__TARGET__", "-silent", "-t", "exposures/"},
		"nuclei_takeover":  {"-u", "__TARGET__", "-silent", "-t", "takeovers/"},
	},
	"wapiti": {
		"wapiti_sqli": {"-u", "__TARGET__", "-m", "sql"},
		"wapiti_xss":  {"-u", "__TARGET__", "-m", "xss"},
		"wapiti_ssrf": {"-u", "__TARGET__", "-m", "ssrf"},
		"wapiti_xxe":  {"-u", "__TARGET__", "-m", "xxe"},
	},
	"sslscan": {
		"sslscan_ciphers":   {"__TARGET__"},
		"sslscan_protocols": {"--no-ciphersuites", "__TARGET__"},
		"sslscan_certs":     {"--show-certificate", "__TARGET__"},
	},
	"whatweb": {
		"whatweb_fingerprint": {"__TARGET__"},
	},
	"fierce": {
		"fierce_dns_enum": {"--domain", "__DOMAIN__"},
	},
	"skipfish": {
		"skipfish_recon": {"-o", "/tmp/sf-__ID__", "__TARGET__"},
	},
	"sqlmap": {
		"sqlmap_detect": {"-u", "__TARGET__", "--batch", "--smart", "--level", "1", "--risk", "1"},
		"sqlmap_deep":   {"-u", "__TARGET__", "--batch", "--level", "3", "--risk", "2"},
	},
	"ffuf": {
		"ffuf_dirs": {"-u", "__TARGET__/FUZZ", "-w", "/usr/local/share/nightfall/wordlists/common.txt", "-mc", "200,204,301,302,307,401,403"},
		"ffuf_api":  {"-u", "__TARGET__/api/FUZZ", "-w", "/usr/local/share/nightfall/wordlists/api.txt", "-mc", "200,204,301,302,307,401,403"},
	},
	"subfinder": {
		"subfinder_passive": {"-d", "__DOMAIN__", "-silent"},
	},
	"testssl.sh": {
		"testssl_basic": {"--warnings", "off", "--color", "0", "__TARGET__"},
		"testssl_vulns": {"--vulnerable", "--warnings", "off", "--color", "0", "__TARGET__"},
	},
	"dalfox": {
		"dalfox_url":   {"url", "__TARGET__", "--no-color", "--silence", "--skip-bav"},
		"dalfox_param": {"url", "__TARGET__", "--no-color", "--silence", "--skip-bav", "--skip-mining-dom"},
	},
	"gobuster": {
		"gobuster_dir":   {"dir", "-u", "__TARGET__", "-w", "/usr/local/share/nightfall/wordlists/common.txt", "-q"},
		"gobuster_vhost": {"vhost", "-u", "__TARGET__", "-w", "/usr/local/share/nightfall/wordlists/vhosts.txt", "-q"},
	},
	"httpx": {
		"httpx_probe": {"-u", "__TARGET__", "-silent", "-status-code", "-title"},
		"httpx_tech":  {"-u", "__TARGET__", "-silent", "-tech-detect"},
	},
	"kr": {
		"kiterunner_scan": {"scan", "__TARGET__"},
	},
	"amass": {
		"amass_passive": {"enum", "-passive", "-d", "__DOMAIN__", "-silent"},
		"amass_intel":   {"intel", "-whois", "-d", "__DOMAIN__"},
	},
	"uncover": {
		"uncover_search": {"-q", "__DOMAIN__", "-silent"},
	},
	"gau": {
		"gau_urls": {"--subs", "__DOMAIN__"},
	},
	"dnsx": {
		"dnsx_resolve": {"-d", "__DOMAIN__", "-silent", "-resp"},
	},
	"alterx": {
		"alterx_permute": {"-d", "__DOMAIN__", "-silent"},
	},
	"crtsh": {
		"crtsh_lookup": {"__DOMAIN__"},
	},
}

// ModuleInfo describes a single tool module.
type ModuleInfo struct {
	ToolName    string `json:"tool_name"`
	ModuleID    string `json:"module_id"`
	Description string `json:"description"`
}

// GetAllModules returns all available tool modules.
func GetAllModules() []ModuleInfo {
	var modules []ModuleInfo
	for toolName, mods := range moduleArgs {
		for modID := range mods {
			modules = append(modules, ModuleInfo{
				ToolName: toolName,
				ModuleID: modID,
			})
		}
	}
	return modules
}

// ToolExecutionService manages standalone tool executions.
type ToolExecutionService struct {
	db        *gorm.DB
	mu        sync.Mutex
	processes map[uint]*exec.Cmd
}

// NewToolExecutionService creates a new service.
func NewToolExecutionService(db *gorm.DB) *ToolExecutionService {
	return &ToolExecutionService{
		db:        db,
		processes: make(map[uint]*exec.Cmd),
	}
}

// buildCommand constructs the CLI args for a given tool/module/target/customArgs.
func buildCommand(toolName, moduleID, target, customArgs string, execID uint) (binary string, args []string, cmdStr string, err error) {
	// Check tool availability
	runner := &tools.ToolRunner{Name: toolName}
	if !runner.CheckAvailable() {
		return "", nil, "", fmt.Errorf("%s is not installed", toolName)
	}
	binary = runner.BinaryPath

	// Look up module args
	toolModules, ok := moduleArgs[toolName]
	if !ok {
		return "", nil, "", fmt.Errorf("unknown tool: %s", toolName)
	}
	baseArgs, ok := toolModules[moduleID]
	if !ok {
		return "", nil, "", fmt.Errorf("unknown module %s for tool %s", moduleID, toolName)
	}

	// Clone and substitute placeholders
	args = make([]string, len(baseArgs))
	copy(args, baseArgs)
	domain := extractDomain(target)
	for i, a := range args {
		if a == "__TARGET__" {
			args[i] = target
		}
		if a == "__DOMAIN__" {
			args[i] = domain
		}
		if strings.Contains(a, "__ID__") {
			args[i] = strings.ReplaceAll(a, "__ID__", fmt.Sprintf("%d", execID))
		}
	}

	// If no __TARGET__ placeholder, append target at the end
	hasTarget := false
	for _, a := range baseArgs {
		if a == "__TARGET__" || a == "__DOMAIN__" {
			hasTarget = true
			break
		}
	}
	if !hasTarget {
		args = append(args, target)
	}

	// Append custom args
	if customArgs != "" {
		extra := strings.Fields(customArgs)
		args = append(args, extra...)
	}

	cmdStr = toolName + " " + strings.Join(args, " ")
	return binary, args, cmdStr, nil
}

func extractDomain(target string) string {
	domain := target
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	domain = strings.TrimSpace(domain)
	return domain
}

// ExecuteTool starts a tool execution asynchronously.
// targetID and scanID are optional (0 = auto-resolve/create).
func (s *ToolExecutionService) ExecuteTool(toolName, moduleID, target, customArgs string, targetID, scanID uint) (*models.ToolExecution, error) {
	// Create DB record first to get an ID
	now := time.Now()
	execution := &models.ToolExecution{
		TargetID:   targetID,
		ScanID:     scanID,
		ToolName:   toolName,
		ModuleID:   moduleID,
		Target:     target,
		CustomArgs: customArgs,
		Status:     "running",
		StartedAt:  &now,
	}
	if err := s.db.Create(execution).Error; err != nil {
		return nil, fmt.Errorf("failed to create execution record: %w", err)
	}

	// Build command
	binary, args, cmdStr, err := buildCommand(toolName, moduleID, target, customArgs, execution.ID)
	if err != nil {
		execution.Status = "failed"
		execution.ErrorMsg = err.Error()
		completedAt := time.Now()
		execution.CompletedAt = &completedAt
		s.db.Save(execution)
		return execution, nil
	}

	execution.Command = cmdStr
	s.db.Save(execution)

	// Run in goroutine
	go s.runTool(execution.ID, binary, args)

	return execution, nil
}

func (s *ToolExecutionService) runTool(execID uint, binary string, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	// Track process for stop
	s.mu.Lock()
	s.processes[execID] = cmd
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.processes, execID)
		s.mu.Unlock()
	}()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[ToolExec] Starting execution #%d: %s %s", execID, binary, strings.Join(args, " "))

	err := cmd.Start()
	if err != nil {
		s.finishExecution(execID, "", -1, fmt.Sprintf("failed to start: %v", err))
		return
	}

	// Poll output every 2 seconds while process runs
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			output := stdout.String() + stderr.String()
			if output != "" {
				s.db.Model(&models.ToolExecution{}).Where("id = ?", execID).Update("raw_output", output)
			}
		case cmdErr := <-done:
			output := stdout.String()
			if stderr.Len() > 0 {
				output += "\n--- STDERR ---\n" + stderr.String()
			}

			exitCode := 0
			errMsg := ""
			if cmdErr != nil {
				if exitErr, ok := cmdErr.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					exitCode = -1
				}
				if ctx.Err() == context.DeadlineExceeded {
					errMsg = "execution timed out after 10 minutes"
				} else if output == "" {
					errMsg = cmdErr.Error()
				}
				// Many security tools exit non-zero when they find issues — not an error
			}

			s.finishExecution(execID, output, exitCode, errMsg)
			return
		}
	}
}

func (s *ToolExecutionService) finishExecution(execID uint, output string, exitCode int, errMsg string) {
	now := time.Now()
	status := "completed"
	if errMsg != "" {
		status = "failed"
	}

	updates := map[string]any{
		"raw_output":   output,
		"status":       status,
		"exit_code":    exitCode,
		"error_msg":    errMsg,
		"completed_at": now,
	}

	s.db.Model(&models.ToolExecution{}).Where("id = ?", execID).Updates(updates)
	log.Printf("[ToolExec] Execution #%d finished: status=%s exit_code=%d", execID, status, exitCode)

	// Parse output into findings if completed successfully
	if status == "completed" && output != "" {
		var execution models.ToolExecution
		if err := s.db.First(&execution, execID).Error; err == nil {
			s.parseAndSaveFindings(&execution)
		}
	}
}

// GetExecution fetches a single execution by ID.
func (s *ToolExecutionService) GetExecution(id uint) (*models.ToolExecution, error) {
	var exec models.ToolExecution
	if err := s.db.First(&exec, id).Error; err != nil {
		return nil, err
	}
	return &exec, nil
}

// ListExecutions returns all executions, optionally filtered by target_id, newest first.
func (s *ToolExecutionService) ListExecutions(targetID uint) ([]models.ToolExecution, error) {
	var execs []models.ToolExecution
	q := s.db.Order("created_at DESC")
	if targetID != 0 {
		q = q.Where("target_id = ?", targetID)
	}
	if err := q.Find(&execs).Error; err != nil {
		return nil, err
	}
	return execs, nil
}

// parseAndSaveFindings parses tool output into structured Finding records.
func (s *ToolExecutionService) parseAndSaveFindings(execution *models.ToolExecution) {
	var scanID uint

	if execution.ScanID != 0 {
		// Reuse the shared batch scan record
		scanID = execution.ScanID
	} else {
		// Find or create target
		target := s.findOrCreateTarget(execution.Target)
		if target == nil {
			log.Printf("[ToolExec] Could not resolve target for %s", execution.Target)
			return
		}

		// Create a lightweight scan record so findings appear in the main Findings page
		now := time.Now()
		scan := models.Scan{
			TargetID:    target.ID,
			Status:      "completed",
			Config:      models.ScanConfig{Mode: "tool"},
			StartedAt:   execution.StartedAt,
			CompletedAt: &now,
		}
		if err := s.db.Create(&scan).Error; err != nil {
			log.Printf("[ToolExec] Failed to create scan record: %v", err)
			return
		}
		scanID = scan.ID
	}

	// alias so rest of function can use scan.ID inline
	scan := struct{ ID uint }{ID: scanID}

	// Parse findings based on tool
	var rawFindings []parsedFinding
	switch execution.ToolName {
	case "nmap":
		rawFindings = parseNmapOutput(execution.RawOutput)
	case "nuclei":
		rawFindings = parseNucleiOutput(execution.RawOutput)
	case "nikto":
		rawFindings = parseNiktoOutput(execution.RawOutput)
	case "sslscan":
		rawFindings = parseSSLScanOutput(execution.RawOutput)
	case "whatweb":
		rawFindings = parseWhatwebOutput(execution.RawOutput)
	case "fierce":
		rawFindings = parseFierceOutput(execution.RawOutput)
	case "wapiti":
		rawFindings = parseWapitiOutput(execution.RawOutput)
	case "sqlmap":
		rawFindings = parseSQLMapOutput(execution.RawOutput)
	case "ffuf":
		rawFindings = parseFFUFOutput(execution.RawOutput)
	case "subfinder":
		rawFindings = parseSubfinderOutput(execution.RawOutput)
	case "testssl.sh":
		rawFindings = parseTestSSLOutput(execution.RawOutput)
	case "dalfox":
		rawFindings = parseDalfoxOutput(execution.RawOutput)
	case "gobuster":
		rawFindings = parseGobusterOutput(execution.RawOutput)
	case "httpx":
		rawFindings = parseHTTPXOutput(execution.RawOutput)
	case "kr":
		rawFindings = parseKiterunnerOutput(execution.RawOutput)
	case "amass":
		rawFindings = parseAmassOutput(execution.RawOutput)
	case "uncover":
		rawFindings = parseUncoverOutput(execution.RawOutput)
	case "gau":
		rawFindings = parseGauOutput(execution.RawOutput)
	case "dnsx":
		rawFindings = parseDNSXOutput(execution.RawOutput)
	case "alterx":
		rawFindings = parseAlterxOutput(execution.RawOutput)
	case "crtsh":
		rawFindings = parseCRTShOutput(execution.RawOutput)
	default:
		rawFindings = parseGenericOutput(execution.RawOutput, execution.ToolName)
	}

	// Convert to Finding models with enrichment
	count := 0
	for _, rf := range rawFindings {
		enrichment := active.EnrichFinding(rf.category, rf.finding, execution.ToolName)
		correlationID := active.GenerateCorrelationID(rf.category, rf.finding, execution.Target)

		finding := models.Finding{
			ScanID:         scan.ID,
			Severity:       rf.severity,
			Category:       rf.category,
			Confidence:     rf.confidence,
			Finding:        rf.finding,
			Evidence:       rf.evidence,
			ToolSource:     execution.ToolName,
			MitreAttackID:  enrichment.MitreAttackID,
			MitreTactic:    enrichment.MitreTactic,
			MitreTechnique: enrichment.MitreTechnique,
			OwaspCategory:  enrichment.OwaspCategory,
			OwaspName:      enrichment.OwaspName,
			KillChainPhase: enrichment.KillChainPhase,
			CorrelationID:  correlationID,
		}
		if err := s.db.Create(&finding).Error; err != nil {
			log.Printf("[ToolExec] Failed to save finding: %v", err)
			continue
		}
		count++
	}

	// Update finding count
	s.db.Model(&models.ToolExecution{}).Where("id = ?", execution.ID).Update("finding_count", count)

	log.Printf("[ToolExec] Parsed %d findings from execution #%d (%s)", count, execution.ID, execution.ToolName)
}

// findOrCreateTarget resolves a target domain from the execution target string.
func (s *ToolExecutionService) findOrCreateTarget(targetStr string) *models.Target {
	// Strip protocol and path to get domain
	domain := targetStr
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}

	var target models.Target
	result := s.db.Where("domain = ?", domain).First(&target)
	if result.Error == nil {
		return &target
	}
	target = models.Target{Domain: domain}
	if err := s.db.Create(&target).Error; err != nil {
		return nil
	}
	return &target
}

// parsedFinding is an intermediate struct for parsed tool output.
type parsedFinding struct {
	severity   string
	category   string
	confidence string
	finding    string
	evidence   string
}

// --- Nmap parser ---
var nmapPortRe = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$`)

func parseNmapOutput(output string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	currentHost := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Nmap scan report for ") {
			currentHost = strings.TrimPrefix(line, "Nmap scan report for ")
		}
		if m := nmapPortRe.FindStringSubmatch(line); m != nil {
			port, proto, service, version := m[1], m[2], m[3], strings.TrimSpace(m[4])
			finding := fmt.Sprintf("Open port %s/%s running %s", port, proto, service)
			if version != "" {
				finding += " (" + version + ")"
			}
			evidence := line
			if currentHost != "" {
				evidence = currentHost + ": " + line
			}
			findings = append(findings, parsedFinding{
				severity:   "Info",
				category:   "port scan",
				confidence: "High",
				finding:    finding,
				evidence:   evidence,
			})
		}
	}
	return findings
}

// --- Nuclei parser ---
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
	Type      string `json:"type"`
}

func parseNucleiOutput(output string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var nr nucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue
		}
		sev := capitalizeFirst(strings.ToLower(nr.Info.Severity))
		if sev == "" {
			sev = "Info"
		}
		category := "nuclei"
		if strings.Contains(strings.ToLower(nr.TemplateID), "cve") {
			category = "cve"
		}
		findings = append(findings, parsedFinding{
			severity:   sev,
			category:   category,
			confidence: "High",
			finding:    fmt.Sprintf("[%s] %s", nr.TemplateID, nr.Info.Name),
			evidence:   fmt.Sprintf("Matched at: %s", nr.MatchedAt),
		})
	}
	return findings
}

// --- Nikto parser ---
func parseNiktoOutput(output string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+ ") {
			continue
		}
		text := strings.TrimPrefix(line, "+ ")
		// Skip informational headers
		if strings.HasPrefix(text, "Target IP:") || strings.HasPrefix(text, "Target Hostname:") ||
			strings.HasPrefix(text, "Target Port:") || strings.HasPrefix(text, "Start Time:") ||
			strings.HasPrefix(text, "End Time:") || strings.HasPrefix(text, "Server:") ||
			strings.Contains(text, "host(s) tested") {
			continue
		}
		sev := "Medium"
		lower := strings.ToLower(text)
		if strings.Contains(lower, "vulnerability") || strings.Contains(lower, "remote code") {
			sev = "High"
		} else if strings.Contains(lower, "outdated") || strings.Contains(lower, "version") {
			sev = "Low"
		}
		findings = append(findings, parsedFinding{
			severity:   sev,
			category:   "nikto",
			confidence: "Medium",
			finding:    text,
			evidence:   line,
		})
	}
	return findings
}

// --- SSLScan parser ---
func parseSSLScanOutput(output string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "sslv2") || strings.Contains(lower, "sslv3") {
			if strings.Contains(lower, "enabled") {
				findings = append(findings, parsedFinding{
					severity: "High", category: "weak cipher", confidence: "High",
					finding: "Deprecated SSL protocol enabled", evidence: line,
				})
			}
		}
		if strings.Contains(lower, "weak") || strings.Contains(lower, "rc4") ||
			strings.Contains(lower, "des-cbc") || strings.Contains(lower, "null") {
			if strings.Contains(lower, "accepted") || strings.Contains(lower, "preferred") {
				findings = append(findings, parsedFinding{
					severity: "Medium", category: "weak cipher", confidence: "High",
					finding: "Weak cipher suite accepted: " + strings.TrimSpace(line), evidence: line,
				})
			}
		}
		if strings.Contains(lower, "expired") {
			findings = append(findings, parsedFinding{
				severity: "High", category: "tls", confidence: "High",
				finding: "Certificate expired", evidence: line,
			})
		}
		if strings.Contains(lower, "self-signed") || strings.Contains(lower, "self signed") {
			findings = append(findings, parsedFinding{
				severity: "Medium", category: "tls", confidence: "High",
				finding: "Self-signed certificate detected", evidence: line,
			})
		}
	}
	return findings
}

// --- WhatWeb parser ---
func parseWhatwebOutput(output string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// WhatWeb default output: URL [STATUS] TECH, TECH, ...
		// Try JSON first
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "{") {
			var records []map[string]interface{}
			if err := json.Unmarshal([]byte(line), &records); err == nil {
				for _, rec := range records {
					if plugins, ok := rec["plugins"].(map[string]interface{}); ok {
						for name := range plugins {
							findings = append(findings, parsedFinding{
								severity: "Info", category: "whatweb", confidence: "High",
								finding:  fmt.Sprintf("Technology detected: %s", name),
								evidence: fmt.Sprintf("WhatWeb: %s", name),
							})
						}
					}
				}
				continue
			}
		}
		// Plain text parsing — extract bracketed items
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		techs := strings.Split(parts[1], ",")
		for _, tech := range techs {
			tech = strings.TrimSpace(tech)
			if tech == "" || strings.HasPrefix(tech, "http") {
				continue
			}
			// Strip brackets
			tech = strings.Trim(tech, "[]")
			findings = append(findings, parsedFinding{
				severity: "Info", category: "whatweb", confidence: "Medium",
				finding:  fmt.Sprintf("Technology detected: %s", tech),
				evidence: line,
			})
		}
	}
	return findings
}

// --- Fierce parser ---
func parseFierceOutput(output string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Fierce outputs discovered hosts as "Found: hostname (IP)"
		if strings.Contains(line, "Found:") || strings.Contains(line, "Nearby:") {
			findings = append(findings, parsedFinding{
				severity: "Info", category: "dns", confidence: "High",
				finding: "DNS discovery: " + line, evidence: line,
			})
		}
		// Also match lines with IP addresses and hostnames
		if matched, _ := regexp.MatchString(`\d+\.\d+\.\d+\.\d+`, line); matched {
			if !strings.HasPrefix(line, "Found:") && !strings.HasPrefix(line, "Nearby:") {
				findings = append(findings, parsedFinding{
					severity: "Info", category: "dns", confidence: "Medium",
					finding: "Host discovered: " + line, evidence: line,
				})
			}
		}
	}
	return findings
}

// --- Wapiti parser ---
func parseWapitiOutput(output string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerability found") || strings.Contains(lower, "flaw found") ||
			strings.Contains(lower, "anomaly found") {
			sev := "Medium"
			category := "wapiti"
			if strings.Contains(lower, "sql") {
				sev = "Critical"
				category = "sqli"
			} else if strings.Contains(lower, "xss") || strings.Contains(lower, "cross-site") {
				sev = "High"
				category = "xss"
			} else if strings.Contains(lower, "ssrf") {
				sev = "High"
				category = "ssrf"
			} else if strings.Contains(lower, "xxe") {
				sev = "High"
				category = "xxe"
			}
			findings = append(findings, parsedFinding{
				severity: sev, category: category, confidence: "High",
				finding: line, evidence: line,
			})
		}
	}
	return findings
}

func parseSQLMapOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "is vulnerable") || strings.Contains(lower, "sql injection") {
			findings = append(findings, parsedFinding{
				severity: "High", category: "sqli", confidence: "High",
				finding: "Potential SQL injection detected", evidence: line,
			})
		}
	}
	return findings
}

func parseFFUFOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "[Status:") || strings.Contains(line, "| URL |") {
			findings = append(findings, parsedFinding{
				severity: "Info", category: "content discovery", confidence: "Medium",
				finding: "Discovered endpoint with ffuf", evidence: line,
			})
		}
	}
	return findings
}

func parseSubfinderOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "dns", confidence: "High",
			finding: "Subdomain discovered: " + line, evidence: line,
		})
	}
	return findings
}

func parseTestSSLOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "not ok") || strings.Contains(lower, "vulnerable") || strings.Contains(lower, "offered") {
			sev := "Medium"
			if strings.Contains(lower, "critical") || strings.Contains(lower, "heartbleed") {
				sev = "High"
			}
			findings = append(findings, parsedFinding{
				severity: sev, category: "tls", confidence: "High",
				finding: "TLS issue detected by testssl", evidence: line,
			})
		}
	}
	return findings
}

func parseDalfoxOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "g]") || strings.Contains(lower, "found xss") || strings.Contains(lower, "vuln") {
			findings = append(findings, parsedFinding{
				severity: "High", category: "xss", confidence: "High",
				finding: "Potential XSS detected by dalfox", evidence: line,
			})
		}
	}
	return findings
}

func parseGobusterOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") || strings.Contains(line, "Status:") || strings.Contains(line, "Found:") {
			findings = append(findings, parsedFinding{
				severity: "Info", category: "content discovery", confidence: "Medium",
				finding: "Path/host discovered by gobuster", evidence: line,
			})
		}
	}
	return findings
}

func parseHTTPXOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "httpx", confidence: "High",
			finding: "HTTP service fingerprint: " + line, evidence: line,
		})
	}
	return findings
}

func parseKiterunnerOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "=>") || strings.Contains(lower, "200") || strings.Contains(lower, "401") || strings.Contains(lower, "403") {
			findings = append(findings, parsedFinding{
				severity: "Info", category: "api discovery", confidence: "Medium",
				finding: "API route discovered by kiterunner", evidence: line,
			})
		}
	}
	return findings
}

func parseAmassOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "dns", confidence: "High",
			finding: "Amass discovered asset: " + line, evidence: line,
		})
	}
	return findings
}

func parseUncoverOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "external exposure", confidence: "Medium",
			finding: "Uncover result: " + line, evidence: line,
		})
	}
	return findings
}

func parseGauOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "url discovery", confidence: "Medium",
			finding: "Historical URL discovered: " + line, evidence: line,
		})
	}
	return findings
}

func parseDNSXOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "dns", confidence: "High",
			finding: "DNS record discovered: " + line, evidence: line,
		})
	}
	return findings
}

func parseAlterxOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "dns permutation", confidence: "Low",
			finding: "Alterx candidate: " + line, evidence: line,
		})
	}
	return findings
}

func parseCRTShOutput(output string) []parsedFinding {
	var findings []parsedFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		findings = append(findings, parsedFinding{
			severity: "Info", category: "certificate transparency", confidence: "High",
			finding: "crt.sh discovered hostname: " + line, evidence: line,
		})
	}
	return findings
}

// --- Generic parser ---
func parseGenericOutput(output, toolName string) []parsedFinding {
	var findings []parsedFinding
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" {
			continue
		}
		if strings.Contains(lower, "vulnerability") || strings.Contains(lower, "warning") ||
			strings.Contains(lower, "issue") || strings.Contains(lower, "risk") {
			findings = append(findings, parsedFinding{
				severity: "Medium", category: toolName, confidence: "Low",
				finding: line, evidence: line,
			})
		}
	}
	return findings
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// StopExecution sends SIGTERM to a running process.
func (s *ToolExecutionService) StopExecution(id uint) error {
	s.mu.Lock()
	cmd, ok := s.processes[id]
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("execution #%d is not running", id)
	}

	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill process: %w", err)
		}
	}

	now := time.Now()
	s.db.Model(&models.ToolExecution{}).Where("id = ?", id).Updates(map[string]any{
		"status":       "stopped",
		"error_msg":    "Stopped by user",
		"completed_at": now,
	})

	return nil
}
