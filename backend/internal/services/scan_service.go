package services

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/active"
	"nightfall-tsukuyomi/internal/active/tools"
	"nightfall-tsukuyomi/internal/models"
)

type ScanService struct {
	db      *gorm.DB
	opencti *OpenCTIService
}

func NewScanService(db *gorm.DB, opencti *OpenCTIService) *ScanService {
	return &ScanService{db: db, opencti: opencti}
}

func (s *ScanService) CreateTarget(domain string) (*models.Target, error) {
	var target models.Target
	err := s.db.Where("domain = ?", domain).First(&target).Error

	if err == gorm.ErrRecordNotFound {
		target = models.Target{
			Domain: domain,
		}
		if err := s.db.Create(&target).Error; err != nil {
			return nil, err
		}
		return &target, nil
	}

	if err != nil {
		return nil, err
	}

	return &target, nil
}

func (s *ScanService) CreateScan(targetID uint, mode string, timeoutMinutes int) (*models.Scan, error) {
	var target models.Target
	if err := s.db.First(&target, targetID).Error; err != nil {
		return nil, fmt.Errorf("target not found: %w", err)
	}

	now := time.Now()
	scan := &models.Scan{
		TargetID:  targetID,
		Status:    "running",
		RiskScore: 0,
		Config: models.ScanConfig{
			Mode: mode,
		},
		StartedAt: &now,
	}

	if err := s.db.Create(scan).Error; err != nil {
		return nil, err
	}

	log.Printf("✅ Scan #%d created for %s (mode: %s)", scan.ID, target.Domain, mode)

	go s.executeScan(scan.ID, target.Domain, mode, timeoutMinutes)

	return scan, nil
}

func (s *ScanService) executeScan(scanID uint, domain, mode string, timeoutMinutes int) {
	log.Printf("🌙 Starting scan #%d for %s (mode: %s)", scanID, domain, mode)

	targetURL := domain
	if len(targetURL) < 4 || targetURL[:4] != "http" {
		targetURL = "https://" + targetURL
	}

	var config *active.ScanConfig
	switch mode {
	case "safe":
		config = active.SafeConfig()
	case "aggressive":
		config = active.AggressiveConfig()
	default:
		config = active.DefaultConfig()
	}

	// Register all expected modules in "pending" state so the UI can show the full list.
	moduleIDs := active.AllModuleIDs(mode)
	active.RegisterScanModules(scanID, moduleIDs)
	defer active.ClearScanModules(scanID)

	scanner := active.NewScanner(targetURL, config)
	scanner.SetScanID(scanID)

	// Detect and register external security tools
	adapters := tools.DetectAvailableTools()
	if len(adapters) > 0 {
		scanner.SetExternalAdapters(adapters...)
		log.Printf("🔧 Registered %d external tool adapters", len(adapters))
	}

	log.Printf("🔍 Executing %s scan on %s...", mode, targetURL)

	// Guard against hung modules or network operations. The scanner itself is best-effort;
	// this prevents the UI from being stuck in "running" forever.
	var timeout time.Duration
	if timeoutMinutes > 0 {
		timeout = time.Duration(timeoutMinutes) * time.Minute
	} else {
		switch mode {
		case "safe":
			timeout = 5 * time.Minute
		case "aggressive":
			timeout = 30 * time.Minute
		default:
			timeout = 10 * time.Minute
		}
	}

	resultCh := make(chan *active.ScanResult, 1)
	errCh := make(chan error, 1)
	doneCh := make(chan struct{})
	go func() {
		result, err := scanner.Scan()
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	// Write live module progress to DB every 5 seconds so the UI can show it.
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-doneCh:
				return
			case <-ticker.C:
				attempted, completed, errored, _, enabled, totalReqs, successReqs, errorReqs := scanner.Progress()
				s.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
					"enabled_modules":     enabled,
					"attempted_modules":   attempted,
					"completed_modules":   completed,
					"errored_modules":     errored,
					"total_requests":      totalReqs,
					"successful_requests": successReqs,
					"errored_requests":    errorReqs,
				})
			}
		}
	}()

	var result *active.ScanResult
	select {
	case err := <-errCh:
		close(doneCh)
		log.Printf("❌ Scan #%d failed: %v", scanID, err)
		s.db.Model(&models.Scan{}).Where("id = ?", scanID).Update("status", "failed")
		return
	case result = <-resultCh:
		close(doneCh)
		// continue
	case <-time.After(timeout):
		close(doneCh)
		log.Printf("⏱️  Scan #%d timed out after %s", scanID, timeout)
		s.db.Model(&models.Scan{}).Where("id = ?", scanID).Update("status", "failed")

		_ = s.db.Create(&models.Finding{
			ScanID:      scanID,
			Severity:    "High",
			Category:    "Scan Timeout",
			Confidence:  "High",
			Finding:     "Scan timed out before completion",
			Remediation: "Retry the scan; if this repeats, reduce aggressive modules or increase scan timeout, and check backend logs for the last executed module",
			Evidence:    "timeout=" + timeout.String(),
			HTTPMethod:  "N/A",
			Outcome:     "Failed",
		}).Error
		return
	}

	if result == nil {
		log.Printf("❌ Scan #%d failed: %v", scanID, errors.New("nil scan result"))
		s.db.Model(&models.Scan{}).Where("id = ?", scanID).Update("status", "failed")
		return
	}

	log.Printf("✅ Scan #%d completed with %d findings", scanID, len(result.Findings))

	var scan models.Scan
	s.db.First(&scan, scanID)

	// Save findings with enrichment
	savedCount := 0
	for _, f := range result.Findings {
		// Determine tool source from category/method
		toolSource := "native"
		if f.HTTPMethod == "External Scanner" || f.HTTPMethod == "Nmap External" {
			toolSource = detectToolSource(f.Category, f.Finding)
		}

		// Enrich with MITRE/OWASP/Kill Chain
		enrichment := active.EnrichFinding(f.Category, f.Finding, toolSource)

		// Generate correlation ID
		correlationID := active.GenerateCorrelationID(f.Category, f.Finding, targetURL)

		finding := models.Finding{
			ScanID:         scanID,
			Severity:       f.Severity,
			Category:       f.Category,
			Confidence:     f.Confidence,
			Finding:        f.Finding,
			Remediation:    f.Remediation,
			Evidence:       f.Evidence,
			HTTPMethod:     f.HTTPMethod,
			Outcome:        f.Outcome,
			ToolSource:     toolSource,
			MitreAttackID:  enrichment.MitreAttackID,
			MitreTactic:    enrichment.MitreTactic,
			MitreTechnique: enrichment.MitreTechnique,
			OwaspCategory:  enrichment.OwaspCategory,
			OwaspName:      enrichment.OwaspName,
			KillChainPhase: enrichment.KillChainPhase,
			CorrelationID:  correlationID,
			ToolCount:      1,
		}

		if err := s.db.Create(&finding).Error; err != nil {
			log.Printf("⚠️  Failed to save finding: %v", err)
		} else {
			savedCount++
		}
	}

	// Correlate findings — increment tool_count for duplicates
	s.correlateFindings(scanID)

	log.Printf("💾 Saved %d/%d findings to database", savedCount, len(result.Findings))

	// Calculate risk
	critical := 0
	high := 0
	for _, f := range result.Findings {
		if f.Severity == "Critical" {
			critical++
		} else if f.Severity == "High" {
			high++
		}
	}

	riskScore := critical*10 + high*5
	if riskScore > 100 {
		riskScore = 100
	}

	riskGrade := "LOW"
	if riskScore > 70 {
		riskGrade = "HIGH"
	} else if riskScore > 40 {
		riskGrade = "MEDIUM"
	}

	completedAt := time.Now()

	var targetRecord models.Target
	if err := s.db.First(&targetRecord, scan.TargetID).Error; err != nil {
		log.Printf("⚠️ Failed to load target for opencti export: %v", err)
	}
	var storedFindings []models.Finding
	if err := s.db.Where("scan_id = ?", scanID).Find(&storedFindings).Error; err != nil {
		log.Printf("⚠️ Failed to load stored findings for opencti export: %v", err)
	}

	openctiStatus := "skipped"
	openctiError := ""
	openctiBundleID := ""
	var err error
	if s.opencti != nil {
		openctiBundleID, err = s.opencti.ExportScan(scan, storedFindings, targetRecord)
		if err != nil {
			openctiStatus = "failed"
			openctiError = err.Error()
		} else {
			openctiStatus = "exported"
		}
	}

	s.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
		"status":                "completed",
		"risk_score":            riskScore,
		"risk_grade":            riskGrade,
		"completed_at":          completedAt,
		"enabled_modules":       result.EnabledModules,
		"attempted_modules":     result.AttemptedModules,
		"completed_modules":     result.CompletedModules,
		"errored_modules":       result.ErroredModules,
		"successful_requests":   result.SuccessfulRequests,
		"total_requests":        result.TotalRequests,
		"errored_requests":      result.ErroredRequests,
		"opencti_bundle_id":     openctiBundleID,
		"opencti_export_status": openctiStatus,
		"opencti_error":         openctiError,
	})

	log.Printf("🎉 Scan #%d complete! Risk: %d (%s) | Findings: %d", scanID, riskScore, riskGrade, savedCount)
}

// CancelScan marks a running scan as cancelled.
func (s *ScanService) CancelScan(scanID uint) error {
	now := time.Now()
	result := s.db.Model(&models.Scan{}).
		Where("id = ? AND status = ?", scanID, "running").
		Updates(map[string]interface{}{
			"status":       "cancelled",
			"completed_at": now,
		})
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (s *ScanService) GetScan(scanID uint) (*models.Scan, error) {
	var scan models.Scan
	if err := s.db.Preload("Target").First(&scan, scanID).Error; err != nil {
		return nil, err
	}
	return &scan, nil
}

func (s *ScanService) GetScanWithFindings(scanID uint) (*models.Scan, error) {
	var scan models.Scan
	if err := s.db.Preload("Target").Preload("Findings").First(&scan, scanID).Error; err != nil {
		return nil, err
	}
	return &scan, nil
}

func (s *ScanService) ListScans() ([]models.Scan, error) {
	var scans []models.Scan
	if err := s.db.Preload("Target").Order("id DESC").Find(&scans).Error; err != nil {
		return nil, err
	}
	return scans, nil
}

func (s *ScanService) ExportScanToOpenCTI(scanID uint) (string, error) {
	var scan models.Scan
	if err := s.db.Preload("Target").First(&scan, scanID).Error; err != nil {
		return "", err
	}

	var findings []models.Finding
	if err := s.db.Where("scan_id = ?", scanID).Find(&findings).Error; err != nil {
		return "", err
	}

	if s.opencti == nil {
		return "", errors.New("opencti not configured")
	}

	bundleID, err := s.opencti.ExportScan(scan, findings, *scan.Target)
	if err != nil {
		s.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
			"opencti_export_status": "failed",
			"opencti_error":         err.Error(),
		})
		return "", err
	}

	s.db.Model(&models.Scan{}).Where("id = ?", scanID).Updates(map[string]interface{}{
		"opencti_export_status": "exported",
		"opencti_bundle_id":     bundleID,
		"opencti_error":         "",
	})

	return bundleID, nil
}

// correlateFindings groups findings with the same correlation_id and updates tool_count.
func (s *ScanService) correlateFindings(scanID uint) {
	type corrGroup struct {
		CorrelationID string `json:"correlation_id"`
		Count         int    `json:"count"`
	}
	var groups []corrGroup
	s.db.Model(&models.Finding{}).
		Select("correlation_id, count(*) as count").
		Where("scan_id = ? AND correlation_id != ''", scanID).
		Group("correlation_id").
		Having("count(*) > 1").
		Scan(&groups)

	for _, g := range groups {
		// Get all finding IDs in this group
		var ids []uint
		s.db.Model(&models.Finding{}).
			Where("scan_id = ? AND correlation_id = ?", scanID, g.CorrelationID).
			Pluck("id", &ids)

		// Build correlated_with string
		idStrs := make([]string, len(ids))
		for i, id := range ids {
			idStrs[i] = fmt.Sprintf("%d", id)
		}
		correlated := strings.Join(idStrs, ",")

		// Update all findings in group
		s.db.Model(&models.Finding{}).
			Where("scan_id = ? AND correlation_id = ?", scanID, g.CorrelationID).
			Updates(map[string]interface{}{
				"tool_count":      g.Count,
				"correlated_with": correlated,
			})
	}
}

// detectToolSource infers the tool name from finding category/text.
func detectToolSource(category, finding string) string {
	lower := strings.ToLower(category + " " + finding)
	tools := []string{
		"nmap", "nikto", "nuclei", "wapiti", "sslscan", "whatweb", "fierce", "skipfish",
		"sqlmap", "ffuf", "subfinder", "testssl", "dalfox", "gobuster", "httpx", "kiterunner",
		"amass", "uncover", "gau", "dnsx", "alterx", "crtsh",
	}
	for _, tool := range tools {
		if strings.Contains(lower, tool) {
			if tool == "testssl" {
				return "testssl.sh"
			}
			return tool
		}
	}
	return "native"
}
