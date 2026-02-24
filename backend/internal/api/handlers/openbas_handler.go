package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/models"
)

type OpenBASHandler struct {
	db *gorm.DB
}

func NewOpenBASHandler(db *gorm.DB) *OpenBASHandler {
	return &OpenBASHandler{db: db}
}

// CreateScenario creates an OpenBAS scenario from scan findings.
func (h *OpenBASHandler) CreateScenario(c *gin.Context) {
	idStr := c.Param("id")
	scanID, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	// Load scan and critical/high findings
	var scan models.Scan
	if err := h.db.Preload("Target").First(&scan, uint(scanID)).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	var findings []models.Finding
	h.db.Where("scan_id = ? AND severity IN ?", scanID, []string{"Critical", "High"}).
		Find(&findings)

	if len(findings) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   "No critical/high findings to create scenario from",
		})
		return
	}

	// Build OpenBAS scenario
	openbasURL := os.Getenv("OPENBAS_URL")
	if openbasURL == "" {
		openbasURL = "http://openaev:8080"
	}
	openbasToken := os.Getenv("OPENBAS_TOKEN")
	if openbasToken == "" {
		openbasToken = "8e2dfb71-51a1-4a19-91e0-f80a91865b29"
	}

	targetDomain := "unknown"
	if scan.Target != nil {
		targetDomain = scan.Target.Domain
	}

	// Build scenario description from findings
	description := fmt.Sprintf("Auto-generated scenario from Nightfall scan #%d against %s.\n\n", scanID, targetDomain)
	description += fmt.Sprintf("Found %d critical/high findings to validate:\n", len(findings))
	for i, f := range findings {
		if i >= 10 {
			description += fmt.Sprintf("... and %d more\n", len(findings)-10)
			break
		}
		description += fmt.Sprintf("- [%s] %s: %s\n", f.Severity, f.Category, f.Finding)
	}

	scenario := map[string]interface{}{
		"scenario_name":        fmt.Sprintf("Nightfall Validation — %s — Scan #%d", targetDomain, scanID),
		"scenario_description": description,
		"scenario_severity":    "critical",
		"scenario_category":    "vulnerability-validation",
		"scenario_main_focus":  "incident-response",
		"scenario_tags":        []string{"nightfall", "automated", targetDomain},
	}

	body, _ := json.Marshal(scenario)
	req, err := http.NewRequest("POST", openbasURL+"/api/scenarios", bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request: " + err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+openbasToken)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"error":   "Failed to connect to OpenBAS: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"error":   fmt.Sprintf("OpenBAS returned %d: %s", resp.StatusCode, string(respBody)),
		})
		return
	}

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"scenario":    result,
		"findings_count": len(findings),
	})
}
