package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/active"
	"nightfall-tsukuyomi/internal/active/tools"
	"nightfall-tsukuyomi/internal/models"
	"nightfall-tsukuyomi/internal/services"
)

type ToolHandler struct {
	db      *gorm.DB
	execSvc *services.ToolExecutionService
}

func NewToolHandler(db *gorm.DB) *ToolHandler {
	return &ToolHandler{
		db:      db,
		execSvc: services.NewToolExecutionService(db),
	}
}

// GetToolStatus returns the install/version status of all external security tools.
func (h *ToolHandler) GetToolStatus(c *gin.Context) {
	statuses := tools.GetToolStatus()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    statuses,
	})
}

// GetFindingsByTool returns findings grouped by tool_source.
func (h *ToolHandler) GetFindingsByTool(c *gin.Context) {
	type toolGroup struct {
		ToolSource string `json:"tool_source"`
		Count      int64  `json:"count"`
	}
	var groups []toolGroup
	h.db.Model(&models.Finding{}).
		Select("COALESCE(NULLIF(tool_source, ''), 'native') as tool_source, count(*) as count").
		Group("tool_source").
		Order("count DESC").
		Scan(&groups)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    groups,
	})
}

// GetMitreMatrix returns findings grouped by MITRE tactic and technique.
func (h *ToolHandler) GetMitreMatrix(c *gin.Context) {
	type mitreEntry struct {
		MitreTactic    string `json:"mitre_tactic"`
		MitreTechnique string `json:"mitre_technique"`
		MitreAttackID  string `json:"mitre_attack_id"`
		Count          int64  `json:"count"`
	}
	var entries []mitreEntry
	query := h.db.Model(&models.Finding{}).
		Select("mitre_tactic, mitre_technique, mitre_attack_id, count(*) as count").
		Where("mitre_attack_id != '' AND mitre_attack_id IS NOT NULL")

	if targetID := c.Query("target_id"); targetID != "" {
		query = query.Joins("JOIN scans ON scans.id = findings.scan_id").
			Where("scans.target_id = ?", targetID)
	}

	query.Group("mitre_tactic, mitre_technique, mitre_attack_id").
		Order("count DESC").
		Scan(&entries)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    entries,
	})
}

// GetCorrelations returns correlated finding groups.
func (h *ToolHandler) GetCorrelations(c *gin.Context) {
	type corrGroup struct {
		CorrelationID string `json:"correlation_id"`
		ToolCount     int    `json:"tool_count"`
		Category      string `json:"category"`
		Finding       string `json:"finding"`
		Severity      string `json:"severity"`
	}
	var groups []corrGroup
	h.db.Model(&models.Finding{}).
		Select("correlation_id, MAX(tool_count) as tool_count, category, finding, severity").
		Where("tool_count > 1 AND correlation_id != ''").
		Group("correlation_id, category, finding, severity").
		Order("tool_count DESC").
		Scan(&groups)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    groups,
	})
}

// ExecuteTool starts a standalone tool execution.
func (h *ToolHandler) ExecuteTool(c *gin.Context) {
	var req struct {
		ToolName   string `json:"tool_name" binding:"required"`
		ModuleID   string `json:"module_id" binding:"required"`
		Target     string `json:"target" binding:"required"`
		CustomArgs string `json:"custom_args"`
		TargetID   uint   `json:"target_id"`
		ScanID     uint   `json:"scan_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	execution, err := h.execSvc.ExecuteTool(req.ToolName, req.ModuleID, req.Target, req.CustomArgs, req.TargetID, req.ScanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": execution})
}

// ListExecutions returns all tool executions (optionally filtered by target_id).
func (h *ToolHandler) ListExecutions(c *gin.Context) {
	var targetID uint
	if tid := c.Query("target_id"); tid != "" {
		if v, err := strconv.ParseUint(tid, 10, 64); err == nil {
			targetID = uint(v)
		}
	}
	execs, err := h.execSvc.ListExecutions(targetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": execs})
}

// GetExecution returns a single tool execution by ID.
func (h *ToolHandler) GetExecution(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}

	execution, err := h.execSvc.GetExecution(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "execution not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": execution})
}

// GetMitreFullMatrix returns the complete MITRE ATT&CK TTP reference database.
func (h *ToolHandler) GetMitreFullMatrix(c *gin.Context) {
	matrix := active.GetMitreFullMatrix()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"tactics": active.AllTactics,
		"matrix":  matrix,
		"total":   len(active.FullMitreMatrix),
	})
}

// createBatchScan resolves a target (by id or domain) and creates a shared scan record for a batch run.
func (h *ToolHandler) createBatchScan(targetID uint, targetDomain string) (uint, uint, error) {
	var target models.Target
	if targetID != 0 {
		if err := h.db.First(&target, targetID).Error; err != nil {
			return 0, 0, err
		}
	} else {
		domain := targetDomain
		result := h.db.Where("domain = ?", domain).First(&target)
		if result.Error != nil {
			target = models.Target{Domain: domain}
			if err := h.db.Create(&target).Error; err != nil {
				return 0, 0, err
			}
		}
	}
	now := time.Now()
	scan := models.Scan{
		TargetID:  target.ID,
		Status:    "running",
		Config:    models.ScanConfig{Mode: "tools"},
		StartedAt: &now,
	}
	if err := h.db.Create(&scan).Error; err != nil {
		return 0, 0, err
	}
	return target.ID, scan.ID, nil
}

// ScanAll runs all available tools with all modules against a target.
func (h *ToolHandler) ScanAll(c *gin.Context) {
	var req struct {
		Target   string `json:"target" binding:"required"`
		TargetID uint   `json:"target_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	resolvedTargetID, sharedScanID, err := h.createBatchScan(req.TargetID, req.Target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create batch scan: " + err.Error()})
		return
	}

	allModules := services.GetAllModules()
	var executions []models.ToolExecution
	for _, mod := range allModules {
		exec, err := h.execSvc.ExecuteTool(mod.ToolName, mod.ModuleID, req.Target, "", resolvedTargetID, sharedScanID)
		if err != nil {
			continue
		}
		executions = append(executions, *exec)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    executions,
		"total":   len(executions),
		"scan_id": sharedScanID,
		"message": "All tool executions started",
	})
}

// ScanCustom runs selected tools/modules against a target.
func (h *ToolHandler) ScanCustom(c *gin.Context) {
	var req struct {
		Target   string `json:"target" binding:"required"`
		TargetID uint   `json:"target_id"`
		Modules  []struct {
			ToolName   string `json:"tool_name"`
			ModuleID   string `json:"module_id"`
			CustomArgs string `json:"custom_args"`
		} `json:"modules" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	resolvedTargetID, sharedScanID, err := h.createBatchScan(req.TargetID, req.Target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "failed to create batch scan: " + err.Error()})
		return
	}

	var executions []models.ToolExecution
	for _, mod := range req.Modules {
		exec, err := h.execSvc.ExecuteTool(mod.ToolName, mod.ModuleID, req.Target, mod.CustomArgs, resolvedTargetID, sharedScanID)
		if err != nil {
			continue
		}
		executions = append(executions, *exec)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    executions,
		"total":   len(executions),
		"scan_id": sharedScanID,
	})
}

// StopExecution stops a running tool execution.
func (h *ToolHandler) StopExecution(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "invalid id"})
		return
	}

	if err := h.execSvc.StopExecution(uint(id)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "execution stopped"})
}
