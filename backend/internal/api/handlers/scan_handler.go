package handlers

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"nightfall-tsukuyomi/internal/active"
	"nightfall-tsukuyomi/internal/services"
	"strconv"
)

type ScanHandler struct {
	scanService *services.ScanService
}

func NewScanHandler(scanService *services.ScanService) *ScanHandler {
	return &ScanHandler{scanService: scanService}
}

// CreateScan handles POST /api/v1/scans
func (h *ScanHandler) CreateScan(c *gin.Context) {
	log.Println("🔥 CreateScan endpoint hit!")

	var req struct {
		TargetID       uint   `json:"target_id" binding:"required"`
		ScanType       string `json:"scan_type"`
		TimeoutMinutes int    `json:"timeout_minutes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("❌ Failed to parse request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("📋 Received scan request: target_id=%d, scan_type=%s, timeout=%dm", req.TargetID, req.ScanType, req.TimeoutMinutes)

	if req.ScanType == "" {
		req.ScanType = "full"
	}

	scan, err := h.scanService.CreateScan(req.TargetID, req.ScanType, req.TimeoutMinutes)
	if err != nil {
		log.Printf("❌ Failed to create scan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to start scan: " + err.Error(),
		})
		return
	}

	log.Printf("✅ Scan created successfully: ID=%d", scan.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    scan,
		"message": "Scan started",
	})
}

// GetModuleStatuses handles GET /api/v1/scans/:id/modules
func (h *ScanHandler) GetModuleStatuses(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}
	statuses := active.GetModuleStatuses(uint(id))
	c.JSON(http.StatusOK, gin.H{"success": true, "data": statuses})
}

// GetScan handles GET /api/v1/scans/:id
func (h *ScanHandler) GetScan(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	scan, err := h.scanService.GetScanWithFindings(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": scan})
}

// ListScans handles GET /api/v1/scans
func (h *ScanHandler) ListScans(c *gin.Context) {
	scans, err := h.scanService.ListScans()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scans"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": scans})
}

// CancelScan marks a running scan as cancelled.
func (h *ScanHandler) CancelScan(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}
	if err := h.scanService.CancelScan(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Scan cancelled"})
}

func (h *ScanHandler) ExportToOpenCTI(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid scan ID"})
		return
	}

	bundleID, err := h.scanService.ExportScanToOpenCTI(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"bundle_id": bundleID,
	})
}
