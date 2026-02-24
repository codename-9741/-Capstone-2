package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"nightfall-tsukuyomi/internal/services"
)

type FrameworkHandler struct {
	frameworkSvc *services.FrameworkService
}

func NewFrameworkHandler(frameworkSvc *services.FrameworkService) *FrameworkHandler {
	return &FrameworkHandler{frameworkSvc: frameworkSvc}
}

// Sync ingests MITRE + seeds OWASP/Kill Chain + remaps findings.
// POST /api/v1/frameworks/sync
func (h *FrameworkHandler) Sync(c *gin.Context) {
	var req struct {
		RemapAll bool `json:"remap_all"`
	}
	_ = c.ShouldBindJSON(&req)

	summary, err := h.frameworkSvc.SyncFrameworkData(c.Request.Context(), req.RemapAll)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    summary,
	})
}

// RemapFindings remaps findings for all, target, or scan scope.
// POST /api/v1/frameworks/remap
func (h *FrameworkHandler) RemapFindings(c *gin.Context) {
	var req struct {
		TargetID     *uint `json:"target_id"`
		ScanID       *uint `json:"scan_id"`
		OnlyUnmapped *bool `json:"only_unmapped"`
	}
	_ = c.ShouldBindJSON(&req)

	onlyUnmapped := true
	if req.OnlyUnmapped != nil {
		onlyUnmapped = *req.OnlyUnmapped
	}

	updated, err := h.frameworkSvc.RemapFindings(c.Request.Context(), req.TargetID, req.ScanID, onlyUnmapped)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"updated":       updated,
			"only_unmapped": onlyUnmapped,
		},
	})
}

// GetStatus shows reference dataset counts.
// GET /api/v1/frameworks/status
func (h *FrameworkHandler) GetStatus(c *gin.Context) {
	mitre, err := h.frameworkSvc.ListMitreTTPs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	owasp, err := h.frameworkSvc.ListOwaspCategories()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	kill, err := h.frameworkSvc.ListKillChainPhases()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"mitre_ttps":        len(mitre),
			"owasp_categories":  len(owasp),
			"kill_chain_phases": len(kill),
		},
	})
}

// ListMitreTTPs returns MITRE TTP reference rows.
// GET /api/v1/frameworks/mitre
func (h *FrameworkHandler) ListMitreTTPs(c *gin.Context) {
	ttps, err := h.frameworkSvc.ListMitreTTPs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	limit := 0
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 0 && len(ttps) > limit {
		ttps = ttps[:limit]
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": ttps})
}

// ListOwasp returns OWASP Top 10 references.
// GET /api/v1/frameworks/owasp
func (h *FrameworkHandler) ListOwasp(c *gin.Context) {
	rows, err := h.frameworkSvc.ListOwaspCategories()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rows})
}

// ListKillChain returns kill chain references.
// GET /api/v1/frameworks/kill-chain
func (h *FrameworkHandler) ListKillChain(c *gin.Context) {
	rows, err := h.frameworkSvc.ListKillChainPhases()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rows})
}
