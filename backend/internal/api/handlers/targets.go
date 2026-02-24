package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"nightfall-tsukuyomi/internal/services"
)

type TargetHandler struct {
	targetService *services.TargetService
}

func NewTargetHandler(targetService *services.TargetService) *TargetHandler {
	return &TargetHandler{targetService: targetService}
}

func (h *TargetHandler) CreateTarget(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	target, err := h.targetService.CreateTarget(c.Request.Context(), req.Domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, target)
}

func (h *TargetHandler) ListTargets(c *gin.Context) {
	targets, err := h.targetService.ListTargets(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": targets})
}

func (h *TargetHandler) GetTarget(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target ID"})
		return
	}

	target, err := h.targetService.GetTarget(c.Request.Context(), uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}

	c.JSON(http.StatusOK, target)
}

func (h *TargetHandler) DeleteTarget(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target ID"})
		return
	}

	if err := h.targetService.DeleteTarget(c.Request.Context(), uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "target deleted"})
}
