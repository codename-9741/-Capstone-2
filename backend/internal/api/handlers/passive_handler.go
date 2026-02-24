package handlers

import (
	"encoding/json"
	"net/http"
	"time"
	"github.com/gin-gonic/gin"
	"nightfall-tsukuyomi/internal/passive"
	"gorm.io/gorm"
)

type PassiveIntelHandler struct {
	db *gorm.DB
}

func NewPassiveIntelHandler(db *gorm.DB) *PassiveIntelHandler {
	return &PassiveIntelHandler{db: db}
}

type PassiveIntelRecord struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Domain           string    `gorm:"uniqueIndex" json:"domain"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at"`
	DurationSeconds  float64   `json:"duration_seconds"`
	ModulesExecuted  int       `json:"modules_executed"`
	ModulesSucceeded int       `json:"modules_succeeded"`
	ModulesFailed    int       `json:"modules_failed"`
	RawData          []byte    `gorm:"type:jsonb" json:"raw_data"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (PassiveIntelRecord) TableName() string {
	return "passive_intelligence"
}

func (h *PassiveIntelHandler) StartPassiveScan(c *gin.Context) {
	var input struct {
		Domain string `json:"domain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Start scan in goroutine
	go func() {
		config := passive.ScanConfig{
			EnableDNS:         true,
			EnableSocialMedia: true,
			EnableCodeRepos:   true,
			EnableCloudIntel:  true,
			EnableTechStack:   true,
			MaxSubdomains:     100,
		}

		scanner := passive.NewPassiveScanner(input.Domain, config)
		scanner.Run(c.Request.Context())
		results := scanner.GetResults()

		// Calculate duration
		duration := results.CompletedAt.Sub(results.StartedAt).Seconds()

		// Save to database
		rawData, _ := json.Marshal(results)
		
		record := PassiveIntelRecord{
			Domain:           input.Domain,
			StartedAt:        results.StartedAt,
			CompletedAt:      results.CompletedAt,
			DurationSeconds:  duration,
			ModulesExecuted:  results.ModulesExecuted,
			ModulesSucceeded: results.ModulesSucceeded,
			ModulesFailed:    results.ModulesFailed,
			RawData:          rawData,
		}

		h.db.Save(&record)
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Passive reconnaissance scan started",
		"domain":  input.Domain,
	})
}

func (h *PassiveIntelHandler) GetPassiveScan(c *gin.Context) {
	domain := c.Param("domain")

	var record PassiveIntelRecord
	result := h.db.Where("domain = ?", domain).First(&record)

	if result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status": "error",
			"error":  "No passive intelligence data found for this domain",
		})
		return
	}

	// Unmarshal raw data
	var data map[string]interface{}
	json.Unmarshal(record.RawData, &data)

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   data,
	})
}

func (h *PassiveIntelHandler) ListPassiveScans(c *gin.Context) {
	var records []PassiveIntelRecord
	h.db.Order("completed_at DESC").Find(&records)

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"data":   records,
	})
}
