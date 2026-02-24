package api

import (
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/api/handlers"
	"nightfall-tsukuyomi/internal/services"
)

func SetupRoutes(router *gin.Engine, db *gorm.DB) {
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "message": "Nightfall Tsukuyomi API"})
	})

	api := router.Group("/api/v1")

	api.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "message": "Nightfall Tsukuyomi API"})
	})

	// Initialize services
	targetService := services.NewTargetService(db)
	openctiService := services.NewOpenCTIService()
	scanService := services.NewScanService(db, openctiService)
	frameworkService := services.NewFrameworkService(db)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "nightfall-secret"
	}
	authService := services.NewAuthService(db, jwtSecret)

	// Initialize handlers
	targetHandler := handlers.NewTargetHandler(targetService)
	scanHandler := handlers.NewScanHandler(scanService)
	passiveHandler := handlers.NewPassiveIntelHandler(db)
	findingsHandler := handlers.NewFindingsHandler(db)
	integrationHandler := handlers.NewIntegrationHandler()
	authHandler := handlers.NewAuthHandler(authService)
	toolHandler := handlers.NewToolHandler(db)
	openbasHandler := handlers.NewOpenBASHandler(db)
	frameworkHandler := handlers.NewFrameworkHandler(frameworkService)

	// Targets
	api.POST("/targets", targetHandler.CreateTarget)
	api.GET("/targets", targetHandler.ListTargets)
	api.GET("/targets/:id", targetHandler.GetTarget)
	api.DELETE("/targets/:id", targetHandler.DeleteTarget)

	// Scans
	api.POST("/scans", scanHandler.CreateScan)
	api.GET("/scans", scanHandler.ListScans)
	api.GET("/scans/:id", scanHandler.GetScan)
	api.GET("/scans/:id/modules", scanHandler.GetModuleStatuses)
	api.POST("/scans/:id/cancel", scanHandler.CancelScan)
	api.POST("/scans/:id/export-opencti", scanHandler.ExportToOpenCTI)

	// Findings
	api.GET("/findings", findingsHandler.ListFindings)
	api.GET("/findings/stats", findingsHandler.GetStats)
	api.GET("/findings/techstack", findingsHandler.GetTechStack)
	api.GET("/findings/by-tool", toolHandler.GetFindingsByTool)
	api.GET("/findings/mitre-matrix", toolHandler.GetMitreMatrix)
	api.GET("/findings/correlations", toolHandler.GetCorrelations)
	api.GET("/findings/:id", findingsHandler.GetFinding)
	api.PUT("/findings/:id", findingsHandler.UpdateFinding)

	// External Tools
	api.GET("/tools/status", toolHandler.GetToolStatus)
	api.POST("/tools/execute", toolHandler.ExecuteTool)
	api.POST("/tools/scan-all", toolHandler.ScanAll)
	api.POST("/tools/scan-custom", toolHandler.ScanCustom)
	api.GET("/tools/executions", toolHandler.ListExecutions)
	api.GET("/tools/executions/:id", toolHandler.GetExecution)
	api.POST("/tools/executions/:id/stop", toolHandler.StopExecution)

	// MITRE ATT&CK Full Matrix
	api.GET("/mitre/matrix", toolHandler.GetMitreFullMatrix)

	// OpenBAS Scenario Creation
	api.POST("/scans/:id/create-scenario", openbasHandler.CreateScenario)

	// Auth
	auth := api.Group("/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/refresh", authHandler.RefreshToken)
		auth.GET("/me", authHandler.GetMe)
	}

	// Passive Intelligence
	api.POST("/intel/passive", passiveHandler.StartPassiveScan)
	api.GET("/intel/passive", passiveHandler.ListPassiveScans)
	api.GET("/intel/passive/:domain", passiveHandler.GetPassiveScan)

	// Integrations — OpenCTI / OpenBAS
	integrations := api.Group("/integrations")
	{
		integrations.GET("/status", integrationHandler.GetIntegrationStatus)
		integrations.GET("/opencti/threats", integrationHandler.GetOpenCTIThreats)
		integrations.GET("/opencti/indicators", integrationHandler.GetOpenCTIIndicators)
		integrations.GET("/openbas/simulations", integrationHandler.GetOpenBASSimulations)
		integrations.GET("/openbas/scenarios", integrationHandler.GetOpenBASScenarios)
	}

	// Framework references + mapping orchestration
	frameworks := api.Group("/frameworks")
	{
		frameworks.GET("/status", frameworkHandler.GetStatus)
		frameworks.POST("/sync", frameworkHandler.Sync)
		frameworks.POST("/remap", frameworkHandler.RemapFindings)
		frameworks.GET("/mitre", frameworkHandler.ListMitreTTPs)
		frameworks.GET("/owasp", frameworkHandler.ListOwasp)
		frameworks.GET("/kill-chain", frameworkHandler.ListKillChain)
	}
}
