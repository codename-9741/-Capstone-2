package main

import (
	"context"
	"log"
	"nightfall-tsukuyomi/internal/api"
	"nightfall-tsukuyomi/internal/database"
	"nightfall-tsukuyomi/internal/models"
	"nightfall-tsukuyomi/internal/services"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	// Connect to database
	dbConfig := database.GetDefaultConfig()
	db, err := database.NewConnection(dbConfig)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	log.Println("✅ Database connected successfully")

	// Ensure columns exist (may be missing from original schema)
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP")

	// Ensure finding enrichment columns exist
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS tool_source VARCHAR(50) DEFAULT 'native'")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS mitre_attack_id VARCHAR(50) DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(100) DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(200) DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS owasp_category VARCHAR(50) DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS owasp_name VARCHAR(200) DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS kill_chain_phase VARCHAR(100) DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(64) DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlated_with TEXT DEFAULT ''")
	db.Exec("ALTER TABLE findings ADD COLUMN IF NOT EXISTS tool_count INTEGER DEFAULT 1")

	// Ensure scan telemetry columns exist
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS enabled_modules INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS attempted_modules INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS completed_modules INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS errored_modules INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS successful_requests BIGINT DEFAULT 0")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS total_requests BIGINT DEFAULT 0")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS errored_requests BIGINT DEFAULT 0")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS risk_grade VARCHAR(10) DEFAULT ''")

	// Ensure tool_executions table columns exist
	db.Exec("CREATE TABLE IF NOT EXISTS tool_executions (id SERIAL PRIMARY KEY)")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS tool_name VARCHAR(50) DEFAULT ''")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS module_id VARCHAR(100) DEFAULT ''")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS target VARCHAR(500) DEFAULT ''")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS command TEXT DEFAULT ''")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS custom_args TEXT DEFAULT ''")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS raw_output TEXT DEFAULT ''")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'pending'")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS exit_code INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS finding_count INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS error_msg TEXT DEFAULT ''")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS started_at TIMESTAMP")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS created_at TIMESTAMP")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS target_id INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE tool_executions ADD COLUMN IF NOT EXISTS scan_id INTEGER DEFAULT 0")

	// Ensure scans table has OpenCTI and risk score columns (fixes 500 error)
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS open_cti_bundle_id TEXT DEFAULT ''")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS open_cti_status VARCHAR(50) DEFAULT ''")        // Fixed column name
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS open_cti_export_status VARCHAR(50) DEFAULT ''") // Keep for safety
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS open_cti_error TEXT DEFAULT ''")
	db.Exec("ALTER TABLE scans ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0")

	// Ensure mitre_ttps table exists (fixes framework service crash)
	db.Exec(`CREATE TABLE IF NOT EXISTS mitre_ttps (
		id SERIAL PRIMARY KEY,
		attack_id TEXT NOT NULL UNIQUE,
		name TEXT,
		tactic TEXT,
		description TEXT,
		url TEXT,
		source TEXT,
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_mitre_ttps_tactic ON mitre_ttps(tactic)")

	// Ensure owasp_category_refs table exists (fixes framework service crash)
	db.Exec(`CREATE TABLE IF NOT EXISTS owasp_category_refs (
		id SERIAL PRIMARY KEY,
		category_id TEXT NOT NULL UNIQUE,
		name TEXT,
		description TEXT,
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	)`)

	// Ensure kill_chain_phase_refs table exists
	db.Exec(`CREATE TABLE IF NOT EXISTS kill_chain_phase_refs (
		id SERIAL PRIMARY KEY,
		phase TEXT NOT NULL UNIQUE,
		sort_order INTEGER,
		description TEXT,
		created_at TIMESTAMP,
		updated_at TIMESTAMP
	)`)

	// Auto-migrate schema (non-fatal — existing DB may have different constraint names)
	if err := db.AutoMigrate(
		&models.Scan{},
		&models.Finding{},
		&models.User{},
		&models.Intelligence{},
		&models.Subdomain{},
		&models.ToolExecution{},
		&models.MitreTTP{},
		&models.OwaspCategoryRef{},
		&models.KillChainPhaseRef{},
	); err != nil {
		log.Printf("⚠️  Auto-migration warning (non-fatal): %v", err)
	} else {
		log.Println("✅ Database schema migrated")
	}

	// Optional framework auto-sync (MITRE/OWASP/Kill Chain + initial remap)
	if v := os.Getenv("FRAMEWORK_AUTO_SYNC"); v == "" || v == "1" || v == "true" || v == "TRUE" {
		fwSvc := services.NewFrameworkService(db)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			summary, err := fwSvc.SyncFrameworkData(ctx, false)
			if err != nil {
				log.Printf("⚠️  Framework auto-sync failed: %v", err)
				return
			}
			log.Printf("✅ Framework sync complete: mitre=%d owasp=%d kill_chain=%d remapped=%d",
				summary.MitreCount, summary.OwaspCount, summary.KillChainCount, summary.Remapped)
		}()
	}

	// DB-centric framework mapper: continuously remap newly stored findings
	// independent of scanner/tool execution paths.
	mapperInterval := 30 * time.Second
	if v := os.Getenv("FRAMEWORK_REMAP_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 {
			mapperInterval = time.Duration(n) * time.Second
		}
	}
	go func() {
		fwSvc := services.NewFrameworkService(db)
		ticker := time.NewTicker(mapperInterval)
		defer ticker.Stop()

		for {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			updated, err := fwSvc.RemapFindings(ctx, nil, nil, true)
			cancel()
			if err != nil {
				log.Printf("⚠️  DB framework remap tick failed: %v", err)
			} else if updated > 0 {
				log.Printf("🧠 DB framework remap updated %d findings", updated)
			}
			<-ticker.C
		}
	}()

	// If the backend restarts while scans are "running", those goroutines are lost.
	// Mark old "running" scans as failed so the UI doesn't remain stuck forever.
	staleMins := 45
	if v := os.Getenv("SCAN_STALE_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			staleMins = n
		}
	}
	cutoff := time.Now().Add(-time.Duration(staleMins) * time.Minute)
	if err := db.Model(&models.Scan{}).
		Where("status = ? AND started_at IS NOT NULL AND started_at < ?", "running", cutoff).
		Updates(map[string]any{
			"status":       "failed",
			"completed_at": time.Now(),
		}).Error; err != nil {
		log.Printf("⚠️  Failed to mark stale running scans as failed: %v", err)
	}

	// Mark stale running tool executions as failed
	if err := db.Model(&models.ToolExecution{}).
		Where("status = ? AND started_at IS NOT NULL AND started_at < ?", "running", cutoff).
		Updates(map[string]any{
			"status":       "failed",
			"error_msg":    "Process lost on backend restart",
			"completed_at": time.Now(),
		}).Error; err != nil {
		log.Printf("⚠️  Failed to mark stale tool executions as failed: %v", err)
	}

	// Create Gin router
	router := gin.Default()

	// Setup all routes
	api.SetupRoutes(router, db)

	// Start server
	log.Println("🌙 NIGHTFALL TSUKUYOMI API starting on port 8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
