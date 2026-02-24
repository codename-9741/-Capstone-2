package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/database"
	"nightfall-tsukuyomi/internal/models"
	"nightfall-tsukuyomi/internal/services"
)

func main() {
	var (
		scanIDFlag     = flag.Uint("scan-id", 0, "If set, only export this scan ID")
		statusFlag     = flag.String("status", "completed", "Status filter when scan-id is not provided")
		limitFlag      = flag.Int("limit", 20, "Max number of scans to export when no scan-id is provided")
		listConnectors = flag.Bool("list-connectors", false, "List available OpenCTI connectors and exit")
	)

	flag.Parse()

	cfg := database.GetDefaultConfig()
	db, err := database.NewConnection(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	openctiSvc := services.NewOpenCTIService()
	scanSvc := services.NewScanService(db, openctiSvc)

	if *listConnectors {
		connectors, err := openctiSvc.ListConnectors()
		if err != nil {
			log.Fatalf("failed to list connectors: %v", err)
		}

		fmt.Println("OpenCTI connectors (use the STIX import connector ID for imports):")
		fmt.Printf("%-38s %-24s %-18s %-30s %s\n", "ID", "Name", "Type", "Scope", "State")
		for _, c := range connectors {
			scope := "—"
			if len(c.ConnectorScope) > 0 {
				scope = strings.Join(c.ConnectorScope, ",")
			}
			state := "—"
			if c.ConnectorState != nil {
				state = *c.ConnectorState
			}
			fmt.Printf("%-38s %-24s %-18s %-30s %s\n", c.ID, c.Name, c.ConnectorType, scope, state)
		}
		return
	}

	scans, err := listExports(db, *scanIDFlag, *statusFlag, *limitFlag)
	if err != nil {
		log.Fatalf("failed to load scans: %v", err)
	}

	if len(scans) == 0 {
		log.Println("no scans need exporting")
		return
	}

	for _, scan := range scans {
		target := "unknown"
		if scan.Target != nil {
			target = scan.Target.Domain
		}
		log.Printf("Exporting scan #%d (%s) → OpenCTI", scan.ID, target)
		bundleID, err := scanSvc.ExportScanToOpenCTI(scan.ID)
		if err != nil {
			log.Printf("❌ export failed: %v", err)
			continue
		}
		log.Printf("✅ exported bundle %s", bundleID)
	}
}

func listExports(db *gorm.DB, scanID uint, status string, limit int) ([]models.Scan, error) {
	var scans []models.Scan

	query := db.Preload("Target")
	if scanID > 0 {
		if err := query.Where("id = ?", scanID).Find(&scans).Error; err != nil {
			return nil, err
		}
		return scans, nil
	}

	query = query.Where("status = ?", status).
		Where("opencti_export_status IS NULL OR opencti_export_status != 'exported'").
		Order("id ASC").
		Limit(limit)

	if err := query.Find(&scans).Error; err != nil {
		return nil, err
	}

	return scans, nil
}
