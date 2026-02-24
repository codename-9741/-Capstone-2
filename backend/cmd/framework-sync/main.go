package main

import (
	"context"
	"fmt"
	"time"

	"nightfall-tsukuyomi/internal/database"
	"nightfall-tsukuyomi/internal/models"
	"nightfall-tsukuyomi/internal/services"
)

func main() {
	db, err := database.NewConnection(database.GetDefaultConfig())
	if err != nil {
		panic(err)
	}

	if err := db.AutoMigrate(&models.MitreTTP{}, &models.OwaspCategoryRef{}, &models.KillChainPhaseRef{}); err != nil {
		panic(err)
	}

	svc := services.NewFrameworkService(db)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	summary, err := svc.SyncFrameworkData(ctx, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("sync_done mitre=%d owasp=%d kill_chain=%d remapped=%d\n",
		summary.MitreCount, summary.OwaspCount, summary.KillChainCount, summary.Remapped)
}
