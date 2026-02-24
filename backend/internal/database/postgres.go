package database

import (
	"fmt"
	"log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/models"
)

var DB *gorm.DB

func ConnectPostgres(host string, port int, user, password, dbname string) error {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	log.Println("✅ Connected to PostgreSQL")
	
	// Auto-migrate database schema
	err = DB.AutoMigrate(
		&models.Target{}, 
		&models.Scan{}, 
		&models.Finding{},
		&models.Intelligence{}, // NEW TABLE
	)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}
	
	log.Println("✅ Database schema migrated")
	return nil
}
