package services

import (
	"context"
	"fmt"

	"nightfall-tsukuyomi/internal/models"
	"gorm.io/gorm"
)

type TargetService struct {
	db *gorm.DB
}

func NewTargetService(db *gorm.DB) *TargetService {
	return &TargetService{db: db}
}

// CreateTarget creates a new target or returns existing one
func (s *TargetService) CreateTarget(ctx context.Context, domain string) (*models.Target, error) {
	// Check if target already exists
	var existing models.Target
	result := s.db.Where("domain = ?", domain).First(&existing)
	
	if result.Error == nil {
		// Target already exists, return it
		return &existing, nil
	}
	
	if result.Error != gorm.ErrRecordNotFound {
		// Some other error occurred
		return nil, fmt.Errorf("failed to check existing target: %w", result.Error)
	}
	
	// Target doesn't exist, create it
	target := &models.Target{
		Domain: domain,
	}
	
	if err := s.db.Create(target).Error; err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}
	
	return target, nil
}

// GetTarget retrieves a target by ID
func (s *TargetService) GetTarget(ctx context.Context, id uint) (*models.Target, error) {
	var target models.Target
	if err := s.db.Preload("Scans").First(&target, id).Error; err != nil {
		return nil, err
	}
	return &target, nil
}

// ListTargets lists all targets
func (s *TargetService) ListTargets(ctx context.Context) ([]models.Target, error) {
	var targets []models.Target
	if err := s.db.Order("created_at DESC").Find(&targets).Error; err != nil {
		return nil, err
	}
	return targets, nil
}

// DeleteTarget deletes a target
func (s *TargetService) DeleteTarget(ctx context.Context, id uint) error {
	return s.db.Delete(&models.Target{}, id).Error
}
