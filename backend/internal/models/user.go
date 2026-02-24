package models

import "time"

type User struct {
    ID             uint       `gorm:"primaryKey" json:"id"`
    Email          string     `gorm:"uniqueIndex;not null" json:"email"`
    PasswordHash   string     `gorm:"not null" json:"-"`
    FullName       string     `gorm:"not null" json:"full_name"`
    Role           string     `gorm:"default:analyst" json:"role"`
    OrganizationID *uint      `json:"organization_id,omitempty"`
    IsActive       bool       `gorm:"default:true" json:"is_active"`
    LastLogin      *time.Time `json:"last_login,omitempty"`
    CreatedAt      time.Time  `json:"created_at"`
    UpdatedAt      time.Time  `json:"updated_at"`
}
