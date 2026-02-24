package models

import "time"

// Intelligence stores passive reconnaissance data
type Intelligence struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	ScanID      uint      `json:"scan_id" gorm:"index"`
	Target      string    `json:"target"`
	Subdomains  string    `json:"subdomains" gorm:"type:text"` // JSON array
	DNSRecords  string    `json:"dns_records" gorm:"type:text"` // JSON object
	Technologies string   `json:"technologies" gorm:"type:text"` // JSON array
	RawData     string    `json:"raw_data" gorm:"type:text"` // Full JSON
	CreatedAt   time.Time `json:"created_at"`
}
