package models

import (
	"time"
)

// Target represents a scan target
type Target struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Domain    string    `json:"domain" gorm:"uniqueIndex;not null"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Scans     []Scan    `json:"scans,omitempty" gorm:"foreignKey:TargetID"`
}

// Scan represents a security scan
type Scan struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	TargetID    uint       `json:"target_id" gorm:"index"`
	Target      *Target    `json:"target,omitempty" gorm:"foreignKey:TargetID"`
	Status      string     `json:"status" gorm:"default:'pending'"`
	RiskScore   int        `json:"risk_score" gorm:"default:0"`
	RiskGrade   string     `json:"risk_grade"`
	Config      ScanConfig `json:"config" gorm:"embedded;embeddedPrefix:config_"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Findings    []Finding  `json:"findings,omitempty" gorm:"foreignKey:ScanID"`

	// Execution telemetry (populated by active scanner)
	EnabledModules     int    `json:"enabled_modules" gorm:"default:0"`
	AttemptedModules   int    `json:"attempted_modules" gorm:"default:0"`
	CompletedModules   int    `json:"completed_modules" gorm:"default:0"`
	ErroredModules     int    `json:"errored_modules" gorm:"default:0"`
	SuccessfulRequests int64  `json:"successful_requests" gorm:"default:0"`
	TotalRequests      int64  `json:"total_requests" gorm:"default:0"`
	ErroredRequests    int64  `json:"errored_requests" gorm:"default:0"`
	OpenCTIBundleID    string `json:"opencti_bundle_id"`
	OpenCTIStatus      string `json:"opencti_export_status"`
	OpenCTIError       string `json:"opencti_error"`
}

// ScanConfig holds scan configuration
type ScanConfig struct {
	Mode             string `json:"mode" gorm:"default:'normal'"`
	StealthEnabled   bool   `json:"stealth_enabled" gorm:"default:true"`
	RespectRobotsTxt bool   `json:"respect_robots_txt" gorm:"default:true"`
}

// ScanRequest represents a scan creation request
type ScanRequest struct {
	TargetID         uint     `json:"target_id" binding:"required"`
	Mode             string   `json:"mode"`
	StealthEnabled   bool     `json:"stealth_enabled"`
	RespectRobotsTxt bool     `json:"respect_robots_txt"`
	Modules          []string `json:"modules"`
}

// Finding represents a security finding
type Finding struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	ScanID      uint      `json:"scan_id" gorm:"index"`
	Severity    string    `json:"severity" gorm:"index"`
	Category    string    `json:"category" gorm:"index"`
	Confidence  string    `json:"confidence"`
	Finding     string    `json:"finding"`
	Remediation string    `json:"remediation"`
	Evidence    string    `json:"evidence"`
	HTTPMethod  string    `json:"http_method"`
	Outcome     string    `json:"outcome"`
	CreatedAt   time.Time `json:"created_at"`

	// Tool source
	ToolSource string `json:"tool_source" gorm:"index;default:'native'"`

	// MITRE ATT&CK
	MitreAttackID  string `json:"mitre_attack_id"`
	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`

	// OWASP Top 10
	OwaspCategory string `json:"owasp_category"`
	OwaspName     string `json:"owasp_name"`

	// Kill Chain
	KillChainPhase string `json:"kill_chain_phase"`

	// Cross-tool correlation
	CorrelationID  string `json:"correlation_id" gorm:"index"`
	CorrelatedWith string `json:"correlated_with"`
	ToolCount      int    `json:"tool_count" gorm:"default:1"`
}

// ToolExecution represents a standalone tool execution from the workbench
type ToolExecution struct {
	ID           uint       `json:"id" gorm:"primaryKey"`
	TargetID     uint       `json:"target_id" gorm:"index;default:0"`
	ScanID       uint       `json:"scan_id" gorm:"index;default:0"`
	ToolName     string     `json:"tool_name" gorm:"index"`
	ModuleID     string     `json:"module_id"`
	Target       string     `json:"target"`
	Command      string     `json:"command"`
	CustomArgs   string     `json:"custom_args"`
	RawOutput    string     `json:"raw_output" gorm:"type:text"`
	Status       string     `json:"status" gorm:"index;default:'pending'"`
	ExitCode     int        `json:"exit_code"`
	FindingCount int        `json:"finding_count" gorm:"default:0"`
	ErrorMsg     string     `json:"error_msg"`
	StartedAt    *time.Time `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Subdomain represents discovered subdomains
type Subdomain struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	TargetID     uint      `json:"target_id" gorm:"index"`
	Subdomain    string    `json:"subdomain"`
	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// MitreTTP is a normalized MITRE ATT&CK technique/tactic reference.
type MitreTTP struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	AttackID    string    `json:"attack_id" gorm:"uniqueIndex;not null"`
	Name        string    `json:"name"`
	Tactic      string    `json:"tactic" gorm:"index"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// OwaspCategoryRef is a normalized OWASP Top 10 reference.
type OwaspCategoryRef struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	CategoryID  string    `json:"category_id" gorm:"uniqueIndex;not null"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// KillChainPhaseRef is a normalized cyber kill chain phase reference.
type KillChainPhaseRef struct {
	ID          uint      `json:"id" gorm:"primaryKey"`
	Phase       string    `json:"phase" gorm:"uniqueIndex;not null"`
	SortOrder   int       `json:"sort_order" gorm:"index"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
