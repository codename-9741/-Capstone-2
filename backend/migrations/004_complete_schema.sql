-- ========================================================================
-- NIGHTFALL TSUKUYOMI - COMPLETE DATABASE SCHEMA
-- Version: 1.0
-- Date: February 5, 2026
-- Description: Complete 52-table schema for security intelligence platform
-- ========================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For fuzzy search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- For multi-column indexes

-- ========================================================================
-- CATEGORY 1: IDENTITY & ACCESS MANAGEMENT (7 tables)
-- ========================================================================

-- Table: users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'analyst', -- admin, analyst, viewer
    organization_id INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: organizations
CREATE TABLE IF NOT EXISTS organizations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    subscription_tier VARCHAR(50) DEFAULT 'free', -- free, pro, enterprise
    max_scans_per_month INTEGER DEFAULT 10,
    max_users INTEGER DEFAULT 5,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: roles
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: permissions
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    resource VARCHAR(100) NOT NULL, -- scans, findings, reports, settings
    action VARCHAR(50) NOT NULL, -- create, read, update, delete
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(role_id, resource, action)
);

-- Table: api_keys
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255),
    permissions JSONB DEFAULT '{}',
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: sessions
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(50),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id INTEGER,
    changes JSONB,
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- CATEGORY 2: ASSET MANAGEMENT (4 tables)
-- ========================================================================

-- Table: targets
CREATE TABLE IF NOT EXISTS targets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    tags TEXT[] DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    last_scanned TIMESTAMP,
    risk_score INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: target_groups
CREATE TABLE IF NOT EXISTS target_groups (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target_ids INTEGER[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: assets
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    asset_type VARCHAR(50) NOT NULL, -- subdomain, ip, port, service, endpoint
    value TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    confidence VARCHAR(50) DEFAULT 'high',
    source VARCHAR(100), -- passive, active, user_provided
    metadata JSONB DEFAULT '{}',
    discovered_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: asset_history
CREATE TABLE IF NOT EXISTS asset_history (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    change_type VARCHAR(50) NOT NULL, -- created, updated, deleted
    old_value JSONB,
    new_value JSONB,
    changed_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- CATEGORY 3: SCANNING & FINDINGS (6 tables)
-- ========================================================================

-- Table: scans
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL, -- passive, active, full
    status VARCHAR(50) DEFAULT 'pending', -- pending, running, completed, failed
    progress INTEGER DEFAULT 0,
    phase VARCHAR(50), -- passive_intel, risk_assessment, active_scan, correlation, reporting
    findings_count INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    risk_grade VARCHAR(10), -- A, B, C, D, F
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    config JSONB DEFAULT '{}',
    results JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: scan_phases
CREATE TABLE IF NOT EXISTS scan_phases (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    phase_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    module_count INTEGER DEFAULT 0,
    completed_modules INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    error_message TEXT,
    metadata JSONB DEFAULT '{}'
);

-- Table: findings
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    
    -- Classification
    severity VARCHAR(50) NOT NULL, -- Critical, High, Medium, Low, Info
    category VARCHAR(100) NOT NULL, -- SQL Injection, XSS, SSRF, Misconfiguration, etc.
    confidence VARCHAR(50) NOT NULL, -- High, Medium, Low
    
    -- Details
    finding TEXT NOT NULL,
    description TEXT,
    remediation TEXT NOT NULL,
    evidence TEXT,
    references TEXT[] DEFAULT '{}',
    
    -- HTTP Details (for web findings)
    affected_url TEXT,
    http_method VARCHAR(20),
    request_headers JSONB,
    request_body TEXT,
    response_status INTEGER,
    response_headers JSONB,
    response_body TEXT,
    outcome VARCHAR(50),
    
    -- Vulnerability Intelligence
    cwe_id VARCHAR(20),
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(255),
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_url TEXT,
    exploit_maturity VARCHAR(50), -- proof_of_concept, functional, high
    
    -- Compliance & Framework Mapping
    owasp_categories TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    pci_dss_requirements TEXT[] DEFAULT '{}',
    iso_controls TEXT[] DEFAULT '{}',
    cis_controls TEXT[] DEFAULT '{}',
    nist_controls TEXT[] DEFAULT '{}',
    
    -- Workflow
    status VARCHAR(50) DEFAULT 'new', -- new, investigating, verified, fixed, closed, false_positive
    assigned_to INTEGER REFERENCES users(id),
    priority INTEGER DEFAULT 0, -- 0=none, 1=low, 2=medium, 3=high, 4=critical
    verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP,
    verified_by INTEGER REFERENCES users(id),
    fixed_at TIMESTAMP,
    false_positive BOOLEAN DEFAULT FALSE,
    false_positive_reason TEXT,
    
    -- Metadata
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: finding_history
CREATE TABLE IF NOT EXISTS finding_history (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    field_name VARCHAR(100) NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_at TIMESTAMP DEFAULT NOW()
);

-- Table: finding_comments
CREATE TABLE IF NOT EXISTS finding_comments (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    comment_text TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: false_positives
CREATE TABLE IF NOT EXISTS false_positives (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- CATEGORY 4: INTELLIGENCE DATA (10 tables)
-- ========================================================================

-- Table: dns_records
CREATE TABLE IF NOT EXISTS dns_records (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    record_type VARCHAR(20) NOT NULL, -- A, AAAA, MX, TXT, NS, CNAME, etc.
    name VARCHAR(255) NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    discovered_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW()
);

-- Table: subdomains
CREATE TABLE IF NOT EXISTS subdomains (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    subdomain VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50),
    status VARCHAR(50) DEFAULT 'active', -- active, inactive, wildcard
    source VARCHAR(100), -- crt.sh, dnsdumpster, brute_force, passive
    technologies TEXT[] DEFAULT '{}',
    http_status INTEGER,
    title TEXT,
    discovered_at TIMESTAMP DEFAULT NOW(),
    last_checked TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Table: ssl_certificates
CREATE TABLE IF NOT EXISTS ssl_certificates (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    common_name VARCHAR(255),
    subject_alt_names TEXT[] DEFAULT '{}',
    issuer VARCHAR(255),
    serial_number VARCHAR(255),
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    signature_algorithm VARCHAR(100),
    key_size INTEGER,
    is_expired BOOLEAN DEFAULT FALSE,
    is_self_signed BOOLEAN DEFAULT FALSE,
    certificate_pem TEXT,
    discovered_at TIMESTAMP DEFAULT NOW()
);

-- Table: whois_records
CREATE TABLE IF NOT EXISTS whois_records (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    registrar VARCHAR(255),
    registered_date TIMESTAMP,
    expiration_date TIMESTAMP,
    updated_date TIMESTAMP,
    name_servers TEXT[] DEFAULT '{}',
    registrant_name VARCHAR(255),
    registrant_email VARCHAR(255),
    registrant_organization VARCHAR(255),
    admin_email VARCHAR(255),
    tech_email VARCHAR(255),
    status TEXT[] DEFAULT '{}',
    raw_data TEXT,
    discovered_at TIMESTAMP DEFAULT NOW()
);

-- Table: technologies
CREATE TABLE IF NOT EXISTS technologies (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    category VARCHAR(100), -- web_server, framework, cms, cdn, etc.
    confidence VARCHAR(50) DEFAULT 'high',
    source VARCHAR(100),
    discovered_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Table: cloud_resources
CREATE TABLE IF NOT EXISTS cloud_resources (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- aws, azure, gcp, cloudflare
    resource_type VARCHAR(100) NOT NULL, -- s3_bucket, azure_blob, gcp_storage
    resource_name TEXT NOT NULL,
    is_public BOOLEAN DEFAULT FALSE,
    url TEXT,
    discovered_at TIMESTAMP DEFAULT NOW(),
    last_checked TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Table: code_repositories
CREATE TABLE IF NOT EXISTS code_repositories (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    platform VARCHAR(50) NOT NULL, -- github, gitlab, bitbucket
    repository_url TEXT NOT NULL,
    repository_name VARCHAR(255),
    is_public BOOLEAN DEFAULT TRUE,
    stars INTEGER,
    forks INTEGER,
    last_commit TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Table: secrets
CREATE TABLE IF NOT EXISTS secrets (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    secret_type VARCHAR(100) NOT NULL, -- api_key, password, token, certificate
    pattern_matched VARCHAR(255),
    location TEXT, -- file path, URL, repository
    masked_value TEXT, -- partially masked for display
    is_verified BOOLEAN DEFAULT FALSE,
    severity VARCHAR(50) DEFAULT 'High',
    discovered_at TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Table: breaches
CREATE TABLE IF NOT EXISTS breaches (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    breach_name VARCHAR(255) NOT NULL,
    breach_date TIMESTAMP,
    compromised_accounts INTEGER,
    compromised_data TEXT[] DEFAULT '{}', -- emails, passwords, names, etc.
    source VARCHAR(100), -- haveibeenpwned, dehashed, etc.
    discovered_at TIMESTAMP DEFAULT NOW()
);

-- Table: threat_indicators
CREATE TABLE IF NOT EXISTS threat_indicators (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    indicator_type VARCHAR(50) NOT NULL, -- ip, domain, hash, url
    indicator_value TEXT NOT NULL,
    threat_type VARCHAR(100), -- malware, phishing, c2, etc.
    confidence VARCHAR(50) DEFAULT 'medium',
    source VARCHAR(100), -- alienvault, virustotal, etc.
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    metadata JSONB DEFAULT '{}'
);

-- ========================================================================
-- CATEGORY 5: CORRELATION & MAPPING (9 tables)
-- ========================================================================

-- Table: cves
CREATE TABLE IF NOT EXISTS cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    published_date TIMESTAMP,
    last_modified TIMESTAMP,
    cvss_v2_score DECIMAL(3,1),
    cvss_v2_vector VARCHAR(255),
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(255),
    severity VARCHAR(50),
    cwe_ids TEXT[] DEFAULT '{}',
    references TEXT[] DEFAULT '{}',
    affected_products JSONB DEFAULT '{}',
    exploit_available BOOLEAN DEFAULT FALSE,
    epss_score DECIMAL(5,4), -- Exploit Prediction Scoring System
    metadata JSONB DEFAULT '{}'
);

-- Table: cve_mappings
CREATE TABLE IF NOT EXISTS cve_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    cve_id VARCHAR(20) REFERENCES cves(cve_id) ON DELETE CASCADE,
    confidence VARCHAR(50) DEFAULT 'high',
    matched_by VARCHAR(100), -- technology_version, port_service, signature
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: exploits
CREATE TABLE IF NOT EXISTS exploits (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) REFERENCES cves(cve_id) ON DELETE CASCADE,
    exploit_db_id INTEGER,
    exploit_title VARCHAR(255),
    exploit_author VARCHAR(255),
    exploit_type VARCHAR(100), -- remote, local, webapps, dos
    platform VARCHAR(100),
    exploit_url TEXT,
    metasploit_module TEXT,
    published_date TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'
);

-- Table: owasp_mappings
CREATE TABLE IF NOT EXISTS owasp_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    owasp_id VARCHAR(10) NOT NULL, -- A01, A02, etc.
    owasp_category VARCHAR(255) NOT NULL,
    owasp_year INTEGER DEFAULT 2021,
    confidence VARCHAR(50) DEFAULT 'high',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: mitre_mappings
CREATE TABLE IF NOT EXISTS mitre_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    technique_id VARCHAR(20) NOT NULL, -- T1190, T1078, etc.
    technique_name VARCHAR(255) NOT NULL,
    tactic VARCHAR(100), -- Initial Access, Execution, etc.
    sub_technique_id VARCHAR(20),
    confidence VARCHAR(50) DEFAULT 'medium',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: cis_mappings
CREATE TABLE IF NOT EXISTS cis_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    control_id VARCHAR(20) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    control_version VARCHAR(20) DEFAULT 'v8',
    implementation_group INTEGER, -- 1, 2, or 3
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: nist_mappings
CREATE TABLE IF NOT EXISTS nist_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    control_family VARCHAR(10) NOT NULL, -- AC, AU, SC, etc.
    control_id VARCHAR(20) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    framework VARCHAR(50) DEFAULT '800-53', -- 800-53, CSF
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: pci_dss_mappings
CREATE TABLE IF NOT EXISTS pci_dss_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    requirement_id VARCHAR(20) NOT NULL,
    requirement_name VARCHAR(255) NOT NULL,
    version VARCHAR(20) DEFAULT '4.0',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: iso_mappings
CREATE TABLE IF NOT EXISTS iso_mappings (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    control_id VARCHAR(20) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    standard VARCHAR(50) DEFAULT '27001:2022',
    annex VARCHAR(10),
    created_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- CATEGORY 6: ATTACK INTELLIGENCE (5 tables)
-- ========================================================================

-- Table: attack_paths
CREATE TABLE IF NOT EXISTS attack_paths (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    path_name VARCHAR(255) NOT NULL,
    entry_point TEXT NOT NULL,
    steps JSONB NOT NULL, -- Array of attack steps
    impact TEXT NOT NULL,
    likelihood VARCHAR(50), -- very_low, low, medium, high, very_high
    risk_score INTEGER,
    findings_involved INTEGER[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: attack_scenarios
CREATE TABLE IF NOT EXISTS attack_scenarios (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    scenario_name VARCHAR(255) NOT NULL,
    description TEXT,
    attacker_profile VARCHAR(100), -- script_kiddie, professional, nation_state
    required_skills VARCHAR(50), -- low, medium, high
    required_resources VARCHAR(50), -- minimal, moderate, significant
    attack_vector VARCHAR(100),
    impact_confidentiality VARCHAR(50),
    impact_integrity VARCHAR(50),
    impact_availability VARCHAR(50),
    overall_risk VARCHAR(50),
    mitigation_steps TEXT[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: kill_chain_phases
CREATE TABLE IF NOT EXISTS kill_chain_phases (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    phase VARCHAR(100) NOT NULL, -- Reconnaissance, Weaponization, Delivery, etc.
    phase_order INTEGER,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: attack_techniques
CREATE TABLE IF NOT EXISTS attack_techniques (
    id SERIAL PRIMARY KEY,
    technique_id VARCHAR(20) UNIQUE NOT NULL,
    technique_name VARCHAR(255) NOT NULL,
    description TEXT,
    platforms TEXT[] DEFAULT '{}',
    required_permissions TEXT[] DEFAULT '{}',
    data_sources TEXT[] DEFAULT '{}',
    detection_methods TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}'
);

-- Table: impact_assessments
CREATE TABLE IF NOT EXISTS impact_assessments (
    id SERIAL PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    business_impact TEXT,
    technical_impact TEXT,
    financial_impact TEXT,
    regulatory_impact TEXT,
    reputation_impact TEXT,
    likelihood_score INTEGER, -- 1-5
    impact_score INTEGER, -- 1-5
    overall_risk_score INTEGER, -- likelihood * impact
    created_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- CATEGORY 7: REPORTING & ANALYTICS (6 tables)
-- ========================================================================

-- Table: reports
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL, -- executive, technical, compliance
    format VARCHAR(20) NOT NULL, -- pdf, html, json, docx
    title VARCHAR(255) NOT NULL,
    generated_at TIMESTAMP DEFAULT NOW(),
    file_path TEXT,
    file_size INTEGER,
    metadata JSONB DEFAULT '{}'
);

-- Table: report_templates
CREATE TABLE IF NOT EXISTS report_templates (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    template_type VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    variables JSONB DEFAULT '{}',
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: dashboards
CREATE TABLE IF NOT EXISTS dashboards (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    layout JSONB NOT NULL, -- Widget positions and configurations
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: metrics
CREATE TABLE IF NOT EXISTS metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,2) NOT NULL,
    metric_type VARCHAR(50), -- count, percentage, score, duration
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Table: trends
CREATE TABLE IF NOT EXISTS trends (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    metric_name VARCHAR(100) NOT NULL,
    time_period VARCHAR(50) NOT NULL, -- daily, weekly, monthly
    data_points JSONB NOT NULL, -- Time series data
    calculated_at TIMESTAMP DEFAULT NOW()
);

-- Table: benchmarks
CREATE TABLE IF NOT EXISTS benchmarks (
    id SERIAL PRIMARY KEY,
    industry VARCHAR(100) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    average_value DECIMAL(10,2),
    median_value DECIMAL(10,2),
    percentile_75 DECIMAL(10,2),
    percentile_90 DECIMAL(10,2),
    sample_size INTEGER,
    period VARCHAR(50),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- CATEGORY 8: INTEGRATIONS (3 tables)
-- ========================================================================

-- Table: integrations
CREATE TABLE IF NOT EXISTS integrations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
    integration_type VARCHAR(50) NOT NULL, -- jira, slack, siem, webhook
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL, -- API keys, URLs, etc. (encrypted)
    is_active BOOLEAN DEFAULT TRUE,
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: webhooks
CREATE TABLE IF NOT EXISTS webhooks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    event_types TEXT[] DEFAULT '{}', -- scan.completed, finding.created, etc.
    secret_key VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Table: api_calls
CREATE TABLE IF NOT EXISTS api_calls (
    id SERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE CASCADE,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER,
    response_time INTEGER, -- milliseconds
    request_body JSONB,
    response_body JSONB,
    ip_address VARCHAR(50),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- CATEGORY 9: AUTOMATION (2 tables)
-- ========================================================================

-- Table: scheduled_scans
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    schedule_name VARCHAR(255) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL, -- 0 0 * * * (daily at midnight)
    scan_config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Table: notifications
CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    notification_type VARCHAR(50) NOT NULL, -- finding, scan_complete, error
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(50) DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    related_resource_type VARCHAR(50), -- scan, finding, target
    related_resource_id INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ========================================================================
-- INDEXES FOR PERFORMANCE
-- ========================================================================

-- Users & Auth
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- Assets
CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain);
CREATE INDEX IF NOT EXISTS idx_targets_user ON targets(user_id);
CREATE INDEX IF NOT EXISTS idx_targets_organization ON targets(organization_id);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);

-- Scans
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scan_phases_scan ON scan_phases(scan_id);

-- Findings (CRITICAL FOR PERFORMANCE)
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_assigned ON findings(assigned_to);
CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(verified);
CREATE INDEX IF NOT EXISTS idx_findings_false_positive ON findings(false_positive);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_cvss ON findings(cvss_score);
CREATE INDEX IF NOT EXISTS idx_finding_comments_finding ON finding_comments(finding_id);

-- Intelligence Data
CREATE INDEX IF NOT EXISTS idx_dns_records_target ON dns_records(target_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_subdomain ON subdomains(subdomain);
CREATE INDEX IF NOT EXISTS idx_ssl_certificates_target ON ssl_certificates(target_id);
CREATE INDEX IF NOT EXISTS idx_technologies_target ON technologies(target_id);
CREATE INDEX IF NOT EXISTS idx_technologies_name ON technologies(name);
CREATE INDEX IF NOT EXISTS idx_cloud_resources_target ON cloud_resources(target_id);
CREATE INDEX IF NOT EXISTS idx_secrets_target ON secrets(target_id);

-- CVE & Correlation
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cve_mappings_finding ON cve_mappings(finding_id);
CREATE INDEX IF NOT EXISTS idx_cve_mappings_cve ON cve_mappings(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_owasp_mappings_finding ON owasp_mappings(finding_id);
CREATE INDEX IF NOT EXISTS idx_mitre_mappings_finding ON mitre_mappings(finding_id);

-- Integrations
CREATE INDEX IF NOT EXISTS idx_integrations_user ON integrations(user_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);
CREATE INDEX IF NOT EXISTS idx_api_calls_key ON api_calls(api_key_id);
CREATE INDEX IF NOT EXISTS idx_api_calls_created ON api_calls(created_at);

-- Automation
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_user ON scheduled_scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(is_read);

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_findings_finding_trgm ON findings USING gin(finding gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_findings_description_trgm ON findings USING gin(description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_cves_description_trgm ON cves USING gin(description gin_trgm_ops);

-- ========================================================================
-- TRIGGERS FOR AUTO-UPDATING TIMESTAMPS
-- ========================================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to tables with updated_at column
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_targets_updated_at BEFORE UPDATE ON targets FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_target_groups_updated_at BEFORE UPDATE ON target_groups FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_findings_updated_at BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_finding_comments_updated_at BEFORE UPDATE ON finding_comments FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_report_templates_updated_at BEFORE UPDATE ON report_templates FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_dashboards_updated_at BEFORE UPDATE ON dashboards FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_integrations_updated_at BEFORE UPDATE ON integrations FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER update_scheduled_scans_updated_at BEFORE UPDATE ON scheduled_scans FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ========================================================================
-- INITIAL SEED DATA
-- ========================================================================

-- Insert default roles
INSERT INTO roles (name, description, permissions) VALUES
('admin', 'Full system access', '{"all": ["*"]}'::jsonb),
('analyst', 'Can create scans and manage findings', '{"scans": ["create", "read", "update"], "findings": ["create", "read", "update"], "reports": ["create", "read"]}'::jsonb),
('viewer', 'Read-only access', '{"scans": ["read"], "findings": ["read"], "reports": ["read"]}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Insert default organization
INSERT INTO organizations (name, domain, subscription_tier) VALUES
('Default Organization', 'localhost', 'pro')
ON CONFLICT DO NOTHING;

-- ========================================================================
-- VIEWS FOR COMMON QUERIES
-- ========================================================================

-- View: Active findings summary
CREATE OR REPLACE VIEW active_findings_summary AS
SELECT 
    f.severity,
    f.category,
    COUNT(*) as count,
    AVG(f.cvss_score) as avg_cvss,
    t.domain
FROM findings f
JOIN targets t ON f.target_id = t.id
WHERE f.status NOT IN ('closed', 'false_positive')
GROUP BY f.severity, f.category, t.domain;

-- View: Target risk dashboard
CREATE OR REPLACE VIEW target_risk_dashboard AS
SELECT 
    t.id,
    t.domain,
    t.risk_score,
    COUNT(DISTINCT s.id) as total_scans,
    COUNT(DISTINCT f.id) as total_findings,
    COUNT(DISTINCT CASE WHEN f.severity = 'Critical' THEN f.id END) as critical_findings,
    COUNT(DISTINCT CASE WHEN f.severity = 'High' THEN f.id END) as high_findings,
    MAX(s.completed_at) as last_scan
FROM targets t
LEFT JOIN scans s ON t.id = s.target_id
LEFT JOIN findings f ON s.id = f.scan_id
GROUP BY t.id, t.domain, t.risk_score;

-- View: Recent activity feed
CREATE OR REPLACE VIEW recent_activity AS
SELECT 
    'scan' as activity_type,
    s.id as resource_id,
    s.status,
    t.domain as target,
    u.full_name as user_name,
    s.created_at as timestamp
FROM scans s
JOIN targets t ON s.target_id = t.id
JOIN users u ON s.user_id = u.id
UNION ALL
SELECT 
    'finding' as activity_type,
    f.id as resource_id,
    f.status,
    t.domain as target,
    u.full_name as user_name,
    f.created_at as timestamp
FROM findings f
JOIN targets t ON f.target_id = t.id
JOIN scans s ON f.scan_id = s.id
JOIN users u ON s.user_id = u.id
ORDER BY timestamp DESC
LIMIT 50;

-- ========================================================================
-- COMPLETION MESSAGE
-- ========================================================================

DO $$
BEGIN
    RAISE NOTICE '========================================================================';
    RAISE NOTICE 'NIGHTFALL TSUKUYOMI DATABASE SCHEMA CREATED SUCCESSFULLY';
    RAISE NOTICE '========================================================================';
    RAISE NOTICE 'Total Tables Created: 52';
    RAISE NOTICE 'Total Indexes Created: 50+';
    RAISE NOTICE 'Total Views Created: 3';
    RAISE NOTICE 'Total Triggers Created: 12';
    RAISE NOTICE '';
    RAISE NOTICE 'Category Breakdown:';
    RAISE NOTICE '  - Identity & Access: 7 tables';
    RAISE NOTICE '  - Asset Management: 4 tables';
    RAISE NOTICE '  - Scanning & Findings: 6 tables';
    RAISE NOTICE '  - Intelligence Data: 10 tables';
    RAISE NOTICE '  - Correlation & Mapping: 9 tables';
    RAISE NOTICE '  - Attack Intelligence: 5 tables';
    RAISE NOTICE '  - Reporting & Analytics: 6 tables';
    RAISE NOTICE '  - Integrations: 3 tables';
    RAISE NOTICE '  - Automation: 2 tables';
    RAISE NOTICE '';
    RAISE NOTICE 'Next Steps:';
    RAISE NOTICE '  1. Create default admin user';
    RAISE NOTICE '  2. Implement Go models for each table';
    RAISE NOTICE '  3. Build API endpoints for findings workflow';
    RAISE NOTICE '  4. Create frontend components';
    RAISE NOTICE '========================================================================';
END $$;
