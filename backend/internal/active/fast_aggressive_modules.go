package active

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
)

type fastAggressiveModuleSpec struct {
	ID          string
	Path        string
	Method      string
	Category    string
	Severity    string
	Title       string
	Remediation string
	Statuses    []int
	Indicators  []string
}

func fastAggressiveModuleIDs() []string {
	specs := fastAggressiveModuleSpecs()
	ids := make([]string, 0, len(specs))
	for _, spec := range specs {
		ids = append(ids, spec.ID)
	}
	return ids
}

func fastAggressiveModuleSpecs() []fastAggressiveModuleSpec {
	type pathDef struct {
		path       string
		title      string
		indicators []string
	}

	files := []pathDef{
		{"/.env", "Environment file exposed", []string{"db_password", "secret", "api_key", "token"}},
		{"/.env.production", "Production environment file exposed", []string{"secret", "database_url", "api_key"}},
		{"/.env.local", "Local environment file exposed", []string{"secret", "token", "password"}},
		{"/.git/config", "Git configuration exposed", []string{"[core]", "repositoryformatversion"}},
		{"/.git/HEAD", "Git HEAD file exposed", []string{"refs/heads"}},
		{"/.svn/entries", "SVN metadata exposed", []string{"dir", "svn"}},
		{"/.hg/hgrc", "Mercurial configuration exposed", []string{"[paths]", "default"}},
		{"/backup.sql", "SQL backup exposed", []string{"create table", "insert into", "database"}},
		{"/dump.sql", "Database dump exposed", []string{"create table", "insert into", "database"}},
		{"/database.sql", "Database SQL file exposed", []string{"create table", "insert into", "database"}},
		{"/backup.zip", "Backup archive exposed", nil},
		{"/site-backup.zip", "Site backup archive exposed", nil},
		{"/db-backup.zip", "Database backup archive exposed", nil},
		{"/config.php", "Config file exposed", []string{"db_name", "db_user", "password"}},
		{"/config.php.bak", "Config backup file exposed", []string{"db_name", "db_user", "password"}},
		{"/wp-config.php.bak", "WordPress config backup exposed", []string{"db_name", "db_password"}},
		{"/composer.json", "Composer manifest exposed", []string{"require", "autoload"}},
		{"/composer.lock", "Composer lockfile exposed", []string{"packages", "name"}},
		{"/package-lock.json", "NPM lockfile exposed", []string{"dependencies", "version"}},
		{"/yarn.lock", "Yarn lockfile exposed", []string{"version"}},
		{"/requirements.txt", "Python requirements exposed", []string{"==", ">="}},
		{"/Pipfile", "Pipfile exposed", []string{"[packages]", "[requires]"}},
		{"/Gemfile", "Ruby Gemfile exposed", []string{"source", "gem"}},
		{"/id_rsa", "Private SSH key file exposed", []string{"begin rsa private key"}},
		{"/id_ed25519", "Private Ed25519 key file exposed", []string{"begin openssh private key"}},
		{"/.aws/credentials", "AWS credentials file exposed", []string{"aws_access_key_id", "aws_secret_access_key"}},
		{"/.docker/config.json", "Docker config file exposed", []string{"auths"}},
		{"/web.config", "Web server config exposed", []string{"configuration", "system.webserver"}},
		{"/phpinfo.php", "phpinfo endpoint exposed", []string{"php version", "phpinfo()"}},
		{"/server-status", "Server status endpoint exposed", []string{"server uptime", "apache"}},
	}

	admin := []pathDef{
		{"/admin", "Admin panel endpoint exposed", nil},
		{"/admin/login", "Admin login endpoint exposed", nil},
		{"/administrator", "Administrator endpoint exposed", nil},
		{"/dashboard", "Dashboard endpoint exposed", nil},
		{"/console", "Console endpoint exposed", nil},
		{"/manage", "Management endpoint exposed", nil},
		{"/manager", "Manager endpoint exposed", nil},
		{"/controlpanel", "Control panel endpoint exposed", nil},
		{"/cpanel", "cPanel endpoint exposed", nil},
		{"/backend", "Backend endpoint exposed", nil},
		{"/internal", "Internal endpoint exposed", nil},
		{"/staff", "Staff endpoint exposed", nil},
		{"/support/admin", "Support admin endpoint exposed", nil},
		{"/ops", "Operations endpoint exposed", nil},
		{"/superadmin", "Superadmin endpoint exposed", nil},
		{"/root", "Root endpoint exposed", nil},
		{"/private", "Private endpoint exposed", nil},
		{"/debug", "Debug endpoint exposed", nil},
		{"/trace", "Trace endpoint exposed", nil},
		{"/actuator", "Actuator endpoint exposed", nil},
		{"/actuator/health", "Actuator health endpoint exposed", nil},
		{"/actuator/env", "Actuator env endpoint exposed", nil},
		{"/jmx-console", "JMX console exposed", nil},
		{"/web-console", "Web console endpoint exposed", nil},
		{"/phpmyadmin", "phpMyAdmin endpoint exposed", nil},
	}

	api := []pathDef{
		{"/api", "API root endpoint exposed", nil},
		{"/api/v1", "API v1 endpoint exposed", nil},
		{"/api/v2", "API v2 endpoint exposed", nil},
		{"/api/docs", "API docs endpoint exposed", nil},
		{"/api/swagger", "API swagger endpoint exposed", nil},
		{"/swagger", "Swagger endpoint exposed", nil},
		{"/swagger-ui", "Swagger UI endpoint exposed", nil},
		{"/swagger-ui.html", "Swagger UI HTML endpoint exposed", nil},
		{"/openapi.json", "OpenAPI spec exposed", nil},
		{"/v3/api-docs", "Spring API docs endpoint exposed", nil},
		{"/graphql", "GraphQL endpoint exposed", nil},
		{"/graphiql", "GraphiQL endpoint exposed", nil},
		{"/.well-known/openid-configuration", "OIDC configuration endpoint exposed", nil},
		{"/.well-known/security.txt", "Security.txt endpoint exposed", nil},
		{"/metrics", "Metrics endpoint exposed", nil},
		{"/prometheus", "Prometheus endpoint exposed", nil},
		{"/status", "Status endpoint exposed", nil},
		{"/health", "Health endpoint exposed", nil},
		{"/readyz", "Readiness endpoint exposed", nil},
		{"/livez", "Liveness endpoint exposed", nil},
	}

	cloud := []pathDef{
		{"/latest/meta-data/", "Cloud instance metadata endpoint exposed", nil},
		{"/latest/user-data", "Cloud user-data endpoint exposed", nil},
		{"/latest/meta-data/iam/security-credentials/", "Cloud IAM metadata endpoint exposed", nil},
		{"/computeMetadata/v1/", "GCP metadata endpoint exposed", nil},
		{"/metadata/instance", "Azure metadata endpoint exposed", nil},
		{"/k8s", "Kubernetes endpoint exposed", nil},
		{"/kubernetes", "Kubernetes endpoint exposed", nil},
		{"/api/v1/namespaces", "Kubernetes namespace API exposed", nil},
		{"/version", "Infrastructure version endpoint exposed", nil},
		{"/docker", "Docker endpoint exposed", nil},
		{"/containers/json", "Docker containers endpoint exposed", nil},
		{"/images/json", "Docker images endpoint exposed", nil},
		{"/env", "Environment dump endpoint exposed", nil},
		{"/config", "Runtime configuration endpoint exposed", nil},
		{"/secrets", "Secrets endpoint exposed", nil},
	}

	auth := []pathDef{
		{"/login", "Login endpoint exposed", nil},
		{"/signin", "Sign-in endpoint exposed", nil},
		{"/auth", "Auth endpoint exposed", nil},
		{"/oauth/token", "OAuth token endpoint exposed", nil},
		{"/oauth/authorize", "OAuth authorize endpoint exposed", nil},
		{"/api/auth/login", "API auth login endpoint exposed", nil},
		{"/api/token", "API token endpoint exposed", nil},
		{"/password/reset", "Password reset endpoint exposed", nil},
		{"/forgot-password", "Forgot-password endpoint exposed", nil},
		{"/register", "Register endpoint exposed", nil},
	}

	specs := make([]fastAggressiveModuleSpec, 0, 100)
	addGroup := func(prefix, category, severity, remediation string, statuses []int, defs []pathDef) {
		for i, d := range defs {
			specs = append(specs, fastAggressiveModuleSpec{
				ID:          fmt.Sprintf("%s_%03d", prefix, i+1),
				Path:        d.path,
				Method:      "GET",
				Category:    category,
				Severity:    severity,
				Title:       d.title,
				Remediation: remediation,
				Statuses:    statuses,
				Indicators:  d.indicators,
			})
		}
	}

	addGroup("fast_file", "Fast Sensitive Exposure", "High", "Remove sensitive files from web root and enforce deny rules", []int{200, 206}, files)
	addGroup("fast_admin", "Fast Admin Surface", "Medium", "Restrict administrative endpoints behind authentication and network controls", []int{200, 401, 403}, admin)
	addGroup("fast_api", "Fast API Surface", "Medium", "Protect API and observability endpoints with authz and strict gateway policy", []int{200, 401, 403}, api)
	addGroup("fast_cloud", "Fast Cloud Exposure", "High", "Block cloud/container metadata and control-plane endpoints from public access", []int{200, 401, 403}, cloud)
	addGroup("fast_auth", "Fast Auth Surface", "Medium", "Harden auth endpoints with MFA, throttling, and abuse monitoring", []int{200, 401, 403}, auth)

	return specs
}

func (s *ActiveScanner) runFastAggressiveModules() {
	specs := fastAggressiveModuleSpecs()
	if len(specs) == 0 {
		return
	}

	workers := s.config.MaxConcurrentRequests
	if workers < 20 {
		workers = 20
	}

	jobs := make(chan fastAggressiveModuleSpec, len(specs))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range jobs {
				s.executeFastAggressiveModule(spec)
			}
		}()
	}

	for _, spec := range specs {
		if s.config.ShouldRunModule(spec.ID) {
			jobs <- spec
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *ActiveScanner) executeFastAggressiveModule(spec fastAggressiveModuleSpec) {
	s.setModuleStatus(spec.ID, "running")
	s.markModuleAttempted()
	resp, err := s.makeRequest(spec.Method, s.target+spec.Path, nil)
	if err != nil {
		if atomic.LoadInt32(&s.connectivityOK) == 0 {
			s.markModuleSkipped()
			s.setModuleStatus(spec.ID, "skipped")
		} else {
			s.markModuleErrored()
			s.setModuleStatus(spec.ID, "failed")
		}
		return
	}
	defer resp.Body.Close()

	if !statusAllowed(resp.StatusCode, spec.Statuses) {
		s.markModuleCompleted()
		s.setModuleStatus(spec.ID, "completed")
		return
	}

	if len(spec.Indicators) > 0 {
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			s.markModuleErrored()
			s.setModuleStatus(spec.ID, "failed")
			return
		}
		bodyLower := strings.ToLower(string(bodyBytes))
		matched := false
		for _, indicator := range spec.Indicators {
			if strings.Contains(bodyLower, strings.ToLower(indicator)) {
				matched = true
				break
			}
		}
		if !matched {
			s.markModuleCompleted()
			s.setModuleStatus(spec.ID, "completed")
			return
		}
	}

	s.addFinding(Finding{
		Severity:    spec.Severity,
		Category:    spec.Category,
		Confidence:  "High",
		Finding:     spec.Title,
		Remediation: spec.Remediation,
		Evidence:    fmt.Sprintf("path=%s status=%d content_type=%s", spec.Path, resp.StatusCode, resp.Header.Get("Content-Type")),
		HTTPMethod:  spec.Method,
		Outcome:     "Confirmed",
	})
	s.markModuleCompleted()
	s.setModuleStatus(spec.ID, "completed")
}

func statusAllowed(status int, allowed []int) bool {
	for _, s := range allowed {
		if status == s {
			return true
		}
	}
	return false
}
