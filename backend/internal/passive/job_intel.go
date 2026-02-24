package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// runJobIntel fetches job postings from public ATSes and extracts tech signals.
func (s *PassiveScanner) runJobIntel(ctx context.Context) {
	modules := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"Greenhouse Job Board", s.scrapeGreenhouse},
		{"Lever Job Board", s.scrapeLever},
		{"Workable Job Board", s.scrapeWorkable},
		{"Tech Stack from Job Postings", s.extractHiringTech},
	}
	for _, mod := range modules {
		s.sendProgress(mod.name, "running", 0, "Executing...")
		if err := mod.fn(ctx); err != nil {
			s.Results.ModulesFailed++
		} else {
			s.Results.ModulesSucceeded++
		}
		s.Results.ModulesExecuted++
	}
}

// ── Greenhouse ────────────────────────────────────────────────────────────────

func (s *PassiveScanner) scrapeGreenhouse(ctx context.Context) error {
	slug := s.orgSlug()
	url := fmt.Sprintf("https://boards-api.greenhouse.io/v1/boards/%s/jobs?content=true", slug)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NightfallOSINT/2.0")
	c := &http.Client{Timeout: 12 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("greenhouse board not found for %s: %d", slug, resp.StatusCode)
	}

	var result struct {
		Jobs []struct {
			ID          int    `json:"id"`
			Title       string `json:"title"`
			UpdatedAt   string `json:"updated_at"`
			Content     string `json:"content"`
			AbsoluteURL string `json:"absolute_url"`
			Offices     []struct {
				Name string `json:"name"`
			} `json:"offices"`
			Departments []struct {
				Name string `json:"name"`
			} `json:"departments"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	s.mu.Lock()
	for _, job := range result.Jobs {
		dept := ""
		if len(job.Departments) > 0 {
			dept = job.Departments[0].Name
		}
		loc := ""
		if len(job.Offices) > 0 {
			loc = job.Offices[0].Name
		}
		keywords := extractTechKeywords(job.Content + " " + job.Title)
		s.Results.JobListings = append(s.Results.JobListings, JobListing{
			ID:           fmt.Sprintf("gh-%d", job.ID),
			Title:        job.Title,
			Department:   dept,
			Location:     loc,
			URL:          job.AbsoluteURL,
			PostedAt:     job.UpdatedAt,
			Source:       "greenhouse",
			TechKeywords: keywords,
		})
	}
	s.mu.Unlock()

	s.addSource("Greenhouse")
	return nil
}

// ── Lever ─────────────────────────────────────────────────────────────────────

func (s *PassiveScanner) scrapeLever(ctx context.Context) error {
	slug := s.orgSlug()
	url := fmt.Sprintf("https://api.lever.co/v0/postings/%s?mode=json", slug)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NightfallOSINT/2.0")
	c := &http.Client{Timeout: 12 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("lever board not found for %s: %d", slug, resp.StatusCode)
	}

	var jobs []struct {
		ID          string `json:"id"`
		Text        string `json:"text"`
		Categories  struct {
			Department string `json:"department"`
			Location   string `json:"location"`
			Team       string `json:"team"`
		} `json:"categories"`
		Description string `json:"descriptionPlain"`
		HostedURL   string `json:"hostedUrl"`
		CreatedAt   int64  `json:"createdAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jobs); err != nil {
		return err
	}

	s.mu.Lock()
	for _, job := range jobs {
		postedAt := ""
		if job.CreatedAt > 0 {
			postedAt = time.UnixMilli(job.CreatedAt).Format(time.RFC3339)
		}
		keywords := extractTechKeywords(job.Description + " " + job.Text)
		s.Results.JobListings = append(s.Results.JobListings, JobListing{
			ID:           "lv-" + job.ID,
			Title:        job.Text,
			Department:   job.Categories.Department,
			Location:     job.Categories.Location,
			URL:          job.HostedURL,
			PostedAt:     postedAt,
			Source:       "lever",
			TechKeywords: keywords,
		})
	}
	s.mu.Unlock()

	s.addSource("Lever")
	return nil
}

// ── Workable ──────────────────────────────────────────────────────────────────

func (s *PassiveScanner) scrapeWorkable(ctx context.Context) error {
	slug := s.orgSlug()
	url := fmt.Sprintf("https://apply.workable.com/api/v3/accounts/%s/jobs", slug)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(`{"query":"","location":[],"department":[],"worktype":[],"remote":false}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NightfallOSINT/2.0")
	c := &http.Client{Timeout: 12 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("workable not found: %d", resp.StatusCode)
	}

	var result struct {
		Results []struct {
			Shortcode   string `json:"shortcode"`
			Title       string `json:"title"`
			Department  string `json:"department"`
			Location    struct {
				City    string `json:"city"`
				Country string `json:"country"`
			} `json:"location"`
			URL string `json:"url"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	s.mu.Lock()
	for _, job := range result.Results {
		loc := strings.TrimRight(job.Location.City+", "+job.Location.Country, ", ")
		s.Results.JobListings = append(s.Results.JobListings, JobListing{
			ID:         "wk-" + job.Shortcode,
			Title:      job.Title,
			Department: job.Department,
			Location:   loc,
			URL:        job.URL,
			Source:     "workable",
		})
	}
	s.mu.Unlock()

	s.addSource("Workable")
	return nil
}

// ── Tech Signal Extraction ────────────────────────────────────────────────────

func (s *PassiveScanner) extractHiringTech(ctx context.Context) error {
	s.mu.Lock()
	jobs := s.Results.JobListings
	s.mu.Unlock()

	techCounts := map[string]struct {
		count    int
		category string
		roles    map[string]bool
	}{}

	for _, job := range jobs {
		keywords := job.TechKeywords
		if len(keywords) == 0 {
			keywords = extractTechKeywords(job.Title)
		}
		for _, kw := range keywords {
			cat := techCategory(kw)
			entry := techCounts[kw]
			if entry.roles == nil {
				entry.roles = map[string]bool{}
			}
			entry.count++
			entry.category = cat
			entry.roles[job.Title] = true
			techCounts[kw] = entry
		}
	}

	var signals []TechHiringSignal
	for tech, data := range techCounts {
		roles := make([]string, 0, len(data.roles))
		for r := range data.roles {
			roles = append(roles, r)
		}
		signals = append(signals, TechHiringSignal{
			Technology: tech,
			Category:   data.category,
			JobCount:   data.count,
			Roles:      roles,
		})
	}
	// Sort by job count descending
	sort.Slice(signals, func(i, j int) bool {
		return signals[i].JobCount > signals[j].JobCount
	})
	if len(signals) > 50 {
		signals = signals[:50]
	}

	s.mu.Lock()
	s.Results.HiringTech = append(s.Results.HiringTech, signals...)
	s.mu.Unlock()
	return nil
}

// ── Tech keyword extraction from text ────────────────────────────────────────

var techKeywords = []struct {
	re       *regexp.Regexp
	name     string
	category string
}{
	// Languages
	{regexp.MustCompile(`(?i)\bgo\b|\bgolang\b`), "Go", "Language"},
	{regexp.MustCompile(`(?i)\bpython\b`), "Python", "Language"},
	{regexp.MustCompile(`(?i)\brust\b`), "Rust", "Language"},
	{regexp.MustCompile(`(?i)\bjava\b`), "Java", "Language"},
	{regexp.MustCompile(`(?i)\bscala\b`), "Scala", "Language"},
	{regexp.MustCompile(`(?i)\bkotlin\b`), "Kotlin", "Language"},
	{regexp.MustCompile(`(?i)\bswift\b`), "Swift", "Language"},
	{regexp.MustCompile(`(?i)\bc\+\+|\bcpp\b`), "C++", "Language"},
	{regexp.MustCompile(`(?i)\bc#\b|\bdotnet\b|\.net`), "C#/.NET", "Language"},
	{regexp.MustCompile(`(?i)\btypescript\b`), "TypeScript", "Language"},
	{regexp.MustCompile(`(?i)\bjavascript\b|\bjs\b`), "JavaScript", "Language"},
	{regexp.MustCompile(`(?i)\bruby\b`), "Ruby", "Language"},
	{regexp.MustCompile(`(?i)\bphp\b`), "PHP", "Language"},
	{regexp.MustCompile(`(?i)\belixir\b`), "Elixir", "Language"},
	{regexp.MustCompile(`(?i)\bclojure\b`), "Clojure", "Language"},
	{regexp.MustCompile(`(?i)\bhaskell\b`), "Haskell", "Language"},
	{regexp.MustCompile(`(?i)\bsql\b`), "SQL", "Language"},
	{regexp.MustCompile(`(?i)\bshell\b|\bbash\b`), "Shell/Bash", "Language"},
	// Frameworks
	{regexp.MustCompile(`(?i)\breact\b`), "React", "Framework"},
	{regexp.MustCompile(`(?i)\bvue\.?js\b|\bvuejs\b`), "Vue.js", "Framework"},
	{regexp.MustCompile(`(?i)\bangular\b`), "Angular", "Framework"},
	{regexp.MustCompile(`(?i)\bnext\.?js\b`), "Next.js", "Framework"},
	{regexp.MustCompile(`(?i)\bnode\.?js\b|\bnodejs\b`), "Node.js", "Framework"},
	{regexp.MustCompile(`(?i)\bdjango\b`), "Django", "Framework"},
	{regexp.MustCompile(`(?i)\bflask\b`), "Flask", "Framework"},
	{regexp.MustCompile(`(?i)\bfastapi\b`), "FastAPI", "Framework"},
	{regexp.MustCompile(`(?i)\bspring\b`), "Spring", "Framework"},
	{regexp.MustCompile(`(?i)\brails\b|\bruby on rails\b`), "Ruby on Rails", "Framework"},
	{regexp.MustCompile(`(?i)\blaravel\b`), "Laravel", "Framework"},
	{regexp.MustCompile(`(?i)\bexpress\.?js\b`), "Express.js", "Framework"},
	{regexp.MustCompile(`(?i)\bgin\b|\bgin-gonic\b`), "Gin", "Framework"},
	{regexp.MustCompile(`(?i)\bgrpc\b`), "gRPC", "Framework"},
	{regexp.MustCompile(`(?i)\bgraphql\b`), "GraphQL", "Framework"},
	// Cloud & Infrastructure
	{regexp.MustCompile(`(?i)\baws\b|\bamazon web services\b`), "AWS", "Cloud"},
	{regexp.MustCompile(`(?i)\bgcp\b|\bgoogle cloud\b`), "GCP", "Cloud"},
	{regexp.MustCompile(`(?i)\bazure\b`), "Azure", "Cloud"},
	{regexp.MustCompile(`(?i)\bkubernetes\b|\bk8s\b`), "Kubernetes", "DevOps"},
	{regexp.MustCompile(`(?i)\bdocker\b`), "Docker", "DevOps"},
	{regexp.MustCompile(`(?i)\bterraform\b`), "Terraform", "DevOps"},
	{regexp.MustCompile(`(?i)\bansible\b`), "Ansible", "DevOps"},
	{regexp.MustCompile(`(?i)\bjenkins\b`), "Jenkins", "DevOps"},
	{regexp.MustCompile(`(?i)\bgithub actions\b`), "GitHub Actions", "DevOps"},
	{regexp.MustCompile(`(?i)\bgitlab ci\b`), "GitLab CI", "DevOps"},
	{regexp.MustCompile(`(?i)\bcircleci\b`), "CircleCI", "DevOps"},
	{regexp.MustCompile(`(?i)\bhelm\b`), "Helm", "DevOps"},
	{regexp.MustCompile(`(?i)\bprometheus\b`), "Prometheus", "Monitoring"},
	{regexp.MustCompile(`(?i)\bgrafana\b`), "Grafana", "Monitoring"},
	{regexp.MustCompile(`(?i)\bdatadog\b`), "Datadog", "Monitoring"},
	{regexp.MustCompile(`(?i)\bnewrelic\b`), "New Relic", "Monitoring"},
	// Databases
	{regexp.MustCompile(`(?i)\bpostgres(ql)?\b`), "PostgreSQL", "Database"},
	{regexp.MustCompile(`(?i)\bmysql\b`), "MySQL", "Database"},
	{regexp.MustCompile(`(?i)\bmongodb\b`), "MongoDB", "Database"},
	{regexp.MustCompile(`(?i)\bredis\b`), "Redis", "Database"},
	{regexp.MustCompile(`(?i)\belasticsearch\b`), "Elasticsearch", "Database"},
	{regexp.MustCompile(`(?i)\bcassandra\b`), "Cassandra", "Database"},
	{regexp.MustCompile(`(?i)\bdynamodb\b`), "DynamoDB", "Database"},
	{regexp.MustCompile(`(?i)\bsnowflake\b`), "Snowflake", "Database"},
	{regexp.MustCompile(`(?i)\bbigquery\b`), "BigQuery", "Database"},
	{regexp.MustCompile(`(?i)\bclickhouse\b`), "ClickHouse", "Database"},
	{regexp.MustCompile(`(?i)\bkafka\b`), "Kafka", "Messaging"},
	{regexp.MustCompile(`(?i)\brabbitmq\b`), "RabbitMQ", "Messaging"},
	{regexp.MustCompile(`(?i)\bnats\b`), "NATS", "Messaging"},
	// Security relevant
	{regexp.MustCompile(`(?i)\bsoc 2\b|\bsoc2\b`), "SOC2", "Compliance"},
	{regexp.MustCompile(`(?i)\bgdpr\b`), "GDPR", "Compliance"},
	{regexp.MustCompile(`(?i)\biso 27001\b`), "ISO 27001", "Compliance"},
	{regexp.MustCompile(`(?i)\bpentest\b|\bpenetration test\b`), "PenTest", "Security"},
	{regexp.MustCompile(`(?i)\bdevsecops\b`), "DevSecOps", "Security"},
	{regexp.MustCompile(`(?i)\bzero trust\b`), "Zero Trust", "Security"},
	{regexp.MustCompile(`(?i)\bvault\b`), "HashiCorp Vault", "Security"},
}

func extractTechKeywords(text string) []string {
	seen := map[string]bool{}
	var result []string
	for _, kw := range techKeywords {
		if kw.re.MatchString(text) && !seen[kw.name] {
			seen[kw.name] = true
			result = append(result, kw.name)
		}
	}
	return result
}

func techCategory(tech string) string {
	for _, kw := range techKeywords {
		if strings.EqualFold(kw.name, tech) {
			return kw.category
		}
	}
	return "Other"
}
