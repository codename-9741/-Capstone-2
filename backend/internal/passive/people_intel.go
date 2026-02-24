package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// httpClient with a reasonable timeout for OSINT probes.
var osintClient = &http.Client{Timeout: 10 * time.Second}

type counter struct {
	count    int
	examples []string
}

// runPeopleIntel runs all people and email discovery modules.
func (s *PassiveScanner) runPeopleIntel(ctx context.Context) {
	modules := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"GitHub Org Member Discovery", s.githubOrgMembers},
		{"GitHub User Company Search", s.githubUserSearch},
		{"GitHub Commit Email Harvest", s.githubCommitEmails},
		{"Email Format Pattern Detection", s.detectEmailPatterns},
		{"LinkedIn Company URL Probe", s.linkedinProbe},
		{"Instagram Account Probe", s.instagramProbe},
		{"Reddit Subreddit Probe", s.redditSubredditProbe},
		{"Twitter/X Account Probe", s.twitterProbe},
		{"YouTube Channel Probe", s.youtubeProbe},
	}
	for _, mod := range modules {
		s.sendProgress(mod.name, "running", 0, "Executing...")
		if err := mod.fn(ctx); err != nil {
			s.Results.ModulesFailed++
			s.sendProgress(mod.name, "failed", 0, err.Error())
		} else {
			s.Results.ModulesSucceeded++
			s.sendProgress(mod.name, "completed", 100, "Success")
		}
		s.Results.ModulesExecuted++
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (s *PassiveScanner) domainName() string {
	// strip port if any
	d := strings.TrimPrefix(s.Target, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.Split(d, "/")[0]
	d = strings.Split(d, ":")[0]
	return d
}

func (s *PassiveScanner) orgSlug() string {
	parts := strings.Split(s.domainName(), ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] // e.g. "google" from "google.com"
	}
	return s.domainName()
}

func (s *PassiveScanner) githubGet(ctx context.Context, url string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "NightfallOSINT/2.0")
	if s.Config.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.Config.GitHubToken)
	}
	resp, err := osintClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		return fmt.Errorf("rate limited: %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("github api error: %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func headProbe(ctx context.Context, rawURL string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; NightfallOSINT/2.0)")
	c := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func bodyContains(ctx context.Context, rawURL, keyword string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; NightfallOSINT/2.0)")
	resp, err := osintClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	return strings.Contains(strings.ToLower(string(body)), strings.ToLower(keyword))
}

// ── GitHub Org Members ────────────────────────────────────────────────────────

func (s *PassiveScanner) githubOrgMembers(ctx context.Context) error {
	slug := s.orgSlug()

	// 1. Try direct org lookup
	var org struct {
		Login       string `json:"login"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Blog        string `json:"blog"`
		Location    string `json:"location"`
		PublicRepos int    `json:"public_repos"`
		Followers   int    `json:"followers"`
		HTMLURL     string `json:"html_url"`
		AvatarURL   string `json:"avatar_url"`
	}
	orgURL := fmt.Sprintf("https://api.github.com/orgs/%s", slug)
	if err := s.githubGet(ctx, orgURL, &org); err != nil {
		return fmt.Errorf("org not found for %s: %w", slug, err)
	}

	// Add GitHub social profile
	s.mu.Lock()
	s.Results.SocialProfiles = append(s.Results.SocialProfiles, SocialProfile{
		Platform:    "GitHub",
		Username:    org.Login,
		URL:         org.HTMLURL,
		Followers:   org.Followers,
		Description: org.Description,
		Verified:    true,
	})
	s.mu.Unlock()

	// 2. Fetch public members
	var members []struct {
		Login     string `json:"login"`
		HTMLURL   string `json:"html_url"`
		AvatarURL string `json:"avatar_url"`
		Type      string `json:"type"`
	}
	membersURL := fmt.Sprintf("https://api.github.com/orgs/%s/public_members?per_page=50", slug)
	if err := s.githubGet(ctx, membersURL, &members); err != nil {
		return nil // not fatal
	}

	for _, m := range members {
		// Fetch each member's detailed profile
		var profile struct {
			Name     string `json:"name"`
			Login    string `json:"login"`
			Company  string `json:"company"`
			Blog     string `json:"blog"`
			Location string `json:"location"`
			Email    string `json:"email"`
			Bio      string `json:"bio"`
			HTMLURL  string `json:"html_url"`
		}
		profileURL := fmt.Sprintf("https://api.github.com/users/%s", m.Login)
		if err := s.githubGet(ctx, profileURL, &profile); err != nil {
			continue
		}
		displayName := profile.Name
		if displayName == "" {
			displayName = profile.Login
		}
		person := Person{
			Name:   displayName,
			GitHub: profile.HTMLURL,
			Source: "github_org",
		}
		if profile.Email != "" {
			person.Email = profile.Email
			s.mu.Lock()
			s.Results.Emails = append(s.Results.Emails, EmailRecord{
				Email:      profile.Email,
				Name:       displayName,
				Source:     "github_profile",
				Confidence: "High",
				Verified:   true,
			})
			s.mu.Unlock()
		}
		s.mu.Lock()
		s.Results.People = append(s.Results.People, person)
		s.mu.Unlock()
	}

	s.addSource("GitHub")
	return nil
}

// ── GitHub User Company Search ────────────────────────────────────────────────

func (s *PassiveScanner) githubUserSearch(ctx context.Context) error {
	domain := s.domainName()
	// Search by email domain
	var searchResult struct {
		Items []struct {
			Login     string `json:"login"`
			HTMLURL   string `json:"html_url"`
			AvatarURL string `json:"avatar_url"`
		} `json:"items"`
	}
	searchURL := fmt.Sprintf("https://api.github.com/search/users?q=%s+in:email&per_page=30", domain)
	if err := s.githubGet(ctx, searchURL, &searchResult); err != nil {
		return err
	}

	for _, item := range searchResult.Items {
		var profile struct {
			Name     string `json:"name"`
			Login    string `json:"login"`
			Company  string `json:"company"`
			Location string `json:"location"`
			Email    string `json:"email"`
			Blog     string `json:"blog"`
			Bio      string `json:"bio"`
			HTMLURL  string `json:"html_url"`
		}
		profileURL := fmt.Sprintf("https://api.github.com/users/%s", item.Login)
		if err := s.githubGet(ctx, profileURL, &profile); err != nil {
			continue
		}
		displayName := profile.Name
		if displayName == "" {
			displayName = profile.Login
		}
		person := Person{
			Name:   displayName,
			GitHub: profile.HTMLURL,
			Source: "github_email_search",
		}
		if profile.Email != "" && strings.HasSuffix(profile.Email, "@"+domain) {
			person.Email = profile.Email
			s.mu.Lock()
			s.Results.Emails = append(s.Results.Emails, EmailRecord{
				Email:      profile.Email,
				Name:       displayName,
				Source:     "github_profile",
				Confidence: "High",
				Verified:   true,
			})
			s.mu.Unlock()
		}
		// Avoid exact duplicates
		s.mu.Lock()
		dup := false
		for _, p := range s.Results.People {
			if p.GitHub == person.GitHub {
				dup = true
				break
			}
		}
		if !dup {
			s.Results.People = append(s.Results.People, person)
		}
		s.mu.Unlock()
	}
	return nil
}

// ── GitHub Commit Email Harvest ───────────────────────────────────────────────

func (s *PassiveScanner) githubCommitEmails(ctx context.Context) error {
	slug := s.orgSlug()
	domain := s.domainName()

	// Fetch the org's top repos
	var repos []struct {
		Name string `json:"name"`
	}
	reposURL := fmt.Sprintf("https://api.github.com/orgs/%s/repos?sort=pushed&per_page=5", slug)
	if err := s.githubGet(ctx, reposURL, &repos); err != nil {
		return nil // not fatal
	}

	emailRe := regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@` + regexp.QuoteMeta(domain))

	for _, repo := range repos {
		var commits []struct {
			Commit struct {
				Author struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commit"`
		}
		commitsURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?per_page=30", slug, repo.Name)
		if err := s.githubGet(ctx, commitsURL, &commits); err != nil {
			continue
		}
		for _, c := range commits {
			email := c.Commit.Author.Email
			name := c.Commit.Author.Name
			if !emailRe.MatchString(email) {
				continue
			}
			s.mu.Lock()
			// Dedup
			dup := false
			for _, e := range s.Results.Emails {
				if strings.EqualFold(e.Email, email) {
					dup = true
					break
				}
			}
			if !dup {
				s.Results.Emails = append(s.Results.Emails, EmailRecord{
					Email:      email,
					Name:       name,
					Source:     fmt.Sprintf("github_commit:%s/%s", slug, repo.Name),
					Confidence: "High",
					Verified:   true,
				})
			}
			s.mu.Unlock()
		}
	}
	return nil
}

// ── Email Pattern Detection ───────────────────────────────────────────────────

func (s *PassiveScanner) detectEmailPatterns(ctx context.Context) error {
	domain := s.domainName()
	s.mu.Lock()
	emails := make([]string, 0, len(s.Results.Emails))
	for _, e := range s.Results.Emails {
		if strings.HasSuffix(strings.ToLower(e.Email), "@"+domain) {
			emails = append(emails, strings.ToLower(e.Email))
		}
	}
	s.mu.Unlock()

	patterns := analyseEmailPatterns(emails, domain)

	s.mu.Lock()
	s.Results.EmailPatterns = append(s.Results.EmailPatterns, patterns...)
	s.mu.Unlock()
	return nil
}

// analyseEmailPatterns detects the email format from a list of known addresses.
func analyseEmailPatterns(emails []string, domain string) []EmailPattern {
	if len(emails) == 0 {
		// Return common guesses as Low confidence
		return []EmailPattern{
			{Pattern: "firstname.lastname", Format: "firstname.lastname@" + domain, Confidence: "Low"},
			{Pattern: "firstnamelastname", Format: "firstnamelastname@" + domain, Confidence: "Low"},
			{Pattern: "f.lastname", Format: "f.lastname@" + domain, Confidence: "Low"},
		}
	}

	counts := map[string]*counter{}

	for _, email := range emails {
		local := strings.Split(email, "@")[0]
		parts := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' })
		if len(parts) == 1 {
			// firstname only
			addPattern(counts, "firstname", email)
		} else if len(parts) == 2 {
			p0, p1 := parts[0], parts[1]
			if len(p0) == 1 {
				addPattern(counts, "f.lastname", email)
			} else if strings.Contains(local, ".") {
				addPattern(counts, "firstname.lastname", email)
			} else if strings.Contains(local, "_") {
				addPattern(counts, "firstname_lastname", email)
			} else {
				addPattern(counts, "firstnamelastname", email)
			}
			_ = p1
		}
	}

	var result []EmailPattern
	for pat, c := range counts {
		conf := "Low"
		if c.count >= 3 {
			conf = "High"
		} else if c.count >= 2 {
			conf = "Medium"
		}
		ex := c.examples
		if len(ex) > 3 {
			ex = ex[:3]
		}
		result = append(result, EmailPattern{
			Pattern:    pat,
			Format:     pat + "@" + domain,
			Examples:   ex,
			Confidence: conf,
		})
	}
	return result
}

func addPattern(m map[string]*counter, pat, example string) {
	if _, ok := m[pat]; !ok {
		m[pat] = &counter{}
	}
	m[pat].count++
	m[pat].examples = append(m[pat].examples, example)
}

// ── Social Profile Probes ─────────────────────────────────────────────────────

func (s *PassiveScanner) linkedinProbe(ctx context.Context) error {
	slug := s.orgSlug()
	domain := s.domainName()

	candidates := []string{slug}
	// Try some common slug variations
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		candidates = append(candidates, parts[len(parts)-2])
	}
	candidates = append(candidates, strings.ReplaceAll(slug, "-", ""))

	for _, candidate := range candidates {
		url := fmt.Sprintf("https://www.linkedin.com/company/%s/", candidate)
		code, err := headProbe(ctx, url)
		if err != nil {
			continue
		}
		if code == 200 || code == 301 || code == 302 {
			s.mu.Lock()
			// Avoid duplicate
			dup := false
			for _, sp := range s.Results.SocialProfiles {
				if sp.Platform == "LinkedIn" {
					dup = true
					break
				}
			}
			if !dup {
				s.Results.SocialProfiles = append(s.Results.SocialProfiles, SocialProfile{
					Platform:    "LinkedIn",
					Username:    candidate,
					URL:         fmt.Sprintf("https://www.linkedin.com/company/%s/", candidate),
					Description: "Company page",
					Verified:    code == 200,
				})
			}
			s.mu.Unlock()
			s.addSource("LinkedIn")
			return nil
		}
	}
	// Fallback: add as unverified
	s.mu.Lock()
	dup := false
	for _, sp := range s.Results.SocialProfiles {
		if sp.Platform == "LinkedIn" {
			dup = true
			break
		}
	}
	if !dup {
		s.Results.SocialProfiles = append(s.Results.SocialProfiles, SocialProfile{
			Platform:    "LinkedIn",
			Username:    slug,
			URL:         fmt.Sprintf("https://www.linkedin.com/company/%s/", slug),
			Description: "Possible company page (unverified)",
			Verified:    false,
		})
	}
	s.mu.Unlock()
	return nil
}

func (s *PassiveScanner) instagramProbe(ctx context.Context) error {
	slug := s.orgSlug()
	url := fmt.Sprintf("https://www.instagram.com/%s/", slug)
	code, err := headProbe(ctx, url)
	if err != nil {
		return err
	}
	verified := code == 200
	s.mu.Lock()
	s.Results.SocialProfiles = append(s.Results.SocialProfiles, SocialProfile{
		Platform: "Instagram",
		Username: slug,
		URL:      url,
		Verified: verified,
	})
	s.mu.Unlock()
	s.addSource("Instagram")
	return nil
}

func (s *PassiveScanner) redditSubredditProbe(ctx context.Context) error {
	slug := s.orgSlug()
	url := fmt.Sprintf("https://www.reddit.com/r/%s/about.json", slug)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NightfallOSINT/2.0")
	resp, err := osintClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var data struct {
			Data struct {
				DisplayName   string `json:"display_name"`
				Title         string `json:"title"`
				Subscribers   int    `json:"subscribers"`
				PublicDesc    string `json:"public_description"`
				URL           string `json:"url"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Data.DisplayName != "" {
			s.mu.Lock()
			s.Results.SocialProfiles = append(s.Results.SocialProfiles, SocialProfile{
				Platform:    "Reddit",
				Username:    data.Data.DisplayName,
				URL:         "https://www.reddit.com" + data.Data.URL,
				Followers:   data.Data.Subscribers,
				Description: data.Data.PublicDesc,
				Verified:    true,
			})
			s.mu.Unlock()
			s.addSource("Reddit")
		}
	}
	return nil
}

func (s *PassiveScanner) twitterProbe(ctx context.Context) error {
	slug := s.orgSlug()
	// Twitter/X doesn't allow unauthenticated API calls; just record the candidate URL
	s.mu.Lock()
	dup := false
	for _, sp := range s.Results.SocialProfiles {
		if sp.Platform == "Twitter" || sp.Platform == "X" {
			dup = true
			break
		}
	}
	if !dup {
		s.Results.SocialProfiles = append(s.Results.SocialProfiles, SocialProfile{
			Platform:    "Twitter/X",
			Username:    slug,
			URL:         fmt.Sprintf("https://twitter.com/%s", slug),
			Description: "Candidate profile (unverified — Twitter auth required)",
			Verified:    false,
		})
	}
	s.mu.Unlock()
	return nil
}

func (s *PassiveScanner) youtubeProbe(ctx context.Context) error {
	slug := s.orgSlug()
	// Check /@handle and /c/handle patterns
	candidates := []string{
		fmt.Sprintf("https://www.youtube.com/@%s", slug),
		fmt.Sprintf("https://www.youtube.com/c/%s", slug),
		fmt.Sprintf("https://www.youtube.com/user/%s", slug),
	}
	for _, url := range candidates {
		code, err := headProbe(ctx, url)
		if err != nil {
			continue
		}
		if code == 200 || code == 301 {
			s.mu.Lock()
			s.Results.SocialProfiles = append(s.Results.SocialProfiles, SocialProfile{
				Platform: "YouTube",
				Username: slug,
				URL:      url,
				Verified: code == 200,
			})
			s.mu.Unlock()
			s.addSource("YouTube")
			return nil
		}
	}
	return nil
}

func (s *PassiveScanner) addSource(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, src := range s.Results.DataSources {
		if src == name {
			return
		}
	}
	s.Results.DataSources = append(s.Results.DataSources, name)
}
