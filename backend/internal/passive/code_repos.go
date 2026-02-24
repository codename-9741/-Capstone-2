package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func (s *PassiveScanner) githubOrgDiscovery(ctx context.Context) error {
	if s.Config.GitHubToken == "" {
		return nil
	}
	
	companyName := s.Target
	url := fmt.Sprintf("https://api.github.com/search/users?q=%s+type:org", companyName)
	
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "token "+s.Config.GitHubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	var result struct {
		Items []struct {
			Login string `json:"login"`
		} `json:"items"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	s.Results.DataSources = append(s.Results.DataSources, "GitHub")
	return nil
}

func (s *PassiveScanner) githubRepoEnum(ctx context.Context) error {
	if s.Config.GitHubToken == "" {
		return nil
	}
	
	url := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc", s.Target)
	
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "token "+s.Config.GitHubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	var result struct {
		Items []struct {
			Name        string    `json:"name"`
			Description string    `json:"description"`
			Language    string    `json:"language"`
			Stars       int       `json:"stargazers_count"`
			Forks       int       `json:"forks_count"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
			Private     bool      `json:"private"`
		} `json:"items"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	s.mu.Lock()
	for _, item := range result.Items {
		s.Results.GitHubRepos = append(s.Results.GitHubRepos, GitHubRepository{
			Name:        item.Name,
			Description: item.Description,
			Language:    item.Language,
			Stars:       item.Stars,
			Forks:       item.Forks,
			CreatedAt:   item.CreatedAt,
			UpdatedAt:   item.UpdatedAt,
			IsPrivate:   item.Private,
		})
	}
	s.mu.Unlock()
	
	return nil
}

func (s *PassiveScanner) githubSecretScan(ctx context.Context) error {
	if s.Config.GitHubToken == "" {
		return nil
	}
	
	url := fmt.Sprintf("https://api.github.com/search/code?q=%s+extension:env+extension:yml", s.Target)
	
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "token "+s.Config.GitHubToken)
	
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	s.Results.DataSources = append(s.Results.DataSources, "GitHub Code Search")
	return nil
}

func (s *PassiveScanner) githubCommitAnalysis(ctx context.Context) error {
	return nil
}

func (s *PassiveScanner) githubIssueTracking(ctx context.Context) error {
	return nil
}

func (s *PassiveScanner) gitlabProjectDiscovery(ctx context.Context) error {
	return nil
}

func (s *PassiveScanner) bitbucketRepoSearch(ctx context.Context) error {
	return nil
}

func (s *PassiveScanner) npmPackageSearch(ctx context.Context) error {
	url := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=%s&size=20", s.Target)
	
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	s.Results.DataSources = append(s.Results.DataSources, "NPM Registry")
	return nil
}

func (s *PassiveScanner) pypiPackageSearch(ctx context.Context) error {
	return nil
}

func (s *PassiveScanner) dockerHubSearch(ctx context.Context) error {
	url := fmt.Sprintf("https://hub.docker.com/v2/search/repositories/?query=%s", s.Target)
	
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	s.Results.DataSources = append(s.Results.DataSources, "Docker Hub")
	return nil
}
