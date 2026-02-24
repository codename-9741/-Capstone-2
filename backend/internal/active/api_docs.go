package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkAPIDocs() {
	if !s.config.ShouldRunModule("api_docs") {
		return
	}

	s.log("Checking for exposed API documentation...")

	docPaths := []string{
		"/api-docs",
		"/api/docs",
		"/swagger",
		"/swagger-ui",
		"/swagger-ui.html",
		"/swagger.json",
		"/swagger.yaml",
		"/api/swagger.json",
		"/openapi.json",
		"/openapi.yaml",
		"/redoc",
		"/graphql",
		"/graphiql",
		"/api/v1/docs",
		"/api/v2/docs",
		"/docs",
	}

	foundDocs := []string{}

	for _, path := range docPaths {
		url := s.target + path
		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := s.readBody(resp)

			// Check for API doc indicators
			if strings.Contains(body, "swagger") ||
				strings.Contains(body, "openapi") ||
				strings.Contains(body, "api documentation") ||
				strings.Contains(body, "graphiql") {
				foundDocs = append(foundDocs, path)
			}
			continue
		}
		resp.Body.Close()
	}

	if len(foundDocs) > 0 {
		s.addFinding(Finding{
			Severity:    "Low",
			Category:    "API Documentation",
			Confidence:  "High",
			Finding:     fmt.Sprintf("API documentation exposed: %v", foundDocs),
			Remediation: "Restrict access to API docs in production; require authentication; use IP whitelisting",
			Evidence:    strings.Join(foundDocs, ", "),
			HTTPMethod:  "GET",
			Outcome:     "Exposed",
		})
	}
}
