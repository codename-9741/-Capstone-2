package active

import "strings"

func (s *ActiveScanner) discoverGraphQL() {
	if !s.config.ShouldRunModule("graphql") {
		return
	}
	s.log("Checking for GraphQL endpoints...")

	paths := []string{"/graphql", "/api/graphql", "/graphiql"}

	for _, path := range paths {
		resp, err := s.makeRequest("GET", s.target+path, nil)
		if err != nil {
			continue
		}

		body := s.readBody(resp)
		if strings.Contains(strings.ToLower(body), "graphql") {
			s.addFinding(Finding{
				Severity:    "Info",
				Category:    "GraphQL",
				Confidence:  "Medium",
				Finding:     "GraphQL endpoint detected: " + path,
				Remediation: "Disable introspection in production, implement auth, rate limiting",
				Evidence:    "GraphQL indicators found",
				HTTPMethod:  "GET",
				Outcome:     "Detected",
			})
		}
	}
}
