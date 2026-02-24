package active

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

type protocolAggressiveModuleSpec struct {
	ID     string
	Path   string
	Method string
}

func protocolAggressiveModuleIDs() []string {
	specs := protocolAggressiveModuleSpecs()
	ids := make([]string, 0, len(specs))
	for _, spec := range specs {
		ids = append(ids, spec.ID)
	}
	return ids
}

func protocolAggressiveModuleSpecs() []protocolAggressiveModuleSpec {
	endpoints := []string{
		"/",
		"/api",
		"/api/v1",
		"/login",
		"/admin",
		"/graphql",
		"/upload",
		"/search",
		"/user",
		"/account",
		"/auth",
		"/oauth/token",
		"/metrics",
		"/actuator",
		"/debug",
		"/internal",
		"/health",
		"/status",
		"/robots.txt",
		"/sitemap.xml",
	}

	methods := []string{"OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"}
	specs := make([]protocolAggressiveModuleSpec, 0, len(endpoints)*len(methods))
	idx := 1
	for _, ep := range endpoints {
		for _, m := range methods {
			specs = append(specs, protocolAggressiveModuleSpec{
				ID:     fmt.Sprintf("proto_method_%03d", idx),
				Path:   ep,
				Method: m,
			})
			idx++
		}
	}
	return specs
}

func (s *ActiveScanner) runProtocolAggressiveModules() {
	specs := protocolAggressiveModuleSpecs()
	if len(specs) == 0 {
		return
	}

	workers := s.config.MaxConcurrentRequests
	if workers < 20 {
		workers = 20
	}

	jobs := make(chan protocolAggressiveModuleSpec, len(specs))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for spec := range jobs {
				s.executeProtocolAggressiveModule(spec)
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

func (s *ActiveScanner) executeProtocolAggressiveModule(spec protocolAggressiveModuleSpec) {
	s.setModuleStatus(spec.ID, "running")
	s.markModuleAttempted()
	url := s.target + spec.Path
	resp, err := s.makeRequest(spec.Method, url, nil)
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

	allow := strings.ToUpper(resp.Header.Get("Allow"))
	corsMethods := strings.ToUpper(resp.Header.Get("Access-Control-Allow-Methods"))
	riskyAdvertised := strings.Contains(allow, "TRACE") || strings.Contains(allow, "PUT") || strings.Contains(allow, "DELETE") || strings.Contains(allow, "PATCH") ||
		strings.Contains(corsMethods, "TRACE") || strings.Contains(corsMethods, "PUT") || strings.Contains(corsMethods, "DELETE") || strings.Contains(corsMethods, "PATCH")

	switch spec.Method {
	case "OPTIONS":
		if riskyAdvertised {
			s.addFinding(Finding{
				Severity:    "Medium",
				Category:    "Protocol Method Matrix",
				Confidence:  "High",
				Finding:     fmt.Sprintf("OPTIONS on %s advertises risky HTTP methods", spec.Path),
				Remediation: "Disable unsafe methods and restrict allowed methods per endpoint",
				Evidence:    fmt.Sprintf("status=%d allow=%s acam=%s", resp.StatusCode, allow, corsMethods),
				HTTPMethod:  spec.Method,
				Outcome:     "Risky Methods Advertised",
			})
		}
	case "TRACE":
		if resp.StatusCode == 200 {
			s.addFinding(Finding{
				Severity:    "High",
				Category:    "Protocol Method Matrix",
				Confidence:  "High",
				Finding:     fmt.Sprintf("TRACE method enabled on %s", spec.Path),
				Remediation: "Disable TRACE at web server, reverse proxy, and application layers",
				Evidence:    fmt.Sprintf("status=%d", resp.StatusCode),
				HTTPMethod:  spec.Method,
				Outcome:     "Enabled",
			})
		}
	case "PUT", "DELETE", "PATCH":
		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 202 || resp.StatusCode == 204 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			severity := "Medium"
			if resp.StatusCode >= 200 && resp.StatusCode <= 204 {
				severity = "High"
			}
			s.addFinding(Finding{
				Severity:    severity,
				Category:    "Protocol Method Matrix",
				Confidence:  "High",
				Finding:     fmt.Sprintf("%s method accepted on %s", spec.Method, spec.Path),
				Remediation: "Enforce strict method allowlists and route-level access controls",
				Evidence:    fmt.Sprintf("status=%d allow=%s", resp.StatusCode, allow),
				HTTPMethod:  spec.Method,
				Outcome:     "Method Accepted",
			})
		}
	}
	s.markModuleCompleted()
	s.setModuleStatus(spec.ID, "completed")
}
