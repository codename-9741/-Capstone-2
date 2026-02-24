package active

import (
	"fmt"
	"strings"
	"time"
)

// ExternalScannerAdapter allows integration with external scanners (nmap, masscan, nuclei, etc).
type ExternalScannerAdapter interface {
	Name() string
	Supports(moduleID string) bool
	Run(moduleID, target string, timeout time.Duration) (string, error)
}

// SetExternalAdapters registers one or more external scanner adapters.
func (s *ActiveScanner) SetExternalAdapters(adapters ...ExternalScannerAdapter) {
	s.externalAdapters = adapters
}

// tryExternalModule executes a module through an external adapter if available.
// Returns (output, true) when an external adapter successfully handled the module.
func (s *ActiveScanner) tryExternalModule(moduleID string) (string, bool) {
	if len(s.externalAdapters) == 0 {
		return "", false
	}

	s.markModuleAttempted()
	timeout := time.Duration(s.config.TimeoutSeconds*3) * time.Second
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	if timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}

	for _, adapter := range s.externalAdapters {
		if adapter == nil || !adapter.Supports(moduleID) {
			continue
		}

		output, err := adapter.Run(moduleID, s.target, timeout)
		if err != nil {
			s.markModuleErrored()
			s.addFinding(Finding{
				Severity:    "Low",
				Category:    "External Adapter",
				Confidence:  "Medium",
				Finding:     fmt.Sprintf("External adapter %s failed for %s", adapter.Name(), moduleID),
				Remediation: "Check external scanner binary, permissions, and runtime environment",
				Evidence:    err.Error(),
				HTTPMethod:  "External Scanner",
				Outcome:     "Adapter Error",
			})
			continue
		}

		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "External Adapter",
			Confidence:  "High",
			Finding:     fmt.Sprintf("External adapter %s executed module %s", adapter.Name(), moduleID),
			Remediation: "Correlate external scanner output with internal findings for validation",
			Evidence:    trimEvidence(output),
			HTTPMethod:  "External Scanner",
			Outcome:     "Executed",
		})
		s.markModuleCompleted()
		return output, true
	}

	return "", false
}

func trimEvidence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	if len(s) <= 180 {
		return s
	}
	return s[:180] + "..."
}
