package tools

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"nightfall-tsukuyomi/internal/active"
)

// ToolRunner wraps an external CLI tool binary.
type ToolRunner struct {
	Name       string
	BinaryPath string
	Available  bool
}

// CheckAvailable probes exec.LookPath to see if the tool binary exists.
func (t *ToolRunner) CheckAvailable() bool {
	path, err := exec.LookPath(t.Name)
	if err != nil {
		t.Available = false
		return false
	}
	t.BinaryPath = path
	t.Available = true
	return true
}

// Version returns the tool's version string (best-effort).
func (t *ToolRunner) Version() string {
	if !t.Available {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, t.BinaryPath, "--version").CombinedOutput()
	if err != nil {
		// Some tools use -V or -version
		out, err = exec.CommandContext(ctx, t.BinaryPath, "-V").CombinedOutput()
		if err != nil {
			return "unknown"
		}
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}

// Exec runs the tool with arguments and returns combined stdout+stderr.
func (t *ToolRunner) Exec(args []string, timeout time.Duration) ([]byte, error) {
	if !t.Available {
		return nil, fmt.Errorf("%s is not installed", t.Name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, t.BinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[ToolRunner] Executing: %s %s", t.Name, strings.Join(args, " "))

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return stdout.Bytes(), fmt.Errorf("%s timed out after %s", t.Name, timeout)
	}
	if err != nil {
		// Many security tools return non-zero exit codes for findings — that's OK.
		// Only error if there's zero output.
		if stdout.Len() > 0 {
			return stdout.Bytes(), nil
		}
		return nil, fmt.Errorf("%s failed: %v — stderr: %s", t.Name, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// ToolAdapter wraps a ToolRunner and implements active.ExternalScannerAdapter.
// Subtype adapters embed this and override ParseFindings.
type ToolAdapter struct {
	Runner    *ToolRunner
	ModuleIDs []string
	ToolName  string
}

func (a *ToolAdapter) Name() string { return a.ToolName }

func (a *ToolAdapter) Supports(moduleID string) bool {
	for _, id := range a.ModuleIDs {
		if id == moduleID {
			return true
		}
	}
	return false
}

// DetectAvailableTools checks all known tool binaries and returns adapters for available ones.
func DetectAvailableTools() []active.ExternalScannerAdapter {
	var adapters []active.ExternalScannerAdapter

	toolChecks := []struct {
		name    string
		factory func(*ToolRunner) active.ExternalScannerAdapter
	}{
		{"nmap", func(r *ToolRunner) active.ExternalScannerAdapter { return NewNmapAdapter(r) }},
		{"nikto", func(r *ToolRunner) active.ExternalScannerAdapter { return NewNiktoAdapter(r) }},
		{"nuclei", func(r *ToolRunner) active.ExternalScannerAdapter { return NewNucleiAdapter(r) }},
		{"wapiti", func(r *ToolRunner) active.ExternalScannerAdapter { return NewWapitiAdapter(r) }},
		{"sslscan", func(r *ToolRunner) active.ExternalScannerAdapter { return NewSSLScanAdapter(r) }},
		{"whatweb", func(r *ToolRunner) active.ExternalScannerAdapter { return NewWhatWebAdapter(r) }},
		{"fierce", func(r *ToolRunner) active.ExternalScannerAdapter { return NewFierceAdapter(r) }},
		{"skipfish", func(r *ToolRunner) active.ExternalScannerAdapter { return NewSkipfishAdapter(r) }},
		{"sqlmap", func(r *ToolRunner) active.ExternalScannerAdapter { return NewSQLMapAdapter(r) }},
		{"ffuf", func(r *ToolRunner) active.ExternalScannerAdapter { return NewFFUFAdapter(r) }},
		{"subfinder", func(r *ToolRunner) active.ExternalScannerAdapter { return NewSubfinderAdapter(r) }},
		{"testssl.sh", func(r *ToolRunner) active.ExternalScannerAdapter { return NewTestSSLAdapter(r) }},
		{"dalfox", func(r *ToolRunner) active.ExternalScannerAdapter { return NewDalfoxAdapter(r) }},
		{"gobuster", func(r *ToolRunner) active.ExternalScannerAdapter { return NewGobusterAdapter(r) }},
		{"httpx", func(r *ToolRunner) active.ExternalScannerAdapter { return NewHTTPXAdapter(r) }},
		{"kr", func(r *ToolRunner) active.ExternalScannerAdapter { return NewKiterunnerAdapter(r) }},
		{"amass", func(r *ToolRunner) active.ExternalScannerAdapter { return NewAmassAdapter(r) }},
		{"uncover", func(r *ToolRunner) active.ExternalScannerAdapter { return NewUncoverAdapter(r) }},
		{"gau", func(r *ToolRunner) active.ExternalScannerAdapter { return NewGauAdapter(r) }},
		{"dnsx", func(r *ToolRunner) active.ExternalScannerAdapter { return NewDNSXAdapter(r) }},
		{"alterx", func(r *ToolRunner) active.ExternalScannerAdapter { return NewAlterxAdapter(r) }},
		{"crtsh", func(r *ToolRunner) active.ExternalScannerAdapter { return NewCRTShAdapter(r) }},
	}

	for _, tc := range toolChecks {
		runner := &ToolRunner{Name: tc.name}
		if runner.CheckAvailable() {
			log.Printf("[Tools] %s detected at %s", tc.name, runner.BinaryPath)
			adapters = append(adapters, tc.factory(runner))
		} else {
			log.Printf("[Tools] %s not available", tc.name)
		}
	}

	return adapters
}

// AllToolNames returns the names of all tools that can be detected.
func AllToolNames() []string {
	return []string{
		"nmap", "nikto", "nuclei", "wapiti", "sslscan", "whatweb", "fierce", "skipfish",
		"sqlmap", "ffuf", "subfinder", "testssl.sh", "dalfox", "gobuster", "httpx", "kr",
		"amass", "uncover", "gau", "dnsx", "alterx", "crtsh",
	}
}

// GetToolStatus returns status info for all known tools.
func GetToolStatus() []ToolStatus {
	var statuses []ToolStatus
	for _, name := range AllToolNames() {
		runner := &ToolRunner{Name: name}
		available := runner.CheckAvailable()
		version := ""
		path := ""
		if available {
			version = runner.Version()
			path = runner.BinaryPath
		}
		statuses = append(statuses, ToolStatus{
			Name:      name,
			Installed: available,
			Version:   version,
			Path:      path,
		})
	}
	return statuses
}

// ToolStatus holds status info for a single tool.
type ToolStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version"`
	Path      string `json:"path"`
}
