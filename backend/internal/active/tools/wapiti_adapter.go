package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WapitiAdapter integrates wapiti into the scanner.
type WapitiAdapter struct {
	ToolAdapter
}

func NewWapitiAdapter(runner *ToolRunner) *WapitiAdapter {
	return &WapitiAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "wapiti",
			ModuleIDs: []string{
				"wapiti_sqli",
				"wapiti_xss",
				"wapiti_ssrf",
				"wapiti_xxe",
			},
		},
	}
}

func (a *WapitiAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	// Wapiti writes output to file, so we use a temp file
	tmpDir := os.TempDir()
	outFile := filepath.Join(tmpDir, fmt.Sprintf("wapiti-%s-%d.json", moduleID, time.Now().UnixNano()))
	defer os.Remove(outFile)

	var module string
	switch moduleID {
	case "wapiti_sqli":
		module = "sql"
	case "wapiti_xss":
		module = "xss"
	case "wapiti_ssrf":
		module = "ssrf"
	case "wapiti_xxe":
		module = "xxe"
	default:
		return "", fmt.Errorf("unsupported wapiti module: %s", moduleID)
	}

	args := []string{
		"-u", target,
		"-m", module,
		"-f", "json",
		"-o", outFile,
		"--max-scan-time", fmt.Sprintf("%d", int(timeout.Seconds())-10),
		"--flush-session",
		"-v", "0",
	}

	_, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		return "", fmt.Errorf("failed to read wapiti output: %w", err)
	}
	return string(data), nil
}
