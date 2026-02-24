package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SkipfishAdapter integrates skipfish into the scanner.
type SkipfishAdapter struct {
	ToolAdapter
}

func NewSkipfishAdapter(runner *ToolRunner) *SkipfishAdapter {
	return &SkipfishAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "skipfish",
			ModuleIDs: []string{
				"skipfish_recon",
			},
		},
	}
}

func (a *SkipfishAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "skipfish_recon" {
		return "", fmt.Errorf("unsupported skipfish module: %s", moduleID)
	}

	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("skipfish-%d", time.Now().UnixNano()))
	defer os.RemoveAll(tmpDir)

	args := []string{
		"-o", tmpDir,
		"-max-time", fmt.Sprintf("%d", int(timeout.Seconds())-10),
		"-LY",
		target,
	}

	out, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}

	// Try to read the summary if available
	summary, readErr := os.ReadFile(filepath.Join(tmpDir, "index.html"))
	if readErr == nil && len(summary) > 0 {
		return string(summary), nil
	}
	return string(out), nil
}
