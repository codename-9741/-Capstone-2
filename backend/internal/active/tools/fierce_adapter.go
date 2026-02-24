package tools

import (
	"fmt"
	"time"
)

// FierceAdapter integrates fierce into the scanner.
type FierceAdapter struct {
	ToolAdapter
}

func NewFierceAdapter(runner *ToolRunner) *FierceAdapter {
	return &FierceAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "fierce",
			ModuleIDs: []string{
				"fierce_dns_enum",
			},
		},
	}
}

func (a *FierceAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "fierce_dns_enum" {
		return "", fmt.Errorf("unsupported fierce module: %s", moduleID)
	}

	host := extractHost(target)
	if host == "" {
		return "", fmt.Errorf("cannot extract host from target: %s", target)
	}

	args := []string{"--domain", host}

	out, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
