package tools

import (
	"fmt"
	"time"
)

// WhatWebAdapter integrates whatweb into the scanner.
type WhatWebAdapter struct {
	ToolAdapter
}

func NewWhatWebAdapter(runner *ToolRunner) *WhatWebAdapter {
	return &WhatWebAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "whatweb",
			ModuleIDs: []string{
				"whatweb_fingerprint",
			},
		},
	}
}

func (a *WhatWebAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "whatweb_fingerprint" {
		return "", fmt.Errorf("unsupported whatweb module: %s", moduleID)
	}

	args := []string{"--log-json=-", "-a", "3", target}

	out, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
