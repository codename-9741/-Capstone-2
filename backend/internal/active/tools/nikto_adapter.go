package tools

import (
	"fmt"
	"time"
)

// NiktoAdapter integrates nikto into the scanner.
type NiktoAdapter struct {
	ToolAdapter
}

func NewNiktoAdapter(runner *ToolRunner) *NiktoAdapter {
	return &NiktoAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "nikto",
			ModuleIDs: []string{
				"nikto_scan",
				"nikto_outdated",
				"nikto_misconfig",
			},
		},
	}
}

func (a *NiktoAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	host := extractHost(target)
	if host == "" {
		return "", fmt.Errorf("cannot extract host from target: %s", target)
	}

	var args []string
	switch moduleID {
	case "nikto_scan":
		args = []string{"-h", target, "-Format", "json", "-output", "-", "-maxtime", fmt.Sprintf("%ds", int(timeout.Seconds())-5)}
	case "nikto_outdated":
		args = []string{"-h", target, "-Format", "json", "-output", "-", "-Tuning", "4", "-maxtime", fmt.Sprintf("%ds", int(timeout.Seconds())-5)}
	case "nikto_misconfig":
		args = []string{"-h", target, "-Format", "json", "-output", "-", "-Tuning", "2", "-maxtime", fmt.Sprintf("%ds", int(timeout.Seconds())-5)}
	default:
		return "", fmt.Errorf("unsupported nikto module: %s", moduleID)
	}

	out, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
