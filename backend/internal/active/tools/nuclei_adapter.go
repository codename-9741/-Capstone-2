package tools

import (
	"fmt"
	"time"
)

// NucleiAdapter integrates nuclei into the scanner.
type NucleiAdapter struct {
	ToolAdapter
}

func NewNucleiAdapter(runner *ToolRunner) *NucleiAdapter {
	return &NucleiAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "nuclei",
			ModuleIDs: []string{
				"nuclei_cves",
				"nuclei_misconfig",
				"nuclei_exposed",
				"nuclei_takeover",
			},
		},
	}
}

func (a *NucleiAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	var args []string
	switch moduleID {
	case "nuclei_cves":
		args = []string{"-u", target, "-t", "cves/", "-jsonl", "-silent", "-timeout", fmt.Sprintf("%d", int(timeout.Seconds())-5)}
	case "nuclei_misconfig":
		args = []string{"-u", target, "-t", "misconfiguration/", "-jsonl", "-silent", "-timeout", fmt.Sprintf("%d", int(timeout.Seconds())-5)}
	case "nuclei_exposed":
		args = []string{"-u", target, "-t", "exposures/", "-jsonl", "-silent", "-timeout", fmt.Sprintf("%d", int(timeout.Seconds())-5)}
	case "nuclei_takeover":
		args = []string{"-u", target, "-t", "takeovers/", "-jsonl", "-silent", "-timeout", fmt.Sprintf("%d", int(timeout.Seconds())-5)}
	default:
		return "", fmt.Errorf("unsupported nuclei module: %s", moduleID)
	}

	out, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
