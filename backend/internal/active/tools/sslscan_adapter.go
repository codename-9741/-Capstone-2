package tools

import (
	"fmt"
	"time"
)

// SSLScanAdapter integrates sslscan into the scanner.
type SSLScanAdapter struct {
	ToolAdapter
}

func NewSSLScanAdapter(runner *ToolRunner) *SSLScanAdapter {
	return &SSLScanAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "sslscan",
			ModuleIDs: []string{
				"sslscan_ciphers",
				"sslscan_protocols",
				"sslscan_certs",
			},
		},
	}
}

func (a *SSLScanAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	host := extractHost(target)
	if host == "" {
		return "", fmt.Errorf("cannot extract host from target: %s", target)
	}

	// sslscan connects to host:443 by default
	args := []string{"--xml=-", host}

	out, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
