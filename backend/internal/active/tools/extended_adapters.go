package tools

import (
	"fmt"
	"strings"
	"time"
)

type SQLMapAdapter struct{ ToolAdapter }

func NewSQLMapAdapter(runner *ToolRunner) *SQLMapAdapter {
	return &SQLMapAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "sqlmap",
			ModuleIDs: []string{"sqlmap_detect", "sqlmap_deep"},
		},
	}
}

func (a *SQLMapAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	var args []string
	switch moduleID {
	case "sqlmap_detect":
		args = []string{"-u", target, "--batch", "--smart", "--level", "1", "--risk", "1"}
	case "sqlmap_deep":
		args = []string{"-u", target, "--batch", "--level", "3", "--risk", "2"}
	default:
		return "", fmt.Errorf("unsupported sqlmap module: %s", moduleID)
	}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

type FFUFAdapter struct{ ToolAdapter }

func NewFFUFAdapter(runner *ToolRunner) *FFUFAdapter {
	return &FFUFAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "ffuf",
			ModuleIDs: []string{"ffuf_dirs", "ffuf_api"},
		},
	}
}

func (a *FFUFAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	base := strings.TrimRight(target, "/")
	var args []string
	switch moduleID {
	case "ffuf_dirs":
		args = []string{"-u", base + "/FUZZ", "-w", "/usr/local/share/nightfall/wordlists/common.txt", "-mc", "200,204,301,302,307,401,403"}
	case "ffuf_api":
		args = []string{"-u", base + "/api/FUZZ", "-w", "/usr/local/share/nightfall/wordlists/api.txt", "-mc", "200,204,301,302,307,401,403"}
	default:
		return "", fmt.Errorf("unsupported ffuf module: %s", moduleID)
	}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

type SubfinderAdapter struct{ ToolAdapter }

func NewSubfinderAdapter(runner *ToolRunner) *SubfinderAdapter {
	return &SubfinderAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "subfinder",
			ModuleIDs: []string{"subfinder_passive"},
		},
	}
}

func (a *SubfinderAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "subfinder_passive" {
		return "", fmt.Errorf("unsupported subfinder module: %s", moduleID)
	}
	out, err := a.Runner.Exec([]string{"-d", domainFromTarget(target), "-silent"}, timeout)
	return string(out), err
}

type TestSSLAdapter struct{ ToolAdapter }

func NewTestSSLAdapter(runner *ToolRunner) *TestSSLAdapter {
	return &TestSSLAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "testssl.sh",
			ModuleIDs: []string{"testssl_basic", "testssl_vulns"},
		},
	}
}

func (a *TestSSLAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	var args []string
	switch moduleID {
	case "testssl_basic":
		args = []string{"--warnings", "off", "--color", "0", target}
	case "testssl_vulns":
		args = []string{"--vulnerable", "--warnings", "off", "--color", "0", target}
	default:
		return "", fmt.Errorf("unsupported testssl module: %s", moduleID)
	}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

type DalfoxAdapter struct{ ToolAdapter }

func NewDalfoxAdapter(runner *ToolRunner) *DalfoxAdapter {
	return &DalfoxAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "dalfox",
			ModuleIDs: []string{"dalfox_url", "dalfox_param"},
		},
	}
}

func (a *DalfoxAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	var args []string
	switch moduleID {
	case "dalfox_url":
		args = []string{"url", target, "--no-color", "--silence", "--skip-bav"}
	case "dalfox_param":
		args = []string{"url", target, "--no-color", "--silence", "--skip-bav", "--skip-mining-dom"}
	default:
		return "", fmt.Errorf("unsupported dalfox module: %s", moduleID)
	}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

type GobusterAdapter struct{ ToolAdapter }

func NewGobusterAdapter(runner *ToolRunner) *GobusterAdapter {
	return &GobusterAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "gobuster",
			ModuleIDs: []string{"gobuster_dir", "gobuster_vhost"},
		},
	}
}

func (a *GobusterAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	var args []string
	switch moduleID {
	case "gobuster_dir":
		args = []string{"dir", "-u", target, "-w", "/usr/local/share/nightfall/wordlists/common.txt", "-q"}
	case "gobuster_vhost":
		args = []string{"vhost", "-u", target, "-w", "/usr/local/share/nightfall/wordlists/vhosts.txt", "-q"}
	default:
		return "", fmt.Errorf("unsupported gobuster module: %s", moduleID)
	}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

type HTTPXAdapter struct{ ToolAdapter }

func NewHTTPXAdapter(runner *ToolRunner) *HTTPXAdapter {
	return &HTTPXAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "httpx",
			ModuleIDs: []string{"httpx_probe", "httpx_tech"},
		},
	}
}

func (a *HTTPXAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	var args []string
	switch moduleID {
	case "httpx_probe":
		args = []string{"-u", target, "-silent", "-status-code", "-title"}
	case "httpx_tech":
		args = []string{"-u", target, "-silent", "-tech-detect"}
	default:
		return "", fmt.Errorf("unsupported httpx module: %s", moduleID)
	}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

type KiterunnerAdapter struct{ ToolAdapter }

func NewKiterunnerAdapter(runner *ToolRunner) *KiterunnerAdapter {
	return &KiterunnerAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "kr",
			ModuleIDs: []string{"kiterunner_scan"},
		},
	}
}

func (a *KiterunnerAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "kiterunner_scan" {
		return "", fmt.Errorf("unsupported kiterunner module: %s", moduleID)
	}
	args := []string{"scan", target}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

func domainFromTarget(target string) string {
	domain := strings.TrimPrefix(target, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if i := strings.Index(domain, "/"); i != -1 {
		domain = domain[:i]
	}
	if i := strings.Index(domain, ":"); i != -1 {
		domain = domain[:i]
	}
	return strings.TrimSpace(domain)
}

type AmassAdapter struct{ ToolAdapter }

func NewAmassAdapter(runner *ToolRunner) *AmassAdapter {
	return &AmassAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "amass",
			ModuleIDs: []string{"amass_passive", "amass_intel"},
		},
	}
}

func (a *AmassAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	domain := domainFromTarget(target)
	var args []string
	switch moduleID {
	case "amass_passive":
		args = []string{"enum", "-passive", "-d", domain, "-silent"}
	case "amass_intel":
		args = []string{"intel", "-whois", "-d", domain}
	default:
		return "", fmt.Errorf("unsupported amass module: %s", moduleID)
	}
	out, err := a.Runner.Exec(args, timeout)
	return string(out), err
}

type UncoverAdapter struct{ ToolAdapter }

func NewUncoverAdapter(runner *ToolRunner) *UncoverAdapter {
	return &UncoverAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "uncover",
			ModuleIDs: []string{"uncover_search"},
		},
	}
}

func (a *UncoverAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "uncover_search" {
		return "", fmt.Errorf("unsupported uncover module: %s", moduleID)
	}
	out, err := a.Runner.Exec([]string{"-q", domainFromTarget(target), "-silent"}, timeout)
	return string(out), err
}

type GauAdapter struct{ ToolAdapter }

func NewGauAdapter(runner *ToolRunner) *GauAdapter {
	return &GauAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "gau",
			ModuleIDs: []string{"gau_urls"},
		},
	}
}

func (a *GauAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "gau_urls" {
		return "", fmt.Errorf("unsupported gau module: %s", moduleID)
	}
	out, err := a.Runner.Exec([]string{"--subs", domainFromTarget(target)}, timeout)
	return string(out), err
}

type DNSXAdapter struct{ ToolAdapter }

func NewDNSXAdapter(runner *ToolRunner) *DNSXAdapter {
	return &DNSXAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "dnsx",
			ModuleIDs: []string{"dnsx_resolve"},
		},
	}
}

func (a *DNSXAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "dnsx_resolve" {
		return "", fmt.Errorf("unsupported dnsx module: %s", moduleID)
	}
	out, err := a.Runner.Exec([]string{"-d", domainFromTarget(target), "-silent", "-resp"}, timeout)
	return string(out), err
}

type AlterxAdapter struct{ ToolAdapter }

func NewAlterxAdapter(runner *ToolRunner) *AlterxAdapter {
	return &AlterxAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "alterx",
			ModuleIDs: []string{"alterx_permute"},
		},
	}
}

func (a *AlterxAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "alterx_permute" {
		return "", fmt.Errorf("unsupported alterx module: %s", moduleID)
	}
	out, err := a.Runner.Exec([]string{"-d", domainFromTarget(target), "-silent"}, timeout)
	return string(out), err
}

type CRTShAdapter struct{ ToolAdapter }

func NewCRTShAdapter(runner *ToolRunner) *CRTShAdapter {
	return &CRTShAdapter{
		ToolAdapter: ToolAdapter{
			Runner: runner, ToolName: "crtsh",
			ModuleIDs: []string{"crtsh_lookup"},
		},
	}
}

func (a *CRTShAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	if moduleID != "crtsh_lookup" {
		return "", fmt.Errorf("unsupported crtsh module: %s", moduleID)
	}
	out, err := a.Runner.Exec([]string{domainFromTarget(target)}, timeout)
	return string(out), err
}
