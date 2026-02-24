package tools

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// NmapAdapter integrates nmap into the scanner.
type NmapAdapter struct {
	ToolAdapter
}

func NewNmapAdapter(runner *ToolRunner) *NmapAdapter {
	return &NmapAdapter{
		ToolAdapter: ToolAdapter{
			Runner:   runner,
			ToolName: "nmap",
			ModuleIDs: []string{
				"nmap_top1000",
				"nmap_service_detection",
				"nmap_vuln_scripts",
				"nmap_udp_top",
				"nmap_tls_ciphers",
				"nmap_firewall_bypass",
			},
		},
	}
}

func (a *NmapAdapter) Run(moduleID, target string, timeout time.Duration) (string, error) {
	host := extractHost(target)
	if host == "" {
		return "", fmt.Errorf("cannot extract host from target: %s", target)
	}

	var args []string
	switch moduleID {
	case "nmap_top1000":
		args = []string{"-sT", "--top-ports", "1000", "-T4", "--open", "-oX", "-", host}
	case "nmap_service_detection":
		args = []string{"-sV", "--top-ports", "100", "-T4", "-oX", "-", host}
	case "nmap_vuln_scripts":
		args = []string{"-sV", "--script", "vuln", "--top-ports", "50", "-T4", "-oX", "-", host}
	case "nmap_udp_top":
		args = []string{"-sU", "--top-ports", "20", "-T4", "-oX", "-", host}
	case "nmap_tls_ciphers":
		args = []string{"-sV", "--script", "ssl-enum-ciphers", "-p", "443", "-oX", "-", host}
	case "nmap_firewall_bypass":
		args = []string{"-sA", "--top-ports", "100", "-T4", "-oX", "-", host}
	default:
		return "", fmt.Errorf("unsupported nmap module: %s", moduleID)
	}

	out, err := a.Runner.Exec(args, timeout)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// nmapRun represents the XML output structure from nmap.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Ports nmapPorts `xml:"ports"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// ParseNmapXML parses nmap XML output into a summary string.
func ParseNmapXML(data []byte) string {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return string(data)
	}

	var lines []string
	for _, host := range run.Hosts {
		for _, port := range host.Ports.Ports {
			if port.State.State == "open" {
				svc := port.Service.Name
				if port.Service.Product != "" {
					svc += " " + port.Service.Product
				}
				if port.Service.Version != "" {
					svc += " " + port.Service.Version
				}
				lines = append(lines, fmt.Sprintf("%d/%s open %s", port.PortID, port.Protocol, strings.TrimSpace(svc)))
			}
		}
	}
	if len(lines) == 0 {
		return "No open ports found"
	}
	return strings.Join(lines, "\n")
}

func extractHost(target string) string {
	parsed, err := url.Parse(target)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	host := strings.TrimSpace(target)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	return host
}
