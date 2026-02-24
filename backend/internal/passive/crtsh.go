package passive

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CertEntry represents a certificate transparency log entry
type CertEntry struct {
	NameValue string `json:"name_value"`
}

// EnumerateSubdomains queries Certificate Transparency logs via crt.sh
func EnumerateSubdomains(domain string) []string {
	subdomains := make(map[string]bool)
	
	// Query crt.sh API
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("[Passive] crt.sh query failed: %v\n", err)
		return []string{}
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		fmt.Printf("[Passive] crt.sh returned status %d\n", resp.StatusCode)
		return []string{}
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}
	}
	
	var entries []CertEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return []string{}
	}
	
	// Extract unique subdomains
	for _, entry := range entries {
		// Split by newlines (cert can have multiple names)
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			name = strings.ToLower(name)
			
			// Only include if it's actually a subdomain of the target
			if strings.HasSuffix(name, domain) && name != "" {
				subdomains[name] = true
			}
		}
	}
	
	// Convert map to slice
	result := make([]string, 0, len(subdomains))
	for subdomain := range subdomains {
		result = append(result, subdomain)
	}
	
	fmt.Printf("[Passive] Found %d unique subdomains via crt.sh\n", len(result))
	return result
}

// FetchSubdomains is an alias for EnumerateSubdomains
func FetchSubdomains(domain string) []string {
	return EnumerateSubdomains(domain)
}

// QueryCertificateTransparency is another alias for backward compatibility
func QueryCertificateTransparency(domain string) []string {
	return EnumerateSubdomains(domain)
}
