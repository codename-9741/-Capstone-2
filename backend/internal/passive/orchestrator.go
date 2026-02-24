package passive

import (
	"fmt"
)

// PassiveReconResult holds results from passive reconnaissance
type PassiveReconResult struct {
	Subdomains []string
	DNSRecords []string
	Error      error
}

// RunPassiveRecon orchestrates all passive reconnaissance modules
func RunPassiveRecon(domain string) *PassiveReconResult {
	result := &PassiveReconResult{}
	
	// Subdomain enumeration via crt.sh
	fmt.Printf("[Passive] Starting subdomain enumeration for %s\n", domain)
	result.Subdomains = EnumerateSubdomains(domain)
	
	// DNS reconnaissance
	fmt.Printf("[Passive] Starting DNS reconnaissance for %s\n", domain)
	result.DNSRecords = DNSLookup(domain)
	
	fmt.Printf("[Passive] Reconnaissance complete: %d subdomains, %d DNS records\n", 
		len(result.Subdomains), len(result.DNSRecords))
	
	return result
}
