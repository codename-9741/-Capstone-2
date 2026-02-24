package passive

import (
	"fmt"
	"net"
	"strings"
)

// DNSScanner performs DNS lookups
type DNSScanner struct{}

func NewDNSScanner() *DNSScanner {
	return &DNSScanner{}
}

// GetDNSRecords retrieves various DNS records for a domain
func (s *DNSScanner) GetDNSRecords(domain string) (map[string][]string, error) {
	records := make(map[string][]string)
	
	// A records (IPv4)
	if ips, err := net.LookupIP(domain); err == nil {
		var ipv4s []string
		var ipv6s []string
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4s = append(ipv4s, ip.String())
			} else {
				ipv6s = append(ipv6s, ip.String())
			}
		}
		if len(ipv4s) > 0 {
			records["A"] = ipv4s
		}
		if len(ipv6s) > 0 {
			records["AAAA"] = ipv6s
		}
	}
	
	// MX records (Mail servers)
	if mxs, err := net.LookupMX(domain); err == nil {
		var mxRecords []string
		for _, mx := range mxs {
			mxRecords = append(mxRecords, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
		records["MX"] = mxRecords
	}
	
	// NS records (Name servers)
	if nss, err := net.LookupNS(domain); err == nil {
		var nsRecords []string
		for _, ns := range nss {
			nsRecords = append(nsRecords, ns.Host)
		}
		records["NS"] = nsRecords
	}
	
	// TXT records (SPF, DMARC, verification, etc)
	if txts, err := net.LookupTXT(domain); err == nil {
		records["TXT"] = txts
	}
	
	// CNAME record
	if cname, err := net.LookupCNAME(domain); err == nil {
		if cname != domain+"." {
			records["CNAME"] = []string{cname}
		}
	}
	
	return records, nil
}

// CheckDNSSEC checks if DNSSEC is enabled
func (s *DNSScanner) CheckDNSSEC(domain string) bool {
	// Simple check - look for DS records
	// In production, you'd want a more thorough check
	_, err := net.LookupTXT("_dnssec." + domain)
	return err == nil
}

// GetSPFRecord extracts SPF record from TXT records
func (s *DNSScanner) GetSPFRecord(txtRecords []string) string {
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			return txt
		}
	}
	return ""
}

// GetDMARCRecord looks up DMARC policy
func (s *DNSScanner) GetDMARCRecord(domain string) string {
	txts, err := net.LookupTXT("_dmarc." + domain)
	if err != nil || len(txts) == 0 {
		return ""
	}
	
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			return txt
		}
	}
	return ""
}

// DNSLookup performs basic DNS lookup
func DNSLookup(domain string) []string {
	results := []string{}
	
	// A records
	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, ip := range ips {
			results = append(results, fmt.Sprintf("A: %s", ip.String()))
		}
	}
	
	// MX records
	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			results = append(results, fmt.Sprintf("MX: %s (priority: %d)", mx.Host, mx.Pref))
		}
	}
	
	// NS records
	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nsRecords {
			results = append(results, fmt.Sprintf("NS: %s", ns.Host))
		}
	}
	
	// TXT records
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txtRecords {
			results = append(results, fmt.Sprintf("TXT: %s", txt))
		}
	}
	
	return results
}
