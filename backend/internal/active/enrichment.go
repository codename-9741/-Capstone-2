package active

import "strings"

// EnrichmentMapping maps a finding category to MITRE ATT&CK, OWASP, and Kill Chain data.
type EnrichmentMapping struct {
	MitreAttackID  string
	MitreTactic    string
	MitreTechnique string
	OwaspCategory  string
	OwaspName      string
	KillChainPhase string
}

// enrichmentTable maps normalized category keywords to framework references.
var enrichmentTable = map[string]EnrichmentMapping{
	// Injection
	"sql injection":        {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"sqli":                 {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"xss":                  {MitreAttackID: "T1059.007", MitreTactic: "Execution", MitreTechnique: "JavaScript", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"cross-site scripting": {MitreAttackID: "T1059.007", MitreTactic: "Execution", MitreTechnique: "JavaScript", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"command injection":    {MitreAttackID: "T1059", MitreTactic: "Execution", MitreTechnique: "Command and Scripting Interpreter", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"ldap injection":       {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"ssti":                 {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"template injection":   {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"xxe":                  {MitreAttackID: "T1611", MitreTactic: "Execution", MitreTechnique: "Escape to Host", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Exploitation"},
	"ssrf":                 {MitreAttackID: "T1090", MitreTactic: "Command and Control", MitreTechnique: "Proxy", OwaspCategory: "A10:2021", OwaspName: "Server-Side Request Forgery", KillChainPhase: "Exploitation"},

	// Broken Access Control
	"cors":                 {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Exploitation"},
	"csrf":                 {MitreAttackID: "T1185", MitreTactic: "Collection", MitreTechnique: "Browser Session Hijacking", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Exploitation"},
	"idor":                 {MitreAttackID: "T1078", MitreTactic: "Defense Evasion", MitreTechnique: "Valid Accounts", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Exploitation"},
	"privilege escalation": {MitreAttackID: "T1068", MitreTactic: "Privilege Escalation", MitreTechnique: "Exploitation for Privilege Escalation", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Exploitation"},
	"open redirect":        {MitreAttackID: "T1204.001", MitreTactic: "Execution", MitreTechnique: "Malicious Link", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Delivery"},
	"clickjacking":         {MitreAttackID: "T1185", MitreTactic: "Collection", MitreTechnique: "Browser Session Hijacking", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Exploitation"},
	"directory listing":    {MitreAttackID: "T1083", MitreTactic: "Discovery", MitreTechnique: "File and Directory Discovery", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Reconnaissance"},
	"path traversal":       {MitreAttackID: "T1083", MitreTactic: "Discovery", MitreTechnique: "File and Directory Discovery", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Exploitation"},
	"file inclusion":       {MitreAttackID: "T1055", MitreTactic: "Defense Evasion", MitreTechnique: "Process Injection", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Exploitation"},

	// Cryptographic Failures
	"tls":         {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Exploitation"},
	"tls matrix":  {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Exploitation"},
	"weak cipher": {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Exploitation"},
	"sslv3":       {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Exploitation"},
	"sslscan":     {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Reconnaissance"},

	// Security Misconfiguration
	"security headers":      {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"headers":               {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"misconfig":             {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"admin panel":           {MitreAttackID: "T1078", MitreTactic: "Initial Access", MitreTechnique: "Valid Accounts", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"robots":                {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"api docs":              {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"graphql":               {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"docker exposure":       {MitreAttackID: "T1613", MitreTactic: "Discovery", MitreTechnique: "Container and Resource Discovery", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Exploitation"},
	"kubernetes":            {MitreAttackID: "T1613", MitreTactic: "Discovery", MitreTechnique: "Container and Resource Discovery", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Exploitation"},
	"cloud metadata":        {MitreAttackID: "T1552.005", MitreTactic: "Credential Access", MitreTechnique: "Cloud Instance Metadata API", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Exploitation"},
	"http method override":  {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Exploitation"},
	"host header injection": {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Exploitation"},

	// Vulnerable/Outdated Components
	"outdated":       {MitreAttackID: "T1195", MitreTactic: "Initial Access", MitreTechnique: "Supply Chain Compromise", OwaspCategory: "A06:2021", OwaspName: "Vulnerable and Outdated Components", KillChainPhase: "Initial Access"},
	"fingerprinting": {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A06:2021", OwaspName: "Vulnerable and Outdated Components", KillChainPhase: "Reconnaissance"},
	"whatweb":        {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A06:2021", OwaspName: "Vulnerable and Outdated Components", KillChainPhase: "Reconnaissance"},

	// Auth Failures
	"authentication": {MitreAttackID: "T1078", MitreTactic: "Initial Access", MitreTechnique: "Valid Accounts", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Initial Access"},
	"brute force":    {MitreAttackID: "T1110", MitreTactic: "Credential Access", MitreTechnique: "Brute Force", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"default cred":   {MitreAttackID: "T1078.001", MitreTactic: "Initial Access", MitreTechnique: "Default Accounts", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Initial Access"},
	"session":        {MitreAttackID: "T1539", MitreTactic: "Credential Access", MitreTechnique: "Steal Web Session Cookie", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"jwt":            {MitreAttackID: "T1528", MitreTactic: "Credential Access", MitreTechnique: "Steal Application Access Token", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"oauth":          {MitreAttackID: "T1528", MitreTactic: "Credential Access", MitreTechnique: "Steal Application Access Token", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"password":       {MitreAttackID: "T1110", MitreTactic: "Credential Access", MitreTechnique: "Brute Force", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"mfa":            {MitreAttackID: "T1111", MitreTactic: "Credential Access", MitreTechnique: "Multi-Factor Authentication Interception", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"cookie":         {MitreAttackID: "T1539", MitreTactic: "Credential Access", MitreTechnique: "Steal Web Session Cookie", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"api key":        {MitreAttackID: "T1552", MitreTactic: "Credential Access", MitreTechnique: "Unsecured Credentials", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Exploitation"},
	"credential":     {MitreAttackID: "T1078", MitreTactic: "Initial Access", MitreTechnique: "Valid Accounts", OwaspCategory: "A07:2021", OwaspName: "Identification and Authentication Failures", KillChainPhase: "Reconnaissance"},

	// Data Integrity
	"file upload": {MitreAttackID: "T1105", MitreTactic: "Command and Control", MitreTechnique: "Ingress Tool Transfer", OwaspCategory: "A08:2021", OwaspName: "Software and Data Integrity Failures", KillChainPhase: "Exploitation"},

	// Logging/Monitoring
	"waf":                 {MitreAttackID: "T1562", MitreTactic: "Defense Evasion", MitreTechnique: "Impair Defenses", OwaspCategory: "A09:2021", OwaspName: "Security Logging and Monitoring Failures", KillChainPhase: "Reconnaissance"},
	"security monitoring": {MitreAttackID: "T1562", MitreTactic: "Defense Evasion", MitreTechnique: "Impair Defenses", OwaspCategory: "A09:2021", OwaspName: "Security Logging and Monitoring Failures", KillChainPhase: "Reconnaissance"},

	// Network / Port scanning
	"nmap":             {MitreAttackID: "T1046", MitreTactic: "Discovery", MitreTechnique: "Network Service Discovery", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"port scan":        {MitreAttackID: "T1046", MitreTactic: "Discovery", MitreTechnique: "Network Service Discovery", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"network exposure": {MitreAttackID: "T1046", MitreTactic: "Discovery", MitreTechnique: "Network Service Discovery", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},

	// DNS
	"dns":                {MitreAttackID: "T1596.001", MitreTactic: "Reconnaissance", MitreTechnique: "DNS/Passive DNS", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"subdomain takeover": {MitreAttackID: "T1584.001", MitreTactic: "Resource Development", MitreTechnique: "Domains", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Weaponization"},
	"fierce":             {MitreAttackID: "T1596.001", MitreTactic: "Reconnaissance", MitreTechnique: "DNS/Passive DNS", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},

	// Nuclei CVEs
	"nuclei": {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A06:2021", OwaspName: "Vulnerable and Outdated Components", KillChainPhase: "Exploitation"},
	"cve":    {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A06:2021", OwaspName: "Vulnerable and Outdated Components", KillChainPhase: "Exploitation"},

	// Compliance
	"gdpr":  {MitreAttackID: "", MitreTactic: "Impact", MitreTechnique: "Data Manipulation", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Actions on Objectives"},
	"ccpa":  {MitreAttackID: "", MitreTactic: "Impact", MitreTechnique: "Data Manipulation", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Actions on Objectives"},
	"pci":   {MitreAttackID: "", MitreTactic: "Impact", MitreTechnique: "Data Manipulation", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Actions on Objectives"},
	"hipaa": {MitreAttackID: "", MitreTactic: "Impact", MitreTechnique: "Data Manipulation", OwaspCategory: "A01:2021", OwaspName: "Broken Access Control", KillChainPhase: "Actions on Objectives"},

	// Nikto
	"nikto": {MitreAttackID: "T1595", MitreTactic: "Reconnaissance", MitreTechnique: "Active Scanning", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},

	// Skipfish
	"skipfish":   {MitreAttackID: "T1595", MitreTactic: "Reconnaissance", MitreTechnique: "Active Scanning", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"sqlmap":     {MitreAttackID: "T1190", MitreTactic: "Initial Access", MitreTechnique: "Exploit Public-Facing Application", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"ffuf":       {MitreAttackID: "T1595", MitreTactic: "Reconnaissance", MitreTechnique: "Active Scanning", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"subfinder":  {MitreAttackID: "T1596.001", MitreTactic: "Reconnaissance", MitreTechnique: "DNS/Passive DNS", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"testssl":    {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Exploitation"},
	"testssl.sh": {MitreAttackID: "T1557", MitreTactic: "Collection", MitreTechnique: "Adversary-in-the-Middle", OwaspCategory: "A02:2021", OwaspName: "Cryptographic Failures", KillChainPhase: "Exploitation"},
	"dalfox":     {MitreAttackID: "T1059.007", MitreTactic: "Execution", MitreTechnique: "JavaScript", OwaspCategory: "A03:2021", OwaspName: "Injection", KillChainPhase: "Exploitation"},
	"gobuster":   {MitreAttackID: "T1595", MitreTactic: "Reconnaissance", MitreTechnique: "Active Scanning", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"httpx":      {MitreAttackID: "T1595", MitreTactic: "Reconnaissance", MitreTechnique: "Active Scanning", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"kr":         {MitreAttackID: "T1595", MitreTactic: "Reconnaissance", MitreTechnique: "Active Scanning", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"kiterunner": {MitreAttackID: "T1595", MitreTactic: "Reconnaissance", MitreTechnique: "Active Scanning", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"amass":      {MitreAttackID: "T1596.001", MitreTactic: "Reconnaissance", MitreTechnique: "DNS/Passive DNS", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"uncover":    {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"gau":        {MitreAttackID: "T1592", MitreTactic: "Reconnaissance", MitreTechnique: "Gather Victim Host Information", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"dnsx":       {MitreAttackID: "T1596.001", MitreTactic: "Reconnaissance", MitreTechnique: "DNS/Passive DNS", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"alterx":     {MitreAttackID: "T1596.001", MitreTactic: "Reconnaissance", MitreTechnique: "DNS/Passive DNS", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
	"crtsh":      {MitreAttackID: "T1596.001", MitreTactic: "Reconnaissance", MitreTechnique: "DNS/Passive DNS", OwaspCategory: "A05:2021", OwaspName: "Security Misconfiguration", KillChainPhase: "Reconnaissance"},
}

// EnrichFinding applies MITRE ATT&CK, OWASP, and Kill Chain mappings to a finding
// based on its category and finding text.
func EnrichFinding(category, findingText, toolSource string) EnrichmentMapping {
	lower := strings.ToLower(category + " " + findingText)

	// Try exact category match first
	if m, ok := enrichmentTable[strings.ToLower(strings.TrimSpace(category))]; ok {
		return m
	}

	// Try keyword matching
	for keyword, mapping := range enrichmentTable {
		if strings.Contains(lower, keyword) {
			return mapping
		}
	}

	// Try tool source
	if toolSource != "" && toolSource != "native" {
		if m, ok := enrichmentTable[strings.ToLower(toolSource)]; ok {
			return m
		}
	}

	return EnrichmentMapping{}
}
