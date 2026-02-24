package passive

import "time"

// DNS & Network Types
type Subdomain struct {
	Name         string    `json:"name"`
	Source       string    `json:"source"`
	DiscoveredAt time.Time `json:"discovered_at"`
	IPAddresses  []string  `json:"ip_addresses"`
	CNAMEs       []string  `json:"cnames"`
}

type IPInfo struct {
	Address     string   `json:"address"`
	Type        string   `json:"type"` // IPv4, IPv6
	Geolocation GeoData  `json:"geolocation"`
	ASN         int      `json:"asn"`
	ISP         string   `json:"isp"`
	Ports       []int    `json:"ports"`
}

type GeoData struct {
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

type ASNData struct {
	ASN         int      `json:"asn"`
	Name        string   `json:"name"`
	Country     string   `json:"country"`
	IPRanges    []string `json:"ip_ranges"`
}

type DNSSecurityInfo struct {
	DNSSEC      bool     `json:"dnssec_enabled"`
	CAA         []string `json:"caa_records"`
	SPF         string   `json:"spf_record"`
	DMARC       string   `json:"dmarc_record"`
	DKIM        []string `json:"dkim_selectors"`
}

type CDNInfo struct {
	Provider    string   `json:"provider"`
	Detected    bool     `json:"detected"`
	Indicators  []string `json:"indicators"`
}

// Certificate Types
type Certificate struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidTo       time.Time `json:"valid_to"`
	SANs          []string  `json:"sans"`
	Fingerprint   string    `json:"fingerprint"`
	KeyAlgorithm  string    `json:"key_algorithm"`
	SignAlgorithm string    `json:"signature_algorithm"`
}

type CTLog struct {
	LogID       string    `json:"log_id"`
	Timestamp   time.Time `json:"timestamp"`
	Certificate string    `json:"certificate"`
	Domains     []string  `json:"domains"`
}

type TLSSnapshot struct {
	Date          time.Time `json:"date"`
	TLSVersion    string    `json:"tls_version"`
	CipherSuites  []string  `json:"cipher_suites"`
	Protocols     []string  `json:"protocols"`
}

// Social Media Types
type SocialProfile struct {
	Platform    string `json:"platform"`
	Username    string `json:"username"`
	URL         string `json:"url"`
	Verified    bool   `json:"verified"`
	Followers   int    `json:"followers"`
	Description string `json:"description"`
}

type LinkedInProfile struct {
	CompanyName  string   `json:"company_name"`
	EmployeeCount string  `json:"employee_count"`
	Industry     string   `json:"industry"`
	Locations    []string `json:"locations"`
	Specialties  []string `json:"specialties"`
	Founded      string   `json:"founded"`
	Employees    []LinkedInEmployee `json:"employees"`
}

type LinkedInEmployee struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	Duration string `json:"duration"`
	Skills   []string `json:"skills"`
}

type TwitterAccount struct {
	Handle      string    `json:"handle"`
	Followers   int       `json:"followers"`
	Following   int       `json:"following"`
	Tweets      int       `json:"tweets"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
	Bio         string    `json:"bio"`
}

type FacebookPage struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Likes       int    `json:"likes"`
	Followers   int    `json:"followers"`
	About       string `json:"about"`
	Website     string `json:"website"`
}

type InstagramAccount struct {
	Username    string `json:"username"`
	Followers   int    `json:"followers"`
	Following   int    `json:"following"`
	Posts       int    `json:"posts"`
	Bio         string `json:"bio"`
	Verified    bool   `json:"verified"`
}

type YouTubeChannel struct {
	Name        string `json:"name"`
	Subscribers int    `json:"subscribers"`
	Videos      int    `json:"videos"`
	Views       int64  `json:"views"`
	CreatedAt   time.Time `json:"created_at"`
}

type RedditPresence struct {
	Subreddits  []string `json:"subreddits"`
	Mentions    int      `json:"mentions"`
	Sentiment   string   `json:"sentiment"`
}

type GlassdoorInfo struct {
	Rating      float64 `json:"rating"`
	Reviews     int     `json:"reviews"`
	CEOApproval float64 `json:"ceo_approval"`
	Recommend   float64 `json:"recommend_percentage"`
}

// Code Repository Types
type GitHubRepository struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Language    string    `json:"language"`
	Stars       int       `json:"stars"`
	Forks       int       `json:"forks"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Topics      []string  `json:"topics"`
	IsPrivate   bool      `json:"is_private"`
}

type GitLabProject struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Visibility  string `json:"visibility"`
	Stars       int    `json:"stars"`
	Forks       int    `json:"forks"`
}

type BitbucketRepo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Language    string `json:"language"`
	IsPrivate   bool   `json:"is_private"`
}

type SecretLeak struct {
	Type        string    `json:"type"` // API_KEY, PASSWORD, TOKEN, etc.
	Value       string    `json:"value_masked"`
	Repository  string    `json:"repository"`
	File        string    `json:"file"`
	CommitHash  string    `json:"commit_hash"`
	Author      string    `json:"author"`
	DetectedAt  time.Time `json:"detected_at"`
	Severity    string    `json:"severity"`
}

type CodeExposure struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Severity    string `json:"severity"`
}

// Job Posting Types
type JobPosting struct {
	Title       string    `json:"title"`
	Company     string    `json:"company"`
	Location    string    `json:"location"`
	PostedDate  time.Time `json:"posted_date"`
	URL         string    `json:"url"`
	Description string    `json:"description"`
	Requirements []string `json:"requirements"`
	TechStack   []string  `json:"tech_stack"`
	SalaryRange string    `json:"salary_range"`
}

type TechnologyStack struct {
	Languages   []string `json:"languages"`
	Frameworks  []string `json:"frameworks"`
	Databases   []string `json:"databases"`
	CloudPlatforms []string `json:"cloud_platforms"`
	Tools       []string `json:"tools"`
	DevOps      []string `json:"devops"`
	Confidence  string   `json:"confidence"`
}

type SkillData struct {
	Skill       string  `json:"skill"`
	Frequency   int     `json:"frequency"`
	Percentage  float64 `json:"percentage"`
}

type SalaryInfo struct {
	Position    string `json:"position"`
	MinSalary   int    `json:"min_salary"`
	MaxSalary   int    `json:"max_salary"`
	Currency    string `json:"currency"`
	Source      string `json:"source"`
}

type TeamSizeEstimate struct {
	Engineering   int    `json:"engineering"`
	Product       int    `json:"product"`
	Design        int    `json:"design"`
	Total         int    `json:"total"`
	Confidence    string `json:"confidence"`
	Source        string `json:"source"`
}

// Cloud Types
type AWSResource struct {
	Type        string   `json:"type"`
	Identifier  string   `json:"identifier"`
	Region      string   `json:"region"`
	Public      bool     `json:"public"`
	Tags        []string `json:"tags"`
}

type AzureResource struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	ResourceGroup string `json:"resource_group"`
	Location    string `json:"location"`
	Public      bool   `json:"public"`
}

type GCPResource struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Project     string `json:"project"`
	Zone        string `json:"zone"`
	Public      bool   `json:"public"`
}

type S3Bucket struct {
	Name        string    `json:"name"`
	Region      string    `json:"region"`
	Public      bool      `json:"public"`
	Listable    bool      `json:"listable"`
	Files       []string  `json:"files"`
	Size        int64     `json:"size_bytes"`
	LastModified time.Time `json:"last_modified"`
}

type CloudFrontDist struct {
	DomainName  string   `json:"domain_name"`
	Origins     []string `json:"origins"`
	Enabled     bool     `json:"enabled"`
}

type DockerImage struct {
	Name        string    `json:"name"`
	Tag         string    `json:"tag"`
	Repository  string    `json:"repository"`
	Digest      string    `json:"digest"`
	Size        int64     `json:"size_bytes"`
	PushedAt    time.Time `json:"pushed_at"`
}

// Breach Types
type DataBreach struct {
	Name        string    `json:"name"`
	Date        time.Time `json:"date"`
	Entries     int       `json:"entries"`
	DataTypes   []string  `json:"data_types"`
	Verified    bool      `json:"verified"`
	Description string    `json:"description"`
}

type EmailLeak struct {
	Email       string    `json:"email"`
	Breaches    []string  `json:"breaches"`
	FirstSeen   time.Time `json:"first_seen"`
	Severity    string    `json:"severity"`
}

type PasswordLeak struct {
	Email       string    `json:"email_masked"`
	Password    string    `json:"password_masked"`
	Hash        string    `json:"hash"`
	HashType    string    `json:"hash_type"`
	Source      string    `json:"source"`
	LeakedAt    time.Time `json:"leaked_at"`
}

type PasteLeak struct {
	Title       string    `json:"title"`
	Source      string    `json:"source"`
	URL         string    `json:"url"`
	Date        time.Time `json:"date"`
	EmailCount  int       `json:"email_count"`
}

type DatabaseDump struct {
	Name        string    `json:"name"`
	Size        string    `json:"size"`
	Records     int       `json:"records"`
	Date        time.Time `json:"date"`
	Source      string    `json:"source"`
	Tables      []string  `json:"tables"`
}

// Historical Types
type WaybackSnapshot struct {
	URL         string    `json:"url"`
	Timestamp   time.Time `json:"timestamp"`
	StatusCode  int       `json:"status_code"`
	MimeType    string    `json:"mime_type"`
	Digest      string    `json:"digest"`
}

type DomainHistoryEntry struct {
	Date        time.Time `json:"date"`
	Event       string    `json:"event"`
	Details     string    `json:"details"`
}

type WHOISRecord struct {
	Date        time.Time `json:"date"`
	Registrar   string    `json:"registrar"`
	Registrant  string    `json:"registrant"`
	Email       string    `json:"email"`
	Nameservers []string  `json:"nameservers"`
}

type IPHistoryEntry struct {
	Date        time.Time `json:"date"`
	IPAddress   string    `json:"ip_address"`
	Provider    string    `json:"provider"`
	Location    string    `json:"location"`
}

type EmailHistoryEntry struct {
	Date        time.Time `json:"date"`
	Email       string    `json:"email"`
	Type        string    `json:"type"` // admin, tech, registrant
}

// Business Intelligence Types
type CompanyInformation struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Founded       string   `json:"founded"`
	Headquarters  string   `json:"headquarters"`
	EmployeeCount string   `json:"employee_count"`
	Industry      string   `json:"industry"`
	Website       string   `json:"website"`
	SocialLinks   []string `json:"social_links"`
}

type RevenueEstimate struct {
	Amount      int64  `json:"amount"`
	Currency    string `json:"currency"`
	Year        int    `json:"year"`
	Source      string `json:"source"`
	Confidence  string `json:"confidence"`
}

type FundingRound struct {
	Date        time.Time `json:"date"`
	Type        string    `json:"type"`
	Amount      int64     `json:"amount"`
	Currency    string    `json:"currency"`
	Investors   []string  `json:"investors"`
	Valuation   int64     `json:"valuation"`
}

type Acquisition struct {
	Date        time.Time `json:"date"`
	Company     string    `json:"company"`
	Amount      int64     `json:"amount"`
	Currency    string    `json:"currency"`
	Type        string    `json:"type"` // acquired_by, acquired
}

type Patent struct {
	Number      string    `json:"number"`
	Title       string    `json:"title"`
	Date        time.Time `json:"date"`
	Status      string    `json:"status"`
	Inventors   []string  `json:"inventors"`
	Description string    `json:"description"`
}

type Trademark struct {
	Number      string    `json:"number"`
	Mark        string    `json:"mark"`
	Status      string    `json:"status"`
	FiledDate   time.Time `json:"filed_date"`
	Owner       string    `json:"owner"`
}

type NewsArticle struct {
	Title       string    `json:"title"`
	Source      string    `json:"source"`
	URL         string    `json:"url"`
	PublishedAt time.Time `json:"published_at"`
	Summary     string    `json:"summary"`
	Sentiment   string    `json:"sentiment"`
}

type PressRelease struct {
	Title       string    `json:"title"`
	Date        time.Time `json:"date"`
	URL         string    `json:"url"`
	Content     string    `json:"content"`
}

// Dark Web Types
type DarkWebMention struct {
	Source      string    `json:"source"`
	URL         string    `json:"url"`
	Date        time.Time `json:"date"`
	Context     string    `json:"context"`
	Severity    string    `json:"severity"`
	Type        string    `json:"type"`
}

type ThreatIndicator struct {
	Type        string    `json:"type"` // domain, ip, hash, etc.
	Value       string    `json:"value"`
	Source      string    `json:"source"`
	Confidence  int       `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Tags        []string  `json:"tags"`
}

type MalwareSample struct {
	Hash        string    `json:"hash"`
	Type        string    `json:"type"`
	Family      string    `json:"family"`
	FirstSeen   time.Time `json:"first_seen"`
	Source      string    `json:"source"`
	Detections  int       `json:"detections"`
}

type ExploitMention struct {
	CVE         string    `json:"cve"`
	Title       string    `json:"title"`
	Source      string    `json:"source"`
	Date        time.Time `json:"date"`
	Price       string    `json:"price"`
	Availability string   `json:"availability"`
}

type ForumMention struct {
	Forum       string    `json:"forum"`
	Thread      string    `json:"thread"`
	Author      string    `json:"author"`
	Date        time.Time `json:"date"`
	Content     string    `json:"content"`
	URL         string    `json:"url"`
}

type RiskIndicator struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Evidence    string `json:"evidence"`
	Source      string `json:"source"`
}

// ── People Intelligence ──────────────────────────────────────────────────────

// Person represents a discovered employee or person associated with the target.
type Person struct {
	Name       string   `json:"name"`
	Title      string   `json:"title"`
	Department string   `json:"department"`
	Company    string   `json:"company"`
	Location   string   `json:"location"`
	LinkedIn   string   `json:"linkedin_url"`
	GitHub     string   `json:"github_url"`
	Twitter    string   `json:"twitter_url"`
	Email      string   `json:"email"`
	Avatar     string   `json:"avatar_url"`
	Skills     []string `json:"skills"`
	Source     string   `json:"source"` // github, linkedin, crtsh, whois
}

// EmailRecord is a single discovered email address.
type EmailRecord struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	Title      string `json:"title"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"` // High | Medium | Low
	Verified   bool   `json:"verified"`
}

// EmailPattern describes a guessed email format for the target organisation.
type EmailPattern struct {
	Pattern    string   `json:"pattern"`  // e.g. "firstname.lastname"
	Format     string   `json:"format"`   // e.g. "firstname.lastname@target.com"
	Examples   []string `json:"examples"` // up to 3 sample addresses
	Confidence string   `json:"confidence"`
}

// JobListing from public job board APIs (Greenhouse, Lever, etc.)
type JobListing struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Department  string   `json:"department"`
	Location    string   `json:"location"`
	URL         string   `json:"url"`
	PostedAt    string   `json:"posted_at"`
	Source      string   `json:"source"` // greenhouse, lever, indeed, etc.
	TechKeywords []string `json:"tech_keywords"`
}

// TechHiringSignal captures a technology seen in job postings.
type TechHiringSignal struct {
	Technology string   `json:"technology"`
	Category   string   `json:"category"` // Language, Framework, Cloud, Tool, etc.
	JobCount   int      `json:"job_count"`
	Roles      []string `json:"roles"`
}
