package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/models"
)

type FindingsHandler struct {
	db *gorm.DB
}

func NewFindingsHandler(db *gorm.DB) *FindingsHandler {
	return &FindingsHandler{db: db}
}

func (h *FindingsHandler) ListFindings(c *gin.Context) {
	var findings []models.Finding
	
	query := h.db.Model(&models.Finding{})
	
	if scanID := c.Query("scan_id"); scanID != "" {
		query = query.Where("scan_id = ?", scanID)
	}
	
	if severity := c.Query("severity"); severity != "" {
		severities := strings.Split(severity, ",")
		query = query.Where("severity IN ?", severities)
	}
	
	if status := c.Query("status"); status != "" {
		statuses := strings.Split(status, ",")
		query = query.Where("status IN ?", statuses)
	}
	
	if category := c.Query("category"); category != "" {
		query = query.Where("category = ?", category)
	}
	
	if assignedTo := c.Query("assigned_to"); assignedTo != "" {
		query = query.Where("assigned_to = ?", assignedTo)
	}

	if toolSource := c.Query("tool_source"); toolSource != "" {
		query = query.Where("tool_source = ?", toolSource)
	}

	if targetID := c.Query("target_id"); targetID != "" {
		query = query.Joins("JOIN scans ON scans.id = findings.scan_id").
			Where("scans.target_id = ?", targetID)
	}
	
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "500"))
	offset := (page - 1) * perPage
	
	var total int64
	query.Count(&total)
	
	result := query.
		Offset(offset).
		Limit(perPage).
		Order("created_at DESC").
		Find(&findings)
	
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   result.Error.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    findings,
		"pagination": gin.H{
			"total":        total,
			"per_page":     perPage,
			"current_page": page,
			"total_pages":  (total + int64(perPage) - 1) / int64(perPage),
		},
	})
}

func (h *FindingsHandler) GetFinding(c *gin.Context) {
	id := c.Param("id")
	var finding models.Finding
	
	if err := h.db.First(&finding, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Finding not found"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"success": true, "data": finding})
}

func (h *FindingsHandler) UpdateFinding(c *gin.Context) {
	id := c.Param("id")
	var input map[string]interface{}
	
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	if err := h.db.Model(&models.Finding{}).Where("id = ?", id).Updates(input).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// TechItem represents a detected technology.
type TechItem struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	Count      int    `json:"count"`
}

// TechStackResult groups detected technologies by category.
type TechStackResult struct {
	Domain      string     `json:"domain"`
	Servers     []TechItem `json:"servers"`
	Frameworks  []TechItem `json:"frameworks"`
	Languages   []TechItem `json:"languages"`
	CMS         []TechItem `json:"cms"`
	Databases   []TechItem `json:"databases"`
	CDN         []TechItem `json:"cdn"`
	Analytics   []TechItem `json:"analytics"`
	JavaScript  []TechItem `json:"javascript"`
	Security    []TechItem `json:"security"`
	Other       []TechItem `json:"other"`
}

func (h *FindingsHandler) GetTechStack(c *gin.Context) {
	var findings []models.Finding
	query := h.db.Model(&models.Finding{}).
		Joins("JOIN scans ON scans.id = findings.scan_id").
		Joins("JOIN targets ON targets.id = scans.target_id")

	if targetID := c.Query("target_id"); targetID != "" {
		query = query.Where("scans.target_id = ?", targetID)
	}

	query.Select("findings.*, targets.domain as _domain, scans.target_id").Find(&findings)

	// Also get target domains for grouping
	type findingWithDomain struct {
		models.Finding
		Domain   string `gorm:"column:_domain"`
		TargetID uint   `gorm:"column:target_id"`
	}

	var fwd []findingWithDomain
	q2 := h.db.Table("findings").
		Select("findings.*, targets.domain as _domain, scans.target_id").
		Joins("JOIN scans ON scans.id = findings.scan_id").
		Joins("JOIN targets ON targets.id = scans.target_id")
	if targetID := c.Query("target_id"); targetID != "" {
		q2 = q2.Where("scans.target_id = ?", targetID)
	}
	q2.Find(&fwd)

	// Group by domain
	domainMap := make(map[string]*TechStackResult)
	techSeen := make(map[string]map[string]bool) // domain -> tech_name -> seen

	for _, f := range fwd {
		domain := f.Domain
		if domain == "" {
			continue
		}
		if _, ok := domainMap[domain]; !ok {
			domainMap[domain] = &TechStackResult{Domain: domain}
			techSeen[domain] = make(map[string]bool)
		}
		result := domainMap[domain]
		seen := techSeen[domain]

		extractTech(f.Finding.Finding, f.Category, f.Evidence, f.ToolSource, result, seen)
	}

	results := make([]TechStackResult, 0, len(domainMap))
	for _, r := range domainMap {
		results = append(results, *r)
	}

	totalTech := 0
	for _, r := range results {
		totalTech += len(r.Servers) + len(r.Frameworks) + len(r.Languages) +
			len(r.CMS) + len(r.Databases) + len(r.CDN) + len(r.Analytics) +
			len(r.JavaScript) + len(r.Security) + len(r.Other)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    results,
		"summary": gin.H{
			"total_technologies": totalTech,
			"targets_analyzed":   len(results),
			"findings_used":      len(fwd),
		},
	})
}

// Tech keyword maps for classification
var serverKeywords = []string{"apache", "nginx", "iis", "lighttpd", "caddy", "tomcat", "gunicorn", "uwsgi", "openresty", "litespeed"}
var frameworkKeywords = []string{"rails", "django", "flask", "express", "laravel", "spring", "nextjs", "next.js", "nuxt", "angular", "react", "vue", "symfony", "fastapi", "gin", "fiber", "koa", "nest", "asp.net", "blazor"}
var languageKeywords = []string{"php", "python", "ruby", "java", "node.js", "nodejs", "perl", "go", "golang", "rust", "c#", ".net"}
var cmsKeywords = []string{"wordpress", "drupal", "joomla", "magento", "shopify", "ghost", "strapi", "contentful", "sanity", "wix", "squarespace"}
var dbKeywords = []string{"mysql", "postgresql", "mongodb", "redis", "elasticsearch", "mariadb", "sqlite", "cassandra", "couchdb", "memcached"}
var cdnKeywords = []string{"cloudflare", "akamai", "fastly", "cloudfront", "stackpath", "keycdn", "bunnycdn", "sucuri"}
var analyticsKeywords = []string{"google analytics", "google tag manager", "gtm", "hotjar", "mixpanel", "segment", "amplitude", "plausible", "matomo"}
var jsKeywords = []string{"jquery", "bootstrap", "lodash", "moment", "axios", "webpack", "vite", "tailwind", "chart.js", "d3.js", "three.js", "alpine", "htmx"}
var securityKeywords = []string{"waf", "hsts", "csp", "x-frame-options", "x-content-type-options", "cors", "rate-limit"}

func extractTech(finding, category, evidence, toolSource string, result *TechStackResult, seen map[string]bool) {
	combined := strings.ToLower(finding + " " + evidence + " " + category)

	addIfMatch := func(keywords []string, dest *[]TechItem, cat string) {
		for _, kw := range keywords {
			if strings.Contains(combined, kw) && !seen[kw] {
				seen[kw] = true
				conf := "Medium"
				if toolSource == "whatweb" || toolSource == "nmap" {
					conf = "High"
				}
				*dest = append(*dest, TechItem{
					Name:       strings.ToUpper(kw[:1]) + kw[1:],
					Source:     toolSource,
					Confidence: conf,
					Count:      1,
				})
			}
		}
	}

	addIfMatch(serverKeywords, &result.Servers, "server")
	addIfMatch(frameworkKeywords, &result.Frameworks, "framework")
	addIfMatch(languageKeywords, &result.Languages, "language")
	addIfMatch(cmsKeywords, &result.CMS, "cms")
	addIfMatch(dbKeywords, &result.Databases, "database")
	addIfMatch(cdnKeywords, &result.CDN, "cdn")
	addIfMatch(analyticsKeywords, &result.Analytics, "analytics")
	addIfMatch(jsKeywords, &result.JavaScript, "javascript")
	addIfMatch(securityKeywords, &result.Security, "security")
}

func (h *FindingsHandler) GetStats(c *gin.Context) {
	var stats []struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	
	h.db.Model(&models.Finding{}).
		Select("severity, count(*) as count").
		Group("severity").
		Scan(&stats)
	
	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}
