package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
	"nightfall-tsukuyomi/internal/active"
	"nightfall-tsukuyomi/internal/models"
)

const mitreEnterpriseStixURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

var attackIDRegex = regexp.MustCompile(`(?i)\bT\d{4}(?:\.\d{3})?\b`)

type FrameworkService struct {
	db     *gorm.DB
	client *http.Client
}

type SyncSummary struct {
	MitreCount     int64 `json:"mitre_count"`
	OwaspCount     int64 `json:"owasp_count"`
	KillChainCount int64 `json:"kill_chain_count"`
	Remapped       int64 `json:"remapped_findings"`
}

func NewFrameworkService(db *gorm.DB) *FrameworkService {
	return &FrameworkService{
		db: db,
		client: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

func (s *FrameworkService) SyncFrameworkData(ctx context.Context, remapAll bool) (*SyncSummary, error) {
	if err := s.syncMitreTTPs(ctx); err != nil {
		return nil, err
	}
	if err := s.seedOwaspCategories(); err != nil {
		return nil, err
	}
	if err := s.seedKillChainPhases(); err != nil {
		return nil, err
	}

	changed, err := s.RemapFindings(ctx, nil, nil, !remapAll)
	if err != nil {
		return nil, err
	}

	var mitreCount, owaspCount, killCount int64
	s.db.Model(&models.MitreTTP{}).Count(&mitreCount)
	s.db.Model(&models.OwaspCategoryRef{}).Count(&owaspCount)
	s.db.Model(&models.KillChainPhaseRef{}).Count(&killCount)

	return &SyncSummary{
		MitreCount:     mitreCount,
		OwaspCount:     owaspCount,
		KillChainCount: killCount,
		Remapped:       changed,
	}, nil
}

func (s *FrameworkService) ListMitreTTPs() ([]models.MitreTTP, error) {
	var rows []models.MitreTTP
	if err := s.db.Order("attack_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *FrameworkService) ListOwaspCategories() ([]models.OwaspCategoryRef, error) {
	var rows []models.OwaspCategoryRef
	if err := s.db.Order("category_id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *FrameworkService) ListKillChainPhases() ([]models.KillChainPhaseRef, error) {
	var rows []models.KillChainPhaseRef
	if err := s.db.Order("sort_order ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// RemapFindings enriches findings from MITRE/OWASP/Kill Chain reference data.
// When onlyUnmapped=true, it updates findings that are missing any framework fields.
func (s *FrameworkService) RemapFindings(ctx context.Context, targetID, scanID *uint, onlyUnmapped bool) (int64, error) {
	var findings []models.Finding
	query := s.db.WithContext(ctx).Model(&models.Finding{})

	if scanID != nil {
		query = query.Where("scan_id = ?", *scanID)
	} else if targetID != nil {
		query = query.Joins("JOIN scans ON scans.id = findings.scan_id").Where("scans.target_id = ?", *targetID)
	}

	if onlyUnmapped {
		query = query.Where("COALESCE(mitre_attack_id, '') = '' OR COALESCE(owasp_category, '') = '' OR COALESCE(kill_chain_phase, '') = ''")
	}

	if err := query.Find(&findings).Error; err != nil {
		return 0, err
	}
	if len(findings) == 0 {
		return 0, nil
	}

	mitreByID, keywordIndex, err := s.loadMitreLookup()
	if err != nil {
		return 0, err
	}

	var changed int64
	for _, f := range findings {
		orig := f
		enrichment := s.enrichFinding(f, mitreByID, keywordIndex)

		if f.MitreAttackID == "" && enrichment.MitreAttackID != "" {
			f.MitreAttackID = enrichment.MitreAttackID
		}
		if f.MitreTactic == "" && enrichment.MitreTactic != "" {
			f.MitreTactic = enrichment.MitreTactic
		}
		if f.MitreTechnique == "" && enrichment.MitreTechnique != "" {
			f.MitreTechnique = enrichment.MitreTechnique
		}
		if f.OwaspCategory == "" && enrichment.OwaspCategory != "" {
			f.OwaspCategory = enrichment.OwaspCategory
		}
		if f.OwaspName == "" && enrichment.OwaspName != "" {
			f.OwaspName = enrichment.OwaspName
		}
		if f.KillChainPhase == "" && enrichment.KillChainPhase != "" {
			f.KillChainPhase = enrichment.KillChainPhase
		}

		if f.MitreAttackID != orig.MitreAttackID ||
			f.MitreTactic != orig.MitreTactic ||
			f.MitreTechnique != orig.MitreTechnique ||
			f.OwaspCategory != orig.OwaspCategory ||
			f.OwaspName != orig.OwaspName ||
			f.KillChainPhase != orig.KillChainPhase {
			if err := s.db.Model(&models.Finding{}).Where("id = ?", f.ID).Updates(map[string]any{
				"mitre_attack_id":  f.MitreAttackID,
				"mitre_tactic":     f.MitreTactic,
				"mitre_technique":  f.MitreTechnique,
				"owasp_category":   f.OwaspCategory,
				"owasp_name":       f.OwaspName,
				"kill_chain_phase": f.KillChainPhase,
			}).Error; err != nil {
				return changed, err
			}
			changed++
		}
	}

	return changed, nil
}

func (s *FrameworkService) enrichFinding(f models.Finding, mitreByID map[string]models.MitreTTP, keywordIndex map[string][]models.MitreTTP) active.EnrichmentMapping {
	// 1) Keep existing static enrichment compatibility.
	base := active.EnrichFinding(f.Category, f.Finding, f.ToolSource)

	// 2) If explicit ATT&CK ID appears in text/category, use it.
	searchText := strings.ToUpper(f.Category + " " + f.Finding + " " + f.Evidence)
	if match := attackIDRegex.FindString(searchText); match != "" {
		if row, ok := mitreByID[strings.ToUpper(match)]; ok {
			base.MitreAttackID = row.AttackID
			base.MitreTechnique = row.Name
			base.MitreTactic = row.Tactic
		}
	}

	// 3) If still missing, best-effort keyword matching against full MITRE technique names.
	if base.MitreAttackID == "" {
		if best, ok := bestKeywordMitreMatch(strings.ToLower(f.Category+" "+f.Finding+" "+f.Evidence), keywordIndex); ok {
			base.MitreAttackID = best.AttackID
			base.MitreTechnique = best.Name
			base.MitreTactic = best.Tactic
		}
	}

	// 4) Fill tactic/technique from MITRE DB if ID exists.
	if base.MitreAttackID != "" {
		if row, ok := mitreByID[strings.ToUpper(base.MitreAttackID)]; ok {
			if base.MitreTechnique == "" {
				base.MitreTechnique = row.Name
			}
			if base.MitreTactic == "" {
				base.MitreTactic = row.Tactic
			}
		}
	}

	// 5) Fill Kill Chain from tactic if missing.
	if base.KillChainPhase == "" && base.MitreTactic != "" {
		base.KillChainPhase = tacticToKillChain(base.MitreTactic)
	}

	// 6) Fill OWASP from tactic if missing.
	if base.OwaspCategory == "" && base.MitreTactic != "" {
		cat, name := tacticToOwasp(base.MitreTactic)
		base.OwaspCategory = cat
		base.OwaspName = name
	}

	return base
}

func (s *FrameworkService) loadMitreLookup() (map[string]models.MitreTTP, map[string][]models.MitreTTP, error) {
	var ttps []models.MitreTTP
	if err := s.db.Find(&ttps).Error; err != nil {
		return nil, nil, err
	}

	byID := make(map[string]models.MitreTTP, len(ttps))
	keywordIndex := make(map[string][]models.MitreTTP, len(ttps)*2)
	for _, t := range ttps {
		byID[strings.ToUpper(t.AttackID)] = t
		for _, token := range normalizedTokens(t.Name) {
			keywordIndex[token] = append(keywordIndex[token], t)
		}
	}
	return byID, keywordIndex, nil
}

func bestKeywordMitreMatch(haystack string, keywordIndex map[string][]models.MitreTTP) (models.MitreTTP, bool) {
	scores := map[string]int{}
	candidate := map[string]models.MitreTTP{}
	for _, tok := range normalizedTokens(haystack) {
		seen := map[string]bool{}
		for _, t := range keywordIndex[tok] {
			if seen[t.AttackID] {
				continue
			}
			scores[t.AttackID]++
			candidate[t.AttackID] = t
			seen[t.AttackID] = true
		}
	}

	type ranked struct {
		id    string
		score int
	}
	var list []ranked
	for id, score := range scores {
		list = append(list, ranked{id: id, score: score})
	}
	if len(list) == 0 {
		return models.MitreTTP{}, false
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].score == list[j].score {
			return list[i].id < list[j].id
		}
		return list[i].score > list[j].score
	})
	if list[0].score < 2 {
		return models.MitreTTP{}, false
	}
	return candidate[list[0].id], true
}

func normalizedTokens(s string) []string {
	clean := strings.NewReplacer("-", " ", "_", " ", "/", " ", ":", " ", ".", " ", ",", " ", "(", " ", ")", " ").Replace(strings.ToLower(s))
	raw := strings.Fields(clean)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if len(r) < 4 {
			continue
		}
		switch r {
		case "technique", "adversaries", "adversary", "information", "application", "using", "through", "victim":
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *FrameworkService) seedOwaspCategories() error {
	refs := []models.OwaspCategoryRef{
		{CategoryID: "A01:2021", Name: "Broken Access Control", Description: "Enforcement of policy constraints is not properly implemented."},
		{CategoryID: "A02:2021", Name: "Cryptographic Failures", Description: "Failures related to cryptography leading to sensitive data exposure."},
		{CategoryID: "A03:2021", Name: "Injection", Description: "Untrusted data is interpreted as command or query."},
		{CategoryID: "A04:2021", Name: "Insecure Design", Description: "Missing or ineffective control design."},
		{CategoryID: "A05:2021", Name: "Security Misconfiguration", Description: "Insecure default settings or incomplete hardening."},
		{CategoryID: "A06:2021", Name: "Vulnerable and Outdated Components", Description: "Known vulnerable or unsupported software components."},
		{CategoryID: "A07:2021", Name: "Identification and Authentication Failures", Description: "Authentication and session management weaknesses."},
		{CategoryID: "A08:2021", Name: "Software and Data Integrity Failures", Description: "Code and infrastructure update integrity failures."},
		{CategoryID: "A09:2021", Name: "Security Logging and Monitoring Failures", Description: "Insufficient logging, detection and response."},
		{CategoryID: "A10:2021", Name: "Server-Side Request Forgery", Description: "Server fetches remote resources without adequate validation."},
	}
	for _, row := range refs {
		if err := s.db.Where("category_id = ?", row.CategoryID).Assign(row).FirstOrCreate(&models.OwaspCategoryRef{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *FrameworkService) seedKillChainPhases() error {
	refs := []models.KillChainPhaseRef{
		{Phase: "Reconnaissance", SortOrder: 1, Description: "Information gathering about the target."},
		{Phase: "Weaponization", SortOrder: 2, Description: "Preparing attack tooling or payloads."},
		{Phase: "Delivery", SortOrder: 3, Description: "Delivering payload to target."},
		{Phase: "Exploitation", SortOrder: 4, Description: "Triggering vulnerability to execute attacker goals."},
		{Phase: "Installation", SortOrder: 5, Description: "Installing persistence/backdoor."},
		{Phase: "Command and Control", SortOrder: 6, Description: "Establishing remote control channel."},
		{Phase: "Actions on Objectives", SortOrder: 7, Description: "Executing final impact objectives."},
	}
	for _, row := range refs {
		if err := s.db.Where("phase = ?", row.Phase).Assign(row).FirstOrCreate(&models.KillChainPhaseRef{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *FrameworkService) syncMitreTTPs(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", mitreEnterpriseStixURL, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("mitre stix fetch failed: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var bundle stixBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return err
	}

	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}
		attackID := obj.attackID()
		if attackID == "" {
			continue
		}
		if !obj.isEnterpriseAttack() {
			continue
		}
		tactic := obj.primaryTactic()
		row := models.MitreTTP{
			AttackID:    strings.ToUpper(attackID),
			Name:        obj.Name,
			Tactic:      tactic,
			Description: obj.Description,
			URL:         obj.attackURL(),
			Source:      "mitre-attack-stix-enterprise",
		}
		if err := s.db.Where("attack_id = ?", row.AttackID).Assign(row).FirstOrCreate(&models.MitreTTP{}).Error; err != nil {
			return err
		}
	}
	return nil
}

type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type               string   `json:"type"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	XMitreDomains      []string `json:"x_mitre_domains"`
	ExternalReferences []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
		URL        string `json:"url"`
	} `json:"external_references"`
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases"`
}

func (o stixObject) attackID() string {
	for _, r := range o.ExternalReferences {
		if strings.EqualFold(r.SourceName, "mitre-attack") && r.ExternalID != "" {
			return r.ExternalID
		}
	}
	return ""
}

func (o stixObject) attackURL() string {
	for _, r := range o.ExternalReferences {
		if strings.EqualFold(r.SourceName, "mitre-attack") && r.URL != "" {
			return r.URL
		}
	}
	return ""
}

func (o stixObject) isEnterpriseAttack() bool {
	for _, d := range o.XMitreDomains {
		if strings.EqualFold(d, "enterprise-attack") {
			return true
		}
	}
	return len(o.XMitreDomains) == 0
}

func (o stixObject) primaryTactic() string {
	for _, kc := range o.KillChainPhases {
		if strings.EqualFold(kc.KillChainName, "mitre-attack") && kc.PhaseName != "" {
			return prettyPhase(kc.PhaseName)
		}
	}
	return ""
}

func prettyPhase(raw string) string {
	parts := strings.Fields(strings.NewReplacer("-", " ", "_", " ").Replace(strings.ToLower(raw)))
	for i, p := range parts {
		if len(p) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func tacticToKillChain(tactic string) string {
	switch strings.ToLower(strings.TrimSpace(tactic)) {
	case "reconnaissance", "resource development":
		return "Reconnaissance"
	case "initial access":
		return "Delivery"
	case "execution", "persistence", "privilege escalation", "defense evasion", "credential access", "discovery", "lateral movement", "collection":
		return "Exploitation"
	case "command and control":
		return "Command and Control"
	case "exfiltration", "impact":
		return "Actions on Objectives"
	default:
		return ""
	}
}

func tacticToOwasp(tactic string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(tactic)) {
	case "initial access", "execution":
		return "A03:2021", "Injection"
	case "credential access", "persistence":
		return "A07:2021", "Identification and Authentication Failures"
	case "discovery", "defense evasion", "resource development", "reconnaissance":
		return "A05:2021", "Security Misconfiguration"
	case "impact", "exfiltration":
		return "A01:2021", "Broken Access Control"
	case "command and control":
		return "A10:2021", "Server-Side Request Forgery"
	default:
		return "", ""
	}
}
