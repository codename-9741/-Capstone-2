package services

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"nightfall-tsukuyomi/internal/models"
)

type OpenCTIService struct {
	url         string
	token       string
	client      *http.Client
	connectorID string
}

func NewOpenCTIService() *OpenCTIService {
	return &OpenCTIService{
		url:   envOr("OPENCTI_URL", "http://opencti:8080"),
		token: envOr("OPENCTI_TOKEN", "6476505b-4674-49c3-8acb-57f6f98998ae"),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		connectorID: envOr("OPENCTI_IMPORT_CONNECTOR_ID", "import-stix"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func severityToConfidence(severity string) int {
	switch severity {
	case "Critical":
		return 80
	case "High":
		return 65
	case "Medium":
		return 45
	case "Low":
		return 25
	default:
		return 10
	}
}

func severityScore(s string) int {
	switch s {
	case "Critical":
		return 90
	case "High":
		return 75
	case "Medium":
		return 50
	case "Low":
		return 25
	default:
		return 10
	}
}

type OpenCTIConnector struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	ConnectorType  string   `json:"connector_type"`
	ConnectorScope []string `json:"connector_scope"`
	ConnectorState *string  `json:"connector_state"`
}

func (s *OpenCTIService) ExportScan(scan models.Scan, findings []models.Finding, target models.Target) (string, error) {
	if s == nil {
		return "", fmt.Errorf("opencti service disabled")
	}

	bundleID, bundle, err := s.buildBundle(scan, findings, target)
	if err != nil {
		return "", err
	}

	query := `
mutation StixBundlePush($connectorId: String!, $bundle: String!) {
	stixBundlePush(connectorId: $connectorId, bundle: $bundle)
}`

	payload := map[string]interface{}{
		"query": query,
		"variables": map[string]interface{}{
			"connectorId": s.connectorID,
			"bundle":      string(bundle),
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", s.url+"/graphql", bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		return "", fmt.Errorf("opencti import failed: %s", string(respBody))
	}

	if errs, ok := respData["errors"]; ok && errs != nil {
		return "", fmt.Errorf("opencti errors: %v", errs)
	}

	data, ok := respData["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected opencti response: %s", string(respBody))
	}

	value, ok := data["stixBundlePush"]
	if !ok {
		return "", fmt.Errorf("opencti response missing stixBundlePush: %s", string(respBody))
	}

	pushed, ok := value.(bool)
	if !ok {
		return "", fmt.Errorf("unexpected opencti response: %s", string(respBody))
	}

	if !pushed {
		return "", fmt.Errorf("stixBundlePush returned false")
	}

	return bundleID, nil
}

func (s *OpenCTIService) ListConnectors() ([]OpenCTIConnector, error) {
	if s == nil {
		return nil, fmt.Errorf("opencti service disabled")
	}

	query := `
query {
	connectors {
		id
		name
		connector_type
		connector_scope
		connector_state
	}
}`

	payload := map[string]interface{}{
		"query": query,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", s.url+"/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result struct {
		Data struct {
			Connectors []OpenCTIConnector `json:"connectors"`
		} `json:"data"`
		Errors []interface{} `json:"errors"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("opencti connectors query failed: %s", string(respBody))
	}

	if len(result.Errors) > 0 {
		return nil, fmt.Errorf("opencti errors: %v", result.Errors)
	}

	return result.Data.Connectors, nil
}

func (s *OpenCTIService) buildBundle(scan models.Scan, findings []models.Finding, target models.Target) (string, []byte, error) {
	bundleID := "bundle--" + newUUID()
	objects := make([]map[string]interface{}, 0, len(findings)+1)
	indicatorIDs := make([]string, 0, len(findings))

	for _, finding := range findings {
		id := "indicator--" + newUUID()
		indicator := map[string]interface{}{
			"type":            "indicator",
			"id":              id,
			"name":            fmt.Sprintf("[%s] %s", finding.Severity, finding.Category),
			"description":     fmt.Sprintf("%s | Evidence: %s", finding.Finding, finding.Evidence),
			"pattern":         fmt.Sprintf("[url:value = '%s']", target.Domain),
			"pattern_type":    "stix",
			"valid_from":      time.Now().UTC().Format(time.RFC3339),
			"confidence":      severityToConfidence(finding.Severity),
			"x_opencti_score": severityScore(finding.Severity),
		}
		objects = append(objects, indicator)
		indicatorIDs = append(indicatorIDs, id)
	}

	completedAt := time.Now().UTC()
	if scan.CompletedAt != nil {
		completedAt = scan.CompletedAt.UTC()
	}

	report := map[string]interface{}{
		"type":        "report",
		"id":          "report--" + newUUID(),
		"name":        fmt.Sprintf("Scan %d — Nightfall %s", scan.ID, target.Domain),
		"description": fmt.Sprintf("Scan completed at %s with %d findings", completedAt.Format(time.RFC3339), len(findings)),
		"published":   completedAt.Format(time.RFC3339),
		"object_refs": indicatorIDs,
	}
	objects = append(objects, report)

	bundle := map[string]interface{}{
		"type":    "bundle",
		"id":      bundleID,
		"objects": objects,
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		return "", nil, err
	}

	return bundleID, raw, nil
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
