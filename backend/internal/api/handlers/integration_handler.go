package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type IntegrationHandler struct {
	openctiURL   string
	openctiToken string
	openbasURL   string
	openbasToken string
	httpClient   *http.Client
}

func NewIntegrationHandler() *IntegrationHandler {
	return &IntegrationHandler{
		openctiURL:   getEnvOr("OPENCTI_URL", "http://opencti:8080"),
		openctiToken: getEnvOr("OPENCTI_TOKEN", "6476505b-4674-49c3-8acb-57f6f98998ae"),
		openbasURL:   getEnvOr("OPENBAS_URL", "http://openaev:8080"),
		openbasToken: getEnvOr("OPENBAS_TOKEN", "8e2dfb71-51a1-4a19-91e0-f80a91865b29"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func getEnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type PlatformStatus struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Status  string `json:"status"`
	Latency int64  `json:"latency_ms"`
}

// GetIntegrationStatus returns health status for all 3 platforms
func (h *IntegrationHandler) GetIntegrationStatus(c *gin.Context) {
	statuses := []PlatformStatus{
		h.checkPlatform("Nightfall", "http://localhost:8080", "/health"),
		h.checkPlatform("OpenCTI", h.openctiURL, "/health?health_access_key=nightfall123"),
		h.checkPlatform("OpenBAS", h.openbasURL, "/api/health?health_access_key=nightfall123"),
	}

	c.JSON(200, gin.H{
		"platforms": statuses,
	})
}

func (h *IntegrationHandler) checkPlatform(name, baseURL, path string) PlatformStatus {
	start := time.Now()
	resp, err := h.httpClient.Get(baseURL + path)
	latency := time.Since(start).Milliseconds()

	status := "healthy"
	if err != nil || resp == nil || resp.StatusCode >= 400 {
		status = "unhealthy"
	}
	if resp != nil {
		resp.Body.Close()
	}

	return PlatformStatus{
		Name:    name,
		URL:     baseURL,
		Status:  status,
		Latency: latency,
	}
}

// GetOpenCTIThreats proxies a GraphQL query to OpenCTI for threat data
func (h *IntegrationHandler) GetOpenCTIThreats(c *gin.Context) {
	query := `{
		"query": "query { threatActorsIndividuals(first: 25, orderBy: created_at, orderMode: desc) { edges { node { id name description created } } } }"
	}`

	req, err := http.NewRequest("POST", h.openctiURL+"/graphql", strings.NewReader(query))
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.openctiToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(502, gin.H{"error": fmt.Sprintf("opencti unreachable: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		c.JSON(502, gin.H{"error": "invalid response from opencti", "raw": string(body)})
		return
	}

	c.JSON(resp.StatusCode, result)
}

// GetOpenCTIIndicators proxies a GraphQL query to OpenCTI for indicators
func (h *IntegrationHandler) GetOpenCTIIndicators(c *gin.Context) {
	query := `{
		"query": "query { indicators(first: 50, orderBy: created_at, orderMode: desc) { edges { node { id name pattern indicator_types valid_from valid_until created } } } }"
	}`

	req, err := http.NewRequest("POST", h.openctiURL+"/graphql", strings.NewReader(query))
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.openctiToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(502, gin.H{"error": fmt.Sprintf("opencti unreachable: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		c.JSON(502, gin.H{"error": "invalid response from opencti"})
		return
	}

	c.JSON(resp.StatusCode, result)
}

// GetOpenBASSimulations proxies to OpenBAS REST API for simulations
func (h *IntegrationHandler) GetOpenBASSimulations(c *gin.Context) {
	req, err := http.NewRequest("GET", h.openbasURL+"/api/exercises", nil)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+h.openbasToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(502, gin.H{"error": fmt.Sprintf("openbas unreachable: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		c.JSON(502, gin.H{"error": "invalid response from openbas"})
		return
	}

	c.JSON(resp.StatusCode, result)
}

// GetOpenBASScenarios proxies to OpenBAS REST API for scenarios
func (h *IntegrationHandler) GetOpenBASScenarios(c *gin.Context) {
	req, err := http.NewRequest("GET", h.openbasURL+"/api/scenarios", nil)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Authorization", "Bearer "+h.openbasToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		c.JSON(502, gin.H{"error": fmt.Sprintf("openbas unreachable: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		c.JSON(502, gin.H{"error": "invalid response from openbas"})
		return
	}

	c.JSON(resp.StatusCode, result)
}
