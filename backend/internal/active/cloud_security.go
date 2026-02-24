package active

import (
	"fmt"
	"strings"
)

func (s *ActiveScanner) checkCloudMetadata() {
	if !s.config.ShouldRunModule("cloud_metadata") || s.config.Mode == "safe" {
		return
	}

	s.log("Checking cloud metadata endpoints...")

	metadataEndpoints := []string{
		"http://169.254.169.254/latest/meta-data/",                        // AWS
		"http://metadata.google.internal/computeMetadata/v1/",             // GCP
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
	}

	for _, endpoint := range metadataEndpoints {
		// Try to access via SSRF
		testURL := fmt.Sprintf("%s?url=%s", s.target, endpoint)

		resp, err := s.makeRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := s.readBody(resp)
			if len(body) > 0 && !strings.Contains(body, "404") {
				s.addFinding(Finding{
					Severity:    "Critical",
					Category:    "Cloud Metadata",
					Confidence:  "Medium",
					Finding:     "Cloud metadata endpoint potentially accessible via SSRF",
					Remediation: "Block access to cloud metadata endpoints; use IMDSv2 (AWS); implement network segmentation",
					Evidence:    "Metadata endpoint responded",
					HTTPMethod:  "GET",
					Outcome:     "Accessible",
				})
				break
			}
			continue
		}
		resp.Body.Close()
	}
}

func (s *ActiveScanner) checkS3BucketPermissions() {
	if !s.config.ShouldRunModule("s3_permissions") {
		return
	}

	s.log("Checking S3 bucket permissions...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	body := s.readBody(resp)

	// Look for S3 bucket URLs
	if strings.Contains(body, ".s3.amazonaws.com") || strings.Contains(body, "s3://") {
		s.addFinding(Finding{
			Severity:    "Medium",
			Category:    "S3 Bucket",
			Confidence:  "Low",
			Finding:     "S3 bucket references detected (verify bucket permissions manually)",
			Remediation: "Block public S3 access; use bucket policies; enable S3 Block Public Access; use signed URLs",
			Evidence:    "S3 URLs found in response",
			HTTPMethod:  "GET",
			Outcome:     "S3 detected",
		})
	}
}

func (s *ActiveScanner) checkDockerExposure() {
	if !s.config.ShouldRunModule("docker_exposure") {
		return
	}

	s.log("Checking for exposed Docker daemon...")

	dockerPaths := []string{
		":2375/version",
		":2376/version",
		"/v1.24/version",
	}

	for _, path := range dockerPaths {
		url := s.target + path

		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := s.readBody(resp)
			if strings.Contains(body, "Version") && strings.Contains(body, "ApiVersion") {
				s.addFinding(Finding{
					Severity:    "Critical",
					Category:    "Docker Exposure",
					Confidence:  "High",
					Finding:     "Docker daemon exposed without authentication",
					Remediation: "Secure Docker daemon with TLS; use socket activation; never expose to public internet",
					Evidence:    "Docker API accessible",
					HTTPMethod:  "GET",
					Outcome:     "Exposed",
				})
				break
			}
			continue
		}
		resp.Body.Close()
	}
}

func (s *ActiveScanner) checkKubernetesExposure() {
	if !s.config.ShouldRunModule("k8s_exposure") {
		return
	}

	s.log("Checking for exposed Kubernetes API...")

	k8sPaths := []string{
		":6443/version",
		":8080/version",
		"/api/v1",
	}

	for _, path := range k8sPaths {
		url := s.target + path

		resp, err := s.makeRequest("GET", url, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 401 {
			body := s.readBody(resp)
			if strings.Contains(body, "kubernetes") || strings.Contains(body, "k8s") {
				s.addFinding(Finding{
					Severity:    "Critical",
					Category:    "Kubernetes Exposure",
					Confidence:  "Medium",
					Finding:     "Kubernetes API potentially exposed",
					Remediation: "Never expose K8s API publicly; use Network Policies; enable RBAC; use API server firewall",
					Evidence:    "K8s API indicators detected",
					HTTPMethod:  "GET",
					Outcome:     "K8s detected",
				})
				break
			}
			continue
		}
		resp.Body.Close()
	}
}

func (s *ActiveScanner) checkCloudProvider() {
	if !s.config.ShouldRunModule("cloud_provider") {
		return
	}

	s.log("Detecting cloud provider...")

	resp, err := s.makeRequest("GET", s.target, nil)
	if err != nil {
		return
	}

	headers := resp.Header
	body := s.readBody(resp)

	// Check for cloud provider indicators
	if strings.Contains(headers.Get("Server"), "cloudflare") {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Cloud Provider",
			Confidence:  "High",
			Finding:     "Cloudflare detected",
			Remediation: "Ensure Cloudflare WAF is enabled; use Page Rules; enable Bot Management",
			Evidence:    "Cloudflare headers detected",
			HTTPMethod:  "GET",
			Outcome:     "Cloudflare",
		})
	}

	if strings.Contains(body, "x-amz-") || strings.Contains(headers.Get("Server"), "AmazonS3") {
		s.addFinding(Finding{
			Severity:    "Info",
			Category:    "Cloud Provider",
			Confidence:  "High",
			Finding:     "AWS detected",
			Remediation: "Review AWS security best practices; enable GuardDuty; use Security Hub",
			Evidence:    "AWS indicators detected",
			HTTPMethod:  "GET",
			Outcome:     "AWS",
		})
	}
}
