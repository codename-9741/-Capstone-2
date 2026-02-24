package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"nightfall-tsukuyomi/internal/active"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <target_url> [mode]")
		fmt.Println("Modes: safe, normal, aggressive")
		os.Exit(1)
	}

	target := os.Args[1]
	mode := "safe"
	if len(os.Args) >= 3 {
		mode = os.Args[2]
	}

	var config *active.ScanConfig
	switch mode {
	case "safe":
		config = active.SafeConfig()
	case "aggressive":
		config = active.AggressiveConfig()
	default:
		config = active.DefaultConfig()
	}

	config.DelayMin = 100
	config.DelayMax = 300

	fmt.Printf("\n🌙 NIGHTFALL TSUKUYOMI - Active Scanner\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Mode: %s\n", mode)
	fmt.Printf("\n")

	scanner := active.NewScanner(target, config)

	done := make(chan *active.ScanResult)
	errChan := make(chan error)

	go func() {
		result, err := scanner.Scan()
		if err != nil {
			errChan <- err
			return
		}
		done <- result
	}()

	var result *active.ScanResult
	select {
	case result = <-done:
	case err := <-errChan:
		log.Fatalf("Scan error: %v", err)
	case <-time.After(2 * time.Minute):
		log.Fatal("Scan timeout after 2 minutes")
	}

	fmt.Printf("\n📊 SCAN RESULTS\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Duration: %v\n", result.Duration)
	fmt.Printf("Enabled Modules: %d\n", result.EnabledModules)
	fmt.Printf("Attempted Modules (instrumented): %d\n", result.AttemptedModules)
	fmt.Printf("Completed Modules (instrumented): %d\n", result.CompletedModules)
	fmt.Printf("Errored Modules (instrumented): %d\n", result.ErroredModules)
	fmt.Printf("Skipped Modules (instrumented): %d\n", result.SkippedModules)
	fmt.Printf("Successful Requests: %d\n", result.SuccessfulRequests)
	fmt.Printf("Total Requests: %d\n", result.TotalRequests)
	fmt.Printf("Errored Requests: %d\n", result.ErroredRequests)
	fmt.Printf("Total Findings: %d\n\n", len(result.Findings))

	severityCounts := make(map[string]int)
	for _, f := range result.Findings {
		severityCounts[f.Severity]++
	}

	fmt.Printf("🔴 Critical: %d\n", severityCounts["Critical"])
	fmt.Printf("🟠 High: %d\n", severityCounts["High"])
	fmt.Printf("🟡 Medium: %d\n", severityCounts["Medium"])
	fmt.Printf("🔵 Low: %d\n", severityCounts["Low"])
	fmt.Printf("ℹ️  Info: %d\n", severityCounts["Info"])

	criticalHigh := []active.Finding{}
	for _, f := range result.Findings {
		if f.Severity == "Critical" || f.Severity == "High" {
			criticalHigh = append(criticalHigh, f)
		}
	}

	if len(criticalHigh) > 0 {
		fmt.Printf("\n⚠️  CRITICAL & HIGH SEVERITY:\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		for i, f := range criticalHigh {
			fmt.Printf("\n%d. [%s] %s\n", i+1, f.Severity, f.Finding)
			fmt.Printf("   Remediation: %s\n", f.Remediation)
		}
	}

	jsonData, _ := json.MarshalIndent(result, "", "  ")
	filename := fmt.Sprintf("scan-%s.json", result.StartTime.Format("20060102-150405"))
	os.WriteFile(filename, jsonData, 0644)
	fmt.Printf("\n✅ Saved: %s\n\n", filename)
}
