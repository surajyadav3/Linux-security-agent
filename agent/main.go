package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"linux-security-agent/collector"
	"linux-security-agent/sender"
)

type AgentReport struct {
	AgentID   string              `json:"agent_id"`
	Timestamp string              `json:"timestamp"`
	Host      collector.HostInfo  `json:"host"`
	Packages  []collector.Package `json:"packages"`
	CISChecks []collector.CISCheck `json:"cis_checks"`
}

func main() {
	apiEndpoint := flag.String("endpoint", os.Getenv("AGENT_API_ENDPOINT"), "AWS API Gateway endpoint URL")
	outputFile := flag.String("output", "", "Write JSON report to file (skips cloud send)")
	verbose := flag.Bool("verbose", false, "Print report to stdout")
	flag.Parse()

	log.Println("[agent] Linux Security Agent v1.0 starting...")

	host, err := collector.CollectHostInfo()
	if err != nil {
		log.Fatalf("[agent] failed to collect host info: %v", err)
	}
	log.Printf("[agent] Host: %s (%s %s)", host.Hostname, host.OS, host.OSVersion)

	packages, err := collector.CollectPackages()
	if err != nil {
		log.Printf("[agent] WARNING: failed to collect packages: %v", err)
	}
	log.Printf("[agent] Collected %d packages", len(packages))

	checks := collector.RunCISChecks()
	passed := 0
	for _, c := range checks {
		if c.Status == "PASS" {
			passed++
		}
	}
	log.Printf("[agent] CIS checks: %d/%d passed", passed, len(checks))

	report := AgentReport{
		AgentID:   host.Hostname,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Host:      host,
		Packages:  packages,
		CISChecks: checks,
	}

	if *verbose || *outputFile == "-" {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return
	}

	if *outputFile != "" {
		data, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(*outputFile, data, 0644); err != nil {
			log.Fatalf("[agent] failed to write report: %v", err)
		}
		log.Printf("[agent] Report written to %s", *outputFile)
		return
	}

	if *apiEndpoint == "" {
		log.Fatal("[agent] No endpoint specified. Use -endpoint flag or AGENT_API_ENDPOINT env var")
	}

	if err := sender.SendReport(*apiEndpoint, report); err != nil {
		log.Fatalf("[agent] failed to send report: %v", err)
	}
	log.Println("[agent] Report sent successfully")
}
