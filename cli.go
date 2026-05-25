package main

import (
	"fmt"
	"os"
	"strings"

	"flaregate/internal/cloudflare"
	"flaregate/internal/config"
)

func runCLI() {
	if len(os.Args) < 2 {
		printCLIUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "serve":
		// already handled in main()
		return
	case "provision":
		cliProvision()
	case "hostname":
		if len(os.Args) < 3 {
			fmt.Println("Usage: flaregate hostname <list|add|remove>")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "list":
			cliHostnameList()
		case "add":
			cliHostnameAdd()
		case "remove":
			cliHostnameRemove()
		default:
			fmt.Printf("Unknown hostname subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	case "status":
		cliStatus()
	case "token":
		cliToken()
	case "help", "-h", "--help":
		printCLIUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printCLIUsage()
		os.Exit(1)
	}
}

func printCLIUsage() {
	fmt.Println(strings.TrimSpace(`
FlareGate — Cloudflare Tunnel management for NAT VPS

Usage:
  flaregate serve                        Start web dashboard (default)
  flaregate provision <hostname> <target> Create tunnel + DNS + ingress
  flaregate hostname list                List all hostnames
  flaregate hostname add <h> <t>         Add hostname to existing tunnel
  flaregate hostname remove <hostname>   Remove hostname
  flaregate status                       Show config and tunnel status
  flaregate token                        Print cloudflared run command

Examples:
  flaregate serve
  flaregate provision app.example.com localhost:3000
  flaregate hostname add api.example.com 127.0.0.1:8080
  flaregate hostname remove api.example.com
  flaregate token
`))
}

func mustGetConfig() *config.Config {
	cfg, err := config.GetAppConfig()
	if err != nil || cfg == nil {
		fmt.Fprintf(os.Stderr, "Error: FlareGate not configured. Run 'flaregate serve' first to set up.\n")
		os.Exit(1)
	}
	return cfg
}

func cliProvision() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: flaregate provision <hostname> <target>")
		fmt.Println("Example: flaregate provision app.example.com localhost:3000")
		os.Exit(1)
	}
	hostname := os.Args[2]
	target := os.Args[3]
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	target, err = normalizeService(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfg := mustGetConfig()

	zoneID, zoneName, err := cloudflare.ResolveZoneByHostname(cfg.APIToken, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving zone: %v\n", err)
		os.Exit(1)
	}

	dns, err := cloudflare.EnsureTunnelDNSRecord(cfg.APIToken, zoneID, hostname, cfg.TunnelID, "Managed by FlareGate")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating DNS: %v\n", err)
		os.Exit(1)
	}

	changed, err := mutateTunnelIngress(cfg, func(ingress []interface{}) ([]interface{}, bool, error) {
		return upsertIngressRule(ingress, hostname, target)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error updating ingress: %v\n", err)
		os.Exit(1)
	}
	if changed {
		scheduleTunnelRestart(cfg)
	}

	dnsID, _ := dns["id"].(string)
	fmt.Printf("✅ %s → %s\n", hostname, target)
	fmt.Printf("   Zone:    %s (%s)\n", zoneName, zoneID)
	fmt.Printf("   DNS:     %s\n", dnsID)
	fmt.Printf("   Tunnel:  %s (%s)\n", cfg.TunnelName, cfg.TunnelID)
}

func cliHostnameList() {
	cfg := mustGetConfig()
	ingress, err := loadVisibleIngress(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if len(ingress) == 0 {
		fmt.Println("No hostnames configured.")
		return
	}
	for _, item := range ingress {
		rule, _ := item.(map[string]interface{})
		h, _ := rule["hostname"].(string)
		s, _ := rule["service"].(string)
		fmt.Printf("  %-40s → %s\n", h, s)
	}
}

func cliHostnameAdd() {
	// Just fall through to provision
	cliProvision()
}

func cliHostnameRemove() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: flaregate hostname remove <hostname>")
		os.Exit(1)
	}
	hostname, err := normalizeHostname(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfg := mustGetConfig()

	changed, err := mutateTunnelIngress(cfg, func(ingress []interface{}) ([]interface{}, bool, error) {
		updated, found, ch, e := removeIngressRule(ingress, hostname)
		if !found {
			return ingress, false, fmt.Errorf("hostname %s not found", hostname)
		}
		return updated, ch, e
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if changed {
		scheduleTunnelRestart(cfg)
	}

	// Best-effort DNS cleanup
	zoneID, _, err := cloudflare.ResolveZoneByHostname(cfg.APIToken, hostname)
	if err == nil {
		cloudflare.DeleteTunnelDNSRecordsByHostname(cfg.APIToken, zoneID, hostname)
	}

	fmt.Printf("✅ Removed %s\n", hostname)
}

func cliStatus() {
	cfg, err := config.GetAppConfig()
	if err != nil || cfg == nil {
		fmt.Println("FlareGate: not configured")
		return
	}
	fmt.Printf("Account:  %s\n", cfg.AccountID)
	fmt.Printf("Tunnel:   %s (%s)\n", cfg.TunnelName, cfg.TunnelID)
	if runner != nil && runner.IsRunning() {
		fmt.Println("cloudflared: running")
	} else {
		fmt.Println("cloudflared: stopped")
	}
	fmt.Printf("Port:     %s\n", os.Getenv("PORT"))

	ingress, err := loadVisibleIngress(cfg)
	if err == nil && len(ingress) > 0 {
		fmt.Printf("\nHostnames (%d):\n", len(ingress))
		for _, item := range ingress {
			rule, _ := item.(map[string]interface{})
			h, _ := rule["hostname"].(string)
			s, _ := rule["service"].(string)
			fmt.Printf("  %s → %s\n", h, s)
		}
	}
}

func cliToken() {
	cfg := mustGetConfig()
	fmt.Printf("cloudflared tunnel run --token %s\n", cfg.TunnelToken)
}
