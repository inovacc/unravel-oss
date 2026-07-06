/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/schema"

	"github.com/spf13/cobra"
)

var (
	schemaAI    bool
	schemaAIMCP bool
)

var schemaCmd = &cobra.Command{
	Use:   "schema <path>",
	Short: "Extract application schema from dissected app",
	Long: `Extract a taxonomic application schema describing communication patterns,
authentication methods, storage mechanisms, IPC channels, stealth features, and
telemetry from an application file.

The schema is machine-readable so another AI can replicate the application
in a different framework (e.g., Electron → Tauri, PWA → Electron).

Examples:
  unravel schema ./app.apk
  unravel schema ./app.asar --json
  unravel schema ./binary.exe --ai -o ./report
  unravel schema ./app.apk --ai-mcp`,
	Args: cobra.ExactArgs(1),
	Run:  runSchema,
}

func init() {
	appCmd.AddCommand(schemaCmd)
	schemaCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
	schemaCmd.Flags().BoolVar(&schemaAI, "ai", false, "Enrich schema with AI analysis (requires running inside `unravel mcp serve`)")
	schemaCmd.Flags().BoolVar(&schemaAIMCP, "ai-mcp", false, "Return AI prompt for Claude Code to process directly")
}

func runSchema(_ *cobra.Command, args []string) {
	path := args[0]

	result, err := dissect.Run(path, dissect.Options{
		Verbose:   verbose,
		OutputDir: output,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	opts := schema.Options{
		AIAnalysis:    schemaAI,
		AIAnalysisMCP: schemaAIMCP,
	}

	appSchema, err := schema.Extract(result, opts)
	if err != nil {
		fmt.Printf("Error extracting schema: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat || schemaAIMCP {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(appSchema)
	} else {
		printSchema(appSchema)
	}

	if output != "" {
		data, _ := json.MarshalIndent(appSchema, "", "  ")
		outPath := filepath.Join(output, "schema.json")
		if err := os.MkdirAll(output, 0755); err != nil {
			fmt.Printf("Error creating output dir: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			fmt.Printf("Error writing schema: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nSchema written to: %s\n", outPath)
	}
}

func printSchema(s *schema.ApplicationSchema) {
	fmt.Printf("Application Schema: %s\n", s.AppName)
	fmt.Printf("  Framework:  %s\n", s.Framework)
	if s.Version != "" {
		fmt.Printf("  Version:    %s\n", s.Version)
	}
	fmt.Printf("  Confidence: %.0f%%\n\n", s.Confidence*100)

	if len(s.Communication.Endpoints) > 0 {
		fmt.Printf("Communication (%d endpoints)\n", len(s.Communication.Endpoints))
		for _, ep := range s.Communication.Endpoints {
			fmt.Printf("  %-10s %s\n", ep.Purpose, ep.URL)
		}
		fmt.Println()
	}

	if len(s.Auth.Methods) > 0 {
		fmt.Printf("Authentication (%d methods)\n", len(s.Auth.Methods))
		for _, m := range s.Auth.Methods {
			fmt.Printf("  %s (%s)\n", m.Type, m.Implementation)
		}
		fmt.Println()
	}

	if len(s.Storage.Databases) > 0 || len(s.Storage.LocalStorage) > 0 {
		fmt.Printf("Storage (%d databases, %d local)\n", len(s.Storage.Databases), len(s.Storage.LocalStorage))
		for _, db := range s.Storage.Databases {
			fmt.Printf("  [%s] %s\n", db.Type, db.Purpose)
		}
		fmt.Println()
	}

	if len(s.IPC.Channels) > 0 {
		fmt.Printf("IPC (%d channels)\n", len(s.IPC.Channels))
		for _, ch := range s.IPC.Channels {
			fmt.Printf("  %s (%s)\n", ch.Name, ch.Direction)
		}
		fmt.Println()
	}

	if s.Stealth.ScreenCaptureBlock || s.Stealth.CodeObfuscation != "" || len(s.Stealth.AntiDebugging) > 0 {
		fmt.Println("Stealth Features")
		if s.Stealth.ScreenCaptureBlock {
			fmt.Println("  Screen capture blocked")
		}
		if s.Stealth.CodeObfuscation != "" {
			fmt.Printf("  Obfuscation: %s\n", s.Stealth.CodeObfuscation)
		}
		for _, ad := range s.Stealth.AntiDebugging {
			fmt.Printf("  Anti-debug: %s\n", ad)
		}
		fmt.Println()
	}

	if len(s.Telemetry.Services) > 0 {
		fmt.Printf("Telemetry (%d services)\n", len(s.Telemetry.Services))
		for _, svc := range s.Telemetry.Services {
			fmt.Printf("  %s\n", svc.Name)
		}
		fmt.Println()
	}

	if s.Security.RiskScore > 0 || len(s.Security.DangerousPermissions) > 0 {
		fmt.Printf("Security (risk: %d/100)\n", s.Security.RiskScore)
		if s.Security.Debuggable {
			fmt.Println("  WARNING: debuggable")
		}
		for _, p := range s.Security.DangerousPermissions {
			fmt.Printf("  DANGEROUS: %s\n", p)
		}
		fmt.Println()
	}

	if s.AIPrompt != "" {
		fmt.Printf("AI Prompt (%d chars) — use with Claude Code for deeper analysis\n", len(s.AIPrompt))
	}
}
