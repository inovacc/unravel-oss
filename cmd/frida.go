/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/frida"
	"github.com/inovacc/unravel-oss/pkg/frida/enrich"

	"github.com/spf13/cobra"
)

var (
	fridaSSL        bool
	fridaRoot       bool
	fridaDebugF     bool
	fridaNetwork    bool
	fridaStorage    bool
	fridaCrypto     bool
	fridaIPC        bool
	fridaAll        bool
	fridaCapture    bool
	fridaHooks      []string
	fridaPackage    string
	fridaRunHost    string
	fridaRunDev     string
	fridaRunSpawn   bool
	fridaTimeout    time.Duration
	fridaScriptFile string

	// Phase 9 (D-04, D-26): AI-enriched comments + validate subcommand.
	fridaAI        bool
	fridaSourceDir string
)

var fridaCmd = &cobra.Command{
	Use:   "frida",
	Short: "Generate Frida instrumentation scripts for Android apps",
	Long: `Generate Frida JavaScript hook scripts for dynamic analysis of Android applications.

Scripts can be auto-generated from APK analysis (dissect) or manually configured
with specific hook categories.

Examples:
  unravel frida generate ./app.apk -o ./scripts/
  unravel frida generate ./app.apk --all
  unravel frida generate --package com.example.app --ssl --root --crypto
`,
}

var fridaGenerateCmd = &cobra.Command{
	Use:   "generate [apk_path]",
	Short: "Generate Frida hook scripts",
	Long: `Generate Frida JavaScript scripts for dynamic analysis.

When an APK path is provided, the tool runs analysis to auto-detect which hooks
are needed. When --package is provided without an APK, scripts are generated
based on the specified flags.`,
	RunE: runFridaGenerate,
}

var fridaRunCmd = &cobra.Command{
	Use:   "run [apk_path]",
	Short: "Run Frida scripts against a target app",
	Long: `Execute Frida instrumentation scripts on a running or spawned Android app.

When an APK path is given, scripts are auto-generated from analysis and then
executed. When --package is given with hook flags, scripts are generated and run.
When --package is given with --script, the specified script file is loaded and run.

Examples:
  unravel frida run ./app.apk -o ./output/
  unravel frida run --package com.example.app --script ./scripts/ssl_bypass.js
  unravel frida run --package com.example.app --all --device emulator-5554
  unravel frida run --package com.example.app --ssl --spawn`,
	RunE: runFridaRun,
}

func init() {
	fridaGenerateCmd.Flags().BoolVar(&fridaSSL, "ssl", false, "include SSL pinning bypass")
	fridaGenerateCmd.Flags().BoolVar(&fridaRoot, "root", false, "include root detection bypass")
	fridaGenerateCmd.Flags().BoolVar(&fridaDebugF, "anti-debug", false, "include anti-debug bypass")
	fridaGenerateCmd.Flags().BoolVar(&fridaNetwork, "network", false, "include network traffic capture")
	fridaGenerateCmd.Flags().BoolVar(&fridaStorage, "storage", false, "include storage monitoring")
	fridaGenerateCmd.Flags().BoolVar(&fridaCrypto, "crypto", false, "include crypto API hooking")
	fridaGenerateCmd.Flags().BoolVar(&fridaIPC, "ipc", false, "include IPC monitoring")
	fridaGenerateCmd.Flags().BoolVar(&fridaAll, "all", false, "enable all hook categories")
	fridaGenerateCmd.Flags().StringArrayVar(&fridaHooks, "hook", nil, "custom class.method hook pattern (repeatable)")
	fridaGenerateCmd.Flags().BoolVar(&fridaCapture, "capture", false, "generate traffic capture templates (mitmproxy, pcapdroid, burp, charles)")
	fridaGenerateCmd.Flags().StringVar(&fridaPackage, "package", "", "target app package name (skips APK analysis)")
	// Phase 9 (D-04 / FRIDA-01): AI-enriched per-hook comments.
	fridaGenerateCmd.Flags().BoolVar(&fridaAI, "ai", false, "Enrich generated scripts with AI-driven per-hook comments + criteria.json sidecars")
	fridaGenerateCmd.Flags().StringVar(&fridaSourceDir, "source-dir", "", "Decompiled source root used as MCP prompt context when --ai is set")

	fridaRunCmd.Flags().StringVar(&fridaRunHost, "host", "127.0.0.1:27042", "frida-server host:port")
	fridaRunCmd.Flags().StringVar(&fridaRunDev, "device", "", "target device ID (direct USB)")
	fridaRunCmd.Flags().DurationVar(&fridaTimeout, "timeout", 30*time.Second, "per-script execution timeout")
	fridaRunCmd.Flags().BoolVar(&fridaRunSpawn, "spawn", false, "spawn app with -f instead of attaching with -n")
	fridaRunCmd.Flags().StringVar(&fridaScriptFile, "script", "", "path to a specific .js script file to run")
	fridaRunCmd.Flags().BoolVar(&fridaSSL, "ssl", false, "include SSL pinning bypass")
	fridaRunCmd.Flags().BoolVar(&fridaRoot, "root", false, "include root detection bypass")
	fridaRunCmd.Flags().BoolVar(&fridaDebugF, "anti-debug", false, "include anti-debug bypass")
	fridaRunCmd.Flags().BoolVar(&fridaNetwork, "network", false, "include network traffic capture")
	fridaRunCmd.Flags().BoolVar(&fridaStorage, "storage", false, "include storage monitoring")
	fridaRunCmd.Flags().BoolVar(&fridaCrypto, "crypto", false, "include crypto API hooking")
	fridaRunCmd.Flags().BoolVar(&fridaIPC, "ipc", false, "include IPC monitoring")
	fridaRunCmd.Flags().BoolVar(&fridaAll, "all", false, "enable all hook categories")
	fridaRunCmd.Flags().StringVar(&fridaPackage, "package", "", "target app package name")
	fridaRunCmd.Flags().StringArrayVar(&fridaHooks, "hook", nil, "custom class.method hook pattern (repeatable)")

	fridaCmd.AddCommand(fridaGenerateCmd)
	fridaCmd.AddCommand(fridaRunCmd)
	fridaCmd.AddCommand(fridaValidateCmd)
	rootCmd.AddCommand(fridaCmd)
}

// Phase 9 (D-26 / FRIDA-02): post-capture validator subcommand.
var fridaValidateCmd = &cobra.Command{
	Use:   "validate <criteria.json> <capture.json>",
	Short: "Run post-capture validation against per-hook criteria",
	Long: `Evaluate captured Frida events against a criteria.json file. Each criterion
is tagged BLOCK / FLAG / PASS. JSON report goes to stdout (or --output dir);
a Markdown sibling is always written next to the JSON report.

Examples:
  unravel frida validate ./scripts/ssl_pinning.criteria.json ./capture.json
  unravel frida validate ./crit.json ./cap.json -o ./reports/`,
	Args: cobra.ExactArgs(2),
	RunE: runFridaValidate,
}

func runFridaValidate(_ *cobra.Command, args []string) error {
	criteriaPath, capturePath := args[0], args[1]
	report, err := frida.Validate(criteriaPath, capturePath)
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}

	outDir := output
	if outDir == "" {
		outDir = filepath.Dir(capturePath)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	mdPath := filepath.Join(outDir, "validation.md")
	if err := frida.WriteMarkdown(report, mdPath); err != nil {
		return fmt.Errorf("write markdown: %w", err)
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Printf("Validation: %d criteria — %d BLOCK, %d FLAG, %d PASS\n",
		report.Summary.Total, report.Summary.Block, report.Summary.Flag, report.Summary.Pass)
	fmt.Printf("Markdown report: %s\n", mdPath)
	return nil
}

// runFridaEnrichScripts enriches each script in result with AI-driven
// per-hook comments + criteria.json sidecars (Phase 9 D-04 / FRIDA-01).
// Called only when --ai is set and writeScripts already wrote the .js
// files to disk.
func runFridaEnrichScripts(ctx context.Context, scriptDir string) error {
	orch := enrich.New()
	entries, err := os.ReadDir(scriptDir)
	if err != nil {
		return fmt.Errorf("read script dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".js" {
			continue
		}
		scriptPath := filepath.Join(scriptDir, e.Name())
		if _, err := orch.Enrich(ctx, scriptPath, fridaSourceDir); err != nil {
			fmt.Fprintf(os.Stderr, "  enrich %s: %v\n", e.Name(), err)
			continue
		}
		if verbose {
			fmt.Printf("  enriched %s\n", e.Name())
		}
	}
	return nil
}

func runFridaGenerate(cmd *cobra.Command, args []string) error {
	var result *frida.GenerateResult

	if len(args) > 0 {
		targetPath := args[0]

		// Detect first; APKs go down the JVM path, native binaries (PE, ELF,
		// Mach-O) go to the native-export generator and skip dissect-on-APK.
		dr, derr := detect.Detect(targetPath)
		if derr == nil && isNativeFridaTarget(dr.FileType) {
			cfg := buildManualConfig()
			cfg.Target = nativeTargetFor(dr.FileType)
			if cfg.PackageName == "" {
				cfg.PackageName = filepath.Base(targetPath)
			}
			// Native targets: default to crypto+network when no flags given.
			if !fridaSSL && !fridaNetwork && !fridaCrypto && !fridaDebugF && !fridaAll && len(fridaHooks) == 0 {
				cfg.IncludeNetwork = true
				cfg.IncludeCrypto = true
			}
			result = frida.Generate(cfg)
		} else {
			// APK / Java / unknown -> run dissect-based auto-detection.
			ddr, err := dissect.Run(targetPath, dissect.Options{
				Verbose: verbose,
				Debug:   debug.NopRecorder(),
			})
			if err != nil {
				return fmt.Errorf("analyze APK: %w", err)
			}

			if ddr.FridaScripts != nil {
				result = ddr.FridaScripts
			} else {
				result = frida.Generate(frida.ScriptConfig{IncludeNetwork: true})
			}

			applyManualFlags(result, ddr)
		}
	} else if fridaPackage != "" {
		// Manual configuration mode
		config := buildManualConfig()
		result = frida.Generate(config)

		if fridaCapture || fridaAll {
			result.CaptureTemplates = frida.GenerateCapture(fridaPackage, nil)
		}
	} else {
		return fmt.Errorf("provide an APK path or --package flag")
	}

	// Output
	if output != "" {
		if err := writeScripts(result, output); err != nil {
			return err
		}
		if fridaAI {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			if err := runFridaEnrichScripts(ctx, output); err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: AI enrichment partial failure: %v\n", err)
			}
		}
		return nil
	}

	return printScripts(result)
}

func buildManualConfig() frida.ScriptConfig {
	config := frida.ScriptConfig{
		PackageName:    fridaPackage,
		IncludeSSL:     fridaSSL || fridaAll,
		IncludeRoot:    fridaRoot || fridaAll,
		IncludeDebug:   fridaDebugF || fridaAll,
		IncludeNetwork: fridaNetwork || fridaAll,
		IncludeStorage: fridaStorage || fridaAll,
		IncludeCrypto:  fridaCrypto || fridaAll,
		IncludeIPC:     fridaIPC || fridaAll,
		CustomHooks:    fridaHooks,
	}

	// Default to network if nothing specified
	if !fridaSSL && !fridaRoot && !fridaDebugF && !fridaNetwork &&
		!fridaStorage && !fridaCrypto && !fridaIPC && !fridaAll {
		config.IncludeNetwork = true
	}

	return config
}

func applyManualFlags(result *frida.GenerateResult, dr *dissect.DissectResult) {
	if !fridaAll && !fridaSSL && !fridaRoot && !fridaDebugF &&
		!fridaNetwork && !fridaStorage && !fridaCrypto && !fridaIPC && len(fridaHooks) == 0 {
		return // no manual overrides, use auto-detection as-is
	}

	// Rebuild with merged config
	config := frida.ScriptConfig{
		PackageName:    result.PackageName,
		IncludeSSL:     fridaSSL || fridaAll,
		IncludeRoot:    fridaRoot || fridaAll,
		IncludeDebug:   fridaDebugF || fridaAll,
		IncludeNetwork: fridaNetwork || fridaAll,
		IncludeStorage: fridaStorage || fridaAll,
		IncludeCrypto:  fridaCrypto || fridaAll,
		IncludeIPC:     fridaIPC || fridaAll,
		CustomHooks:    fridaHooks,
	}

	// Override package from manifest if not set manually
	if fridaPackage != "" {
		config.PackageName = fridaPackage
	} else if dr.ManifestInfo != nil && dr.ManifestInfo.Package != "" {
		config.PackageName = dr.ManifestInfo.Package
	}

	merged := frida.Generate(config)
	merged.AutoDetected = result.AutoDetected
	*result = *merged
}

func writeScripts(result *frida.GenerateResult, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	for _, s := range result.Scripts {
		path := filepath.Join(dir, s.Name+".js")
		if err := os.WriteFile(path, []byte(s.Content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}

		if verbose {
			fmt.Printf("  wrote %s (%s)\n", path, s.Description)
		}
	}

	fmt.Printf("Generated %d Frida scripts in %s\n", len(result.Scripts), dir)

	if len(result.AutoDetected) > 0 {
		fmt.Println("Auto-detected:")
		for _, ad := range result.AutoDetected {
			fmt.Printf("  - %s\n", ad)
		}
	}

	// Write capture templates
	if result.CaptureTemplates != nil {
		for _, tmpl := range result.CaptureTemplates.Templates {
			path := filepath.Join(dir, tmpl.Name+"."+tmpl.Format)
			if err := os.WriteFile(path, []byte(tmpl.Content), 0644); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}

			if verbose {
				fmt.Printf("  wrote %s (%s)\n", path, tmpl.Description)
			}
		}

		fmt.Printf("Generated %d capture templates in %s\n", len(result.CaptureTemplates.Templates), dir)
	}

	// Write manifest
	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := json.MarshalIndent(result, "", "  ")
	if err == nil {
		_ = os.WriteFile(manifestPath, data, 0644)
	}

	return nil
}

func runFridaRun(_ *cobra.Command, args []string) error {
	var scripts []frida.GeneratedScript
	packageName := fridaPackage

	if fridaScriptFile != "" && packageName != "" {
		// Run a specific script file
		content, err := os.ReadFile(fridaScriptFile)
		if err != nil {
			return fmt.Errorf("read script file: %w", err)
		}

		scripts = []frida.GeneratedScript{{
			Name:        filepath.Base(fridaScriptFile),
			Description: "user-provided script",
			Content:     string(content),
			Category:    "custom",
		}}
	} else if len(args) > 0 {
		// APK path: analyze and generate scripts
		apkPath := args[0]

		dr, err := dissect.Run(apkPath, dissect.Options{
			Verbose: verbose,
			Debug:   debug.NopRecorder(),
		})
		if err != nil {
			return fmt.Errorf("analyze APK: %w", err)
		}

		var result *frida.GenerateResult
		if dr.FridaScripts != nil {
			result = dr.FridaScripts
		} else {
			result = frida.Generate(frida.ScriptConfig{IncludeNetwork: true})
		}

		applyManualFlags(result, dr)
		scripts = result.Scripts
		packageName = result.PackageName

		// Write scripts to output dir if specified
		if output != "" {
			if err := writeScripts(result, output); err != nil {
				return err
			}
		}
	} else if packageName != "" {
		// Generate from flags
		config := buildManualConfig()
		result := frida.Generate(config)
		scripts = result.Scripts
	} else {
		return fmt.Errorf("provide an APK path, or --package with --script or hook flags")
	}

	if packageName == "" {
		return fmt.Errorf("package name required: use --package or provide an APK")
	}

	if len(scripts) == 0 {
		return fmt.Errorf("no scripts to run")
	}

	// Build runner
	var opts []frida.RunnerOption
	if fridaRunHost != "" {
		opts = append(opts, frida.WithHost(fridaRunHost))
	}
	if fridaRunDev != "" {
		opts = append(opts, frida.WithDevice(fridaRunDev))
	}
	if verbose {
		opts = append(opts, frida.WithVerbose(true))
	}
	opts = append(opts, frida.WithOutput(os.Stdout))

	runner := frida.NewRunner(packageName, opts...)

	// Set up context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Check device connectivity
	fmt.Println("Checking frida-server connectivity...")
	if err := runner.CheckDevice(ctx); err != nil {
		return fmt.Errorf("device check failed: %w", err)
	}
	fmt.Println("Connected.")

	// Run scripts
	fmt.Printf("Running %d script(s) against %s...\n", len(scripts), packageName)

	var session *frida.SessionResult
	if fridaRunSpawn && len(scripts) == 1 {
		result, err := runner.Spawn(ctx, scripts[0], fridaTimeout)
		if err != nil {
			return fmt.Errorf("spawn failed: %w", err)
		}

		session = &frida.SessionResult{
			PackageName: packageName,
			Device:      fridaRunHost,
			Scripts:     []frida.RunResult{*result},
			Duration:    result.Duration,
		}
	} else {
		var err error
		session, err = runner.RunAll(ctx, scripts, fridaTimeout)
		if err != nil {
			return fmt.Errorf("run failed: %w", err)
		}
	}

	// Output results
	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(session)
	}

	printSessionResult(session)
	return nil
}

func printSessionResult(s *frida.SessionResult) {
	fmt.Printf("\nSession Results (%s)\n", s.Duration)
	fmt.Printf("Package: %s\n", s.PackageName)
	fmt.Printf("Device:  %s\n", s.Device)
	fmt.Printf("Scripts: %d\n\n", len(s.Scripts))

	for _, r := range s.Scripts {
		fmt.Printf("--- %s (%s) ---\n", r.ScriptName, r.Duration)

		if len(r.Output) > 0 {
			for _, line := range r.Output {
				fmt.Printf("  %s\n", line)
			}
		}

		if len(r.Errors) > 0 {
			fmt.Println("  Errors:")
			for _, e := range r.Errors {
				fmt.Printf("    %s\n", e)
			}
		}

		fmt.Println()
	}
}

// isNativeFridaTarget reports whether a detected file type should use the
// native-export Frida generator instead of the JVM/Android path.
func isNativeFridaTarget(t detect.FileType) bool {
	switch t {
	case detect.TypePE, detect.TypeELF, detect.TypeMachO, detect.TypeMachOFat:
		return true
	}
	return false
}

// nativeTargetFor maps a detected file type to the corresponding frida.Target.
func nativeTargetFor(t detect.FileType) frida.Target {
	switch t {
	case detect.TypePE:
		return frida.TargetWindowsPE
	case detect.TypeMachO, detect.TypeMachOFat:
		return frida.TargetMachO
	case detect.TypeELF:
		return frida.TargetELF
	}
	return frida.TargetAndroid
}

func printScripts(result *frida.GenerateResult) error {
	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")

		return enc.Encode(result)
	}

	fmt.Printf("Package: %s\n", result.PackageName)
	fmt.Printf("Scripts: %d\n\n", len(result.Scripts))

	for _, s := range result.Scripts {
		fmt.Printf("=== %s (%s) ===\n", s.Name, s.Category)
		fmt.Printf("// %s\n", s.Description)
		fmt.Println(s.Content)
	}

	return nil
}
