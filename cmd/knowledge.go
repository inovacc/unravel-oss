/*
Copyright (c) 2026 Security Research
*/
// Package cmd / knowledge.go hosts the former `unravel knowledge` flows,
// now folded into the `kb` command tree (command-taxonomy redesign PR1).
// The top-level `knowledge` command has been removed; every subcommand is
// re-parented under the appropriate `kb` sub-noun group (see cmd/kb.go).
//
// Flows still owned by this file:
//
//	kb enrich generate <path>   runKnowledge (former bare `knowledge <path>`)
//	kb transfer diff-dirs       runKnowledgeDiff (former `knowledge diff`)
//	kb transfer migrate         runKnowledgeMigrate (cobra var in knowledge_kb_migrate.go)
//
// Cross-file resolution is plain `package cmd` shared scope: cobra vars
// and helpers (kbOpenDB, etc.) reference each other by name without any
// import-graph changes. D-09 invariant preserved across all sibling files
// (no anthropic-sdk-go imports).
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
	livecapture "github.com/inovacc/unravel-oss/pkg/knowledge/capture"
	"github.com/inovacc/unravel-oss/pkg/knowledge/migrate"
	"github.com/inovacc/unravel-oss/pkg/knowledge/overlay"
	"github.com/inovacc/unravel-oss/pkg/knowledge/regressions"
	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"
	"github.com/inovacc/unravel-oss/pkg/npm"

	// Wire per-ecosystem cve.LatestProber implementations (CVE-POL-01).
	_ "github.com/inovacc/unravel-oss/pkg/cve/registry"

	"github.com/spf13/cobra"
)

// ─────────────────────────────────────────────────────────────────────
// flag-backing variables
// ─────────────────────────────────────────────────────────────────────

var (
	// catalog: extract / index / search / dump / pending / summarize / stats
	kbExtractSrc, kbExtractDst                       string
	kbIndexApp, kbIndexSrc, kbIndexDB                string
	kbIndexExcerpt, kbIndexMinBytes, kbIndexMaxBytes int
	kbIndexBatch                                     int
	kbIndexReuseEpoch                                int // when >0, reuse this epoch instead of allocating
	kbIndexLastEpoch                                 int // set by runKBIndex after Begin (read by sweep)
	kbDumpDB                                         string
	kbDumpID                                         int
	kbPendingDB, kbPendingApp                        string
	kbPendingLimit                                   int
	kbSumDB, kbSumSummary, kbSumTags                 string
	kbSumID                                          int
	kbStatsDB                                        string
	kbStatsJSON                                      bool
	kbQuerySQL                                       string

	// knowledge diff (07-03)
	kbDiffRubric string
	kbDiffOutput string
	kbDiffAI     bool

	// knowledge --with-ai flag (07-04, D-14)
	knowledgeWithAI bool

	// Phase 23: live-overlay flags (KB-CAP-01..03)
	knowledgeLive        bool
	knowledgeLiveTimeout time.Duration

	// knowledge --enrich / --enrich-include-private (Phase 14, D-07/D-08)
	knowledgeEnrich               bool
	knowledgeEnrichIncludePrivate bool

	// P59-04a: scorecard / iterative-deepening flags. Defaults preserve
	// pre-P59 behavior — single-shot Score wrapped into a 1-entry log,
	// SCORECARD.md emitted next to knowledge.json.
	knowledgeIterate         bool
	knowledgeCDPPort         int
	knowledgeMaxIter         int
	knowledgeThreshold       int
	knowledgeScorecardMD     bool
	knowledgeStrictCitations bool

	// knowledge migrate (07-04)
	kbMigrateTo string

	// sweep
	sweepRoot  string
	sweepDB    string
	sweepApps  string
	sweepBatch int

	// facts: dissect-app / gaps / facts
	dissectAppDB  string
	dissectAppApp string

	gapsDB, gapsApp, gapsCat string

	factsDB, factsApp, factsCat string

	// fill + ask var blocks removed 2026-05-23: kbFillCmd / kbAskCmd
	// were removed alongside the legacy 'knowledge enrich' CLI. The
	// sampling-only kbllm.Call returns ErrNoSamplingClient when invoked
	// from a naked CLI context, so neither command could function. If
	// the workflows are needed again, ship them as
	// unravel_kb_enrich_fill / unravel_kb_enrich_ask MCP tools.
)

// ─────────────────────────────────────────────────────────────────────
// command definitions
// ─────────────────────────────────────────────────────────────────────

// kbGenerateCmd is the former bare `knowledge <path>` command, now
// `kb enrich generate <path>`. It generates a structured knowledge source
// from an app path. Behavior (Args/flags/RunE) is preserved verbatim.
var kbGenerateCmd = &cobra.Command{
	Use:   "generate <path>",
	Short: "Generate structured knowledge source from an app",
	Long: `Generate a structured knowledge source describing an application's communication
patterns, authentication, IPC channels, stealth features, telemetry, and security
posture from any supported file type (APK, ASAR, PE, ELF, etc.).

Examples:
  unravel kb enrich generate ./app.apk
  unravel kb enrich generate ./app.asar --json
  unravel kb enrich generate ./binary.exe -o ./report -v`,
	Args: cobra.ExactArgs(1),
	RunE: runKnowledge,
}

// knowledgeDiffCmd is the former `knowledge diff`, now
// `kb transfer diff-dirs`. It compares two on-disk knowledge output
// directories (distinct from `kb transfer diff`, which compares DB epochs).
var knowledgeDiffCmd = &cobra.Command{
	Use:   "diff-dirs <old-dir> <new-dir>",
	Short: "Compare two knowledge output directories",
	Long: `Compare two knowledge output directories and show what changed between versions.
Compares all JSON files field-by-field and reports added, removed, and changed entries.

Examples:
  unravel kb transfer diff-dirs ./knowledge-v1 ./knowledge-v2
  unravel kb transfer diff-dirs ./knowledge-v1 ./knowledge-v2 --json`,
	Args: cobra.ExactArgs(2),
	RunE: runKnowledgeDiff,
}

// ─────────────────────────────────────────────────────────────────────
// init: flag wiring + registration under the kb command tree
//
// The former `knowledge` tree was folded into `kb` (command-taxonomy
// redesign PR1). Each subcommand is registered under the kb sub-noun
// group that matches docs/COMMAND-TAXONOMY.md §5. The group parents
// (kbCatalogCmd, kbEnrichCmd, kbFindingsCmd, kbTransferCmd, kbGapsCmd,
// kbOpsCmd) are declared in cmd/kb.go.
// ─────────────────────────────────────────────────────────────────────

func init() {
	// kb enrich generate (former bare `knowledge <path>`).
	kbEnrichCmd.AddCommand(kbGenerateCmd)
	kbGenerateCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON to stdout")
	kbGenerateCmd.Flags().BoolVar(&knowledgeWithAI, "with-ai", false,
		"Enable MCP-backed beautification across Java/JS/Bundle/C# tracks. Token cost applies.")
	kbGenerateCmd.Flags().BoolVar(&knowledgeEnrich, "enrich", false,
		"enrich dependency list with CVE/CWE/version-freshness data (sends dep names to OSV/NVD/GHSA — opt-in per D-08)")
	kbGenerateCmd.Flags().BoolVar(&knowledgeEnrichIncludePrivate, "enrich-include-private", false,
		"do NOT skip scoped/private packages during enrichment (overrides D-08 default)")
	// Phase 23: live-overlay capture (KB-CAP-01..03). Static-only output is
	// byte-equivalent to v2.3 when --live is absent (D-10).
	// P59-04a flags. --scorecard-md defaults to true so every run emits
	// SCORECARD.md next to knowledge.json (D-10 byte shape unchanged).
	kbGenerateCmd.Flags().BoolVar(&knowledgeIterate, "iterate", false, "Run iterative-deepening rubric loop (P57)")
	kbGenerateCmd.Flags().IntVar(&knowledgeCDPPort, "cdp-port", 0, "CDP port for runtime probe (0 = no probe)")
	kbGenerateCmd.Flags().IntVar(&knowledgeMaxIter, "max-iter", 5, "Maximum iterations for --iterate")
	kbGenerateCmd.Flags().IntVar(&knowledgeThreshold, "threshold", 80, "Score threshold (percent) for convergence")
	kbGenerateCmd.Flags().BoolVar(&knowledgeScorecardMD, "scorecard-md", true, "Emit SCORECARD.md next to knowledge.json")
	kbGenerateCmd.Flags().BoolVar(&knowledgeStrictCitations, "strict-citations", true, "Require every spec line to cite evidence (P58)")
	kbGenerateCmd.Flags().BoolVar(&knowledgeLive, "live", false,
		"Enable optional live-overlay capture pass (CDP). Adds provenance metadata; static output unchanged when absent.")
	kbGenerateCmd.Flags().DurationVar(&knowledgeLiveTimeout, "live-timeout", 30*time.Second,
		"Maximum live-pass duration. Default 30s.")

	// kb transfer diff-dirs (former `knowledge diff`) + kb transfer migrate.
	kbTransferCmd.AddCommand(knowledgeDiffCmd)
	kbTransferCmd.AddCommand(kbMigrateCmd)
	kbMigrateCmd.Flags().StringVar(&kbMigrateTo, "to", "",
		"Target framework: react|vue|angular|svelte|wpf|winui3|flutter|react-native")
	_ = kbMigrateCmd.MarkFlagRequired("to")
	knowledgeDiffCmd.Flags().BoolVar(&jsonFormat, "json", false, "Output as JSON to stdout")
	knowledgeDiffCmd.Flags().StringVar(&kbDiffRubric, "rubric", "", "Path to kb-regressions.yaml (overrides embedded defaults)")
	knowledgeDiffCmd.Flags().BoolVar(&kbDiffAI, "ai", false, "Run AI second-opinion via MCP (opt-in)")
	knowledgeDiffCmd.Flags().StringVarP(&kbDiffOutput, "output", "o", "", "Output dir for diff.json + DIFF.md (also written when set)")

	// catalog flags
	kbExtractCmd.Flags().StringVar(&kbExtractSrc, "src", "", "Chromium Cache_Data dir")
	kbExtractCmd.Flags().StringVar(&kbExtractDst, "dst", "", "output dir for .js bundles")
	_ = kbExtractCmd.MarkFlagRequired("src")
	_ = kbExtractCmd.MarkFlagRequired("dst")

	kbIndexCmd.Flags().StringVar(&kbIndexApp, "app", "", "logical app name (whatsapp, teams, ...)")
	kbIndexCmd.Flags().StringVar(&kbIndexSrc, "src", "", "directory of extracted .js bundles")
	kbIndexCmd.Flags().StringVar(&kbIndexDB, "database", "", "DSN override (defaults to config.yaml)")
	kbIndexCmd.Flags().IntVar(&kbIndexExcerpt, "excerpt", 32768, "bytes of body to keep per module (raised from 4 KB so realistic Send/Receive bodies survive uncut)")
	kbIndexCmd.Flags().IntVar(&kbIndexMinBytes, "min-bytes", 200, "skip modules whose body is smaller than this — feature flags + 1-line constants pollute search results")
	kbIndexCmd.Flags().IntVar(&kbIndexMaxBytes, "max-bytes", 0, "skip modules whose body is larger than this (0 = no limit)")
	kbIndexCmd.Flags().IntVar(&kbIndexBatch, "batch", 1000, "commit every N modules so a mid-run timeout/crash leaves partial progress on disk (env UNRAVEL_KB_BATCH overrides; 0 = single transaction, legacy behaviour)")
	kbIndexCmd.Flags().IntVar(&kbIndexReuseEpoch, "reuse-epoch", 0, "reuse this existing epoch instead of allocating a new one (keeps multi-dir builds in one epoch; 0 = allocate fresh)")
	_ = kbIndexCmd.MarkFlagRequired("app")
	_ = kbIndexCmd.MarkFlagRequired("src")

	kbDumpCmd.Flags().StringVar(&kbDumpDB, "database", "", "DSN override (defaults to config.yaml)")
	kbDumpCmd.Flags().IntVar(&kbDumpID, "id", 0, "module id")
	_ = kbDumpCmd.MarkFlagRequired("id")

	kbPendingCmd.Flags().StringVar(&kbPendingDB, "database", "", "DSN override (defaults to config.yaml)")
	kbPendingCmd.Flags().StringVar(&kbPendingApp, "app", "", "filter by app")
	kbPendingCmd.Flags().IntVar(&kbPendingLimit, "limit", 50, "max rows")

	kbSummarizeCmd.Flags().StringVar(&kbSumDB, "database", "", "DSN override (defaults to config.yaml)")
	kbSummarizeCmd.Flags().IntVar(&kbSumID, "id", 0, "module id")
	kbSummarizeCmd.Flags().StringVar(&kbSumSummary, "summary", "", "natural-language summary")
	kbSummarizeCmd.Flags().StringVar(&kbSumTags, "tags", "", "comma-separated tags")
	_ = kbSummarizeCmd.MarkFlagRequired("id")
	_ = kbSummarizeCmd.MarkFlagRequired("summary")

	kbStatsCmd.Flags().BoolVar(&kbStatsJSON, "json", false, "Output as JSON")

	kbQueryCmd.Flags().StringVar(&kbQuerySQL, "sql", "", "SQL query to execute")
	_ = kbQueryCmd.MarkFlagRequired("sql")

	// kb catalog: read/browse verbs (extract/index/dump/stats/query).
	kbCatalogCmd.AddCommand(kbExtractCmd, kbIndexCmd, kbDumpCmd, kbStatsCmd, kbQueryCmd)
	// kb catalog sweep-targets: dump the static built-in sweep app registry.
	kbCatalogCmd.AddCommand(kbSweepTargetsCmd)
	// kb enrich: population verbs (pending/summarize).
	kbEnrichCmd.AddCommand(kbPendingCmd, kbSummarizeCmd)

	kbSynthNamesCmd.Flags().StringVar(&synthDB, "database", "", "DSN override (default: configured Postgres)")
	kbSynthNamesCmd.Flags().StringVar(&synthApp, "app", "teams", "app filter (default teams)")
	kbSynthNamesCmd.Flags().IntVar(&synthLimit, "limit", 200, "max modules to process (cost/scope bound)")
	kbSynthNamesCmd.Flags().BoolVar(&synthForce, "force", false, "recompute even if synthetic_name set")
	kbSynthNamesCmd.Flags().BoolVar(&synthDryRun, "dry-run", false, "print derived names, write nothing")
	kbSynthNamesCmd.Flags().BoolVar(&synthVerify, "verify", false, "read-only: placeholder vs synthetic_named counts; non-zero exit on a true gap")
	kbSynthNamesCmd.SilenceUsage = true
	kbEnrichCmd.AddCommand(kbSynthNamesCmd)

	kbTopicsCmd.Flags().StringVar(&topicsDB, "database", "", "DSN override (default: configured Postgres)")
	kbTopicsCmd.Flags().StringVar(&topicsApp, "app", "whatsapp", "app filter (default whatsapp)")
	kbTopicsCmd.Flags().IntVar(&topicsLimit, "limit", 200, "max modules to process (cost/scope bound)")
	kbTopicsCmd.Flags().BoolVar(&topicsForce, "force", false, "recompute even if topic set")
	kbTopicsCmd.Flags().BoolVar(&topicsDryRun, "dry-run", false, "print derived topics, write nothing")
	kbTopicsCmd.Flags().BoolVar(&topicsVerify, "verify", false, "read-only: enriched vs topiced counts; non-zero exit on a true gap")
	kbTopicsCmd.SilenceUsage = true
	kbCatalogCmd.AddCommand(kbTopicsCmd)

	// sweep flags
	kbSweepCmd.Flags().StringVar(&sweepRoot, "root", "", "knowledge-base root dir (one subdir per app)")
	kbSweepCmd.Flags().StringVar(&sweepDB, "database", "", "DSN override (defaults to config.yaml)")
	kbSweepCmd.Flags().StringVar(&sweepApps, "apps", "", "comma-separated subset of apps to run (default: all known)")
	kbSweepCmd.Flags().IntVar(&sweepBatch, "batch", 1000, "per-app index batch size — commit every N modules so a mid-sweep timeout/crash leaves partial progress on disk (env UNRAVEL_KB_BATCH overrides; 0 = single transaction)")
	_ = kbSweepCmd.MarkFlagRequired("root")
	kbEnrichCmd.AddCommand(kbSweepCmd)

	// facts flags
	kbDissectAppCmd.Flags().StringVar(&dissectAppDB, "database", "", "DSN override (defaults to config.yaml)")
	kbDissectAppCmd.Flags().StringVar(&dissectAppApp, "app", "", "app to provision (whatsapp, teams, ...). empty = all known.")

	kbGapsListCmd.Flags().StringVar(&gapsDB, "database", "", "DSN override (defaults to config.yaml)")
	kbGapsListCmd.Flags().StringVar(&gapsApp, "app", "", "filter by app")
	kbGapsListCmd.Flags().StringVar(&gapsCat, "category", "", "filter by category")

	// kbFillCmd flag wiring removed alongside the command — see var block comment.

	kbFactsCmd.Flags().StringVar(&factsDB, "database", "", "DSN override (defaults to config.yaml)")
	kbFactsCmd.Flags().StringVar(&factsApp, "app", "", "filter by app")
	kbFactsCmd.Flags().StringVar(&factsCat, "category", "", "filter by category")

	// kbDissectAppCmd is intentionally left unregistered (MCP-only; its
	// flags are bound above to preserve prior behavior). kb catalog gets
	// facts; kb gaps gets the open-gap list.
	kbCatalogCmd.AddCommand(kbFactsCmd)
	kbGapsCmd.AddCommand(kbGapsListCmd)

	kbBackfillDedupCmd.Flags().StringVar(&backfillDedupDB, "database", "", "DSN override (defaults to config.yaml)")
	kbBackfillDedupCmd.Flags().StringVar(&backfillDedupApp, "app", "", "limit backfill to one app's pending rows (representative sibling may be any app)")
	kbBackfillDedupCmd.Flags().BoolVar(&backfillDedupDryRun, "dry-run", false, "report how many rows would be backfilled without writing")
	kbEnrichCmd.AddCommand(kbBackfillDedupCmd)
}

// ─────────────────────────────────────────────────────────────────────
// runKnowledge / runKnowledgeDiff (parent + diff)
// ─────────────────────────────────────────────────────────────────────

func runKnowledge(cmd *cobra.Command, args []string) error {
	path := args[0]

	resolved, cleanup, err := resolveKnowledgeInput(path)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}
	path = resolved.Path

	outDir := output
	if outDir == "" && !jsonFormat {
		base := strings.TrimSuffix(filepath.Base(resolved.DisplayName), filepath.Ext(resolved.DisplayName))
		outDir = fmt.Sprintf("./knowledge-%s", base)
	}

	result, err := knowledge.Run(path, knowledge.Options{
		OutputDir:            outDir,
		Verbose:              verbose,
		WithAI:               knowledgeWithAI,
		Enrich:               knowledgeEnrich,
		EnrichIncludePrivate: knowledgeEnrichIncludePrivate,
	})
	if err != nil {
		return err
	}

	// Phase 23: optional live-overlay pass (KB-CAP-01..03). Failure here
	// MUST NOT prevent static-only output (D-14). Static bundle is never
	// mutated; the overlay is written to a separate knowledge.live.json
	// (D-12). Absent --live, this entire branch is skipped, preserving
	// byte-equivalence with v2.3 (D-10).
	if knowledgeLive && outDir != "" {
		if err := runLiveOverlay(cmd.Context(), path, outDir, result, knowledgeLiveTimeout); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] live pass failed: %v; static-only KB written to %s\n", err, outDir)
		}
	}

	// P59-04a: emit SCORECARD.md alongside knowledge.json. D-10 unchanged
	// — emitter writes a sidecar file, never mutates knowledge.json. The
	// rubric is run with a re-dissect (cache-hit fast) so we have proper
	// inputs; failures degrade to a placeholder report so static output
	// is never blocked by scorer panics.
	if knowledgeScorecardMD && outDir != "" {
		if knowledgeIterate {
			// P61 CLSR-01: --iterate dispatches to Rubric.Iterate, persists
			// iterations.jsonl, and refreshes SCORECARD.md with the
			// IterationLog. Failure here MUST NOT block knowledge.json
			// (D-10) — log and continue.
			opts := scorecard.IterateOptions{
				MaxIter:        knowledgeMaxIter,
				Threshold:      knowledgeThreshold,
				RequireAll12:   knowledgeStrictCitations,
				PerIterTimeout: 4 * time.Minute,
			}
			if ierr := emitScorecardSidecarIterate(cmd.Context(), path, outDir, result, opts, knowledgeCDPPort); ierr != nil {
				fmt.Fprintf(os.Stderr, "[WARN] scorecard iterate emission failed: %v\n", ierr)
			}
		} else {
			emitScorecardSidecar(path, outDir, result)
		}
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Print summary
	fmt.Printf("Knowledge Source: %s\n", result.AppName)
	fmt.Printf("  Framework:    %s\n", result.Framework)

	endpointCount := 0
	if result.Communication != nil {
		endpointCount = len(result.Communication.Endpoints)
	}
	fmt.Printf("  Endpoints:    %d\n", endpointCount)

	ipcCount := 0
	if result.IPC != nil {
		ipcCount = len(result.IPC.Channels)
	}
	fmt.Printf("  IPC Channels: %d\n", ipcCount)

	riskScore := 0
	if result.Security != nil {
		riskScore = result.Security.RiskScore
	}
	fmt.Printf("  Risk Score:   %d/100\n", riskScore)
	fmt.Printf("  Source Files: %d\n", len(result.SourceFiles))

	if a := result.Android; a != nil {
		fmt.Printf("  Package:      %s\n", a.Package)
		fmt.Printf("  SDK:          min=%s target=%s\n", a.MinSDK, a.TargetSDK)
		fmt.Printf("  Permissions:  %d\n", len(a.Permissions))
		fmt.Printf("  Components:   %d\n", len(a.Components))
		if a.DEXStats != nil {
			fmt.Printf("  DEX:          %d classes, %d methods\n", a.DEXStats.TotalClasses, a.DEXStats.TotalMethods)
		}
		if len(a.Secrets) > 0 {
			fmt.Printf("  Secrets:      %d findings\n", len(a.Secrets))
		}
		if len(a.NativeLibs) > 0 {
			fmt.Printf("  Native Libs:  %d\n", len(a.NativeLibs))
		}
		if a.Obfuscation != nil {
			fmt.Printf("  Obfuscation:  %s (%d%%)\n", a.Obfuscation.Type, a.Obfuscation.Confidence)
		}
	}

	if g := result.GoBinary; g != nil {
		fmt.Printf("  Go Version:   %s\n", g.GoVersion)
		fmt.Printf("  Module:       %s\n", g.ModulePath)
		fmt.Printf("  OS/Arch:      %s/%s\n", g.OS, g.Arch)
		if g.IsGarbled {
			fmt.Printf("  Garbled:      yes (%.0f%% confidence)\n", g.GarbleConfidence*100)
		}
	}

	if p := result.Packaging; p != nil {
		fmt.Printf("  Pkg Format:   %s\n", p.Format)
		fmt.Printf("  Pkg Name:     %s\n", p.Name)
		if p.Version != "" {
			fmt.Printf("  Pkg Version:  %s\n", p.Version)
		}
		fmt.Printf("  Pkg Files:    %d\n", p.FileCount)
		fmt.Printf("  Pkg Signed:   %v\n", p.HasSignature)
	}

	if d := result.DataDir; d != nil {
		fmt.Printf("  Data Dir:     %s\n", d.Path)
		if d.LocalStorage != nil {
			fmt.Printf("  LocalStorage: %d entries across %d origins\n",
				d.LocalStorage.Stats.TotalEntries, d.LocalStorage.Stats.OriginCount)
		}
		if d.Cache != nil {
			fmt.Printf("  HTTP Cache:   %d entries, %d domains\n",
				d.Cache.EntryCount, len(d.Cache.Domains))
		}
		if d.AppState != nil {
			fmt.Printf("  App State:    %d files\n", len(d.AppState))
		}
		if d.Cookies != nil {
			fmt.Printf("  Cookies:      %d across %d domains\n",
				d.Cookies.Stats.Total, d.Cookies.Stats.DomainCount)
		}
		if d.IndexedDB != nil {
			fmt.Printf("  IndexedDB:    %d entries in %d databases\n",
				d.IndexedDB.Stats.TotalEntries, d.IndexedDB.Stats.DatabaseCount)
		}
		if d.DIPS != nil {
			fmt.Printf("  DIPS:         %d sites\n", d.DIPS.Total)
		}
	}

	if outDir != "" {
		fmt.Printf("\nKnowledge written to: %s\n", outDir)
	}

	return nil
}

type knowledgeInput struct {
	Path        string
	DisplayName string
}

func resolveKnowledgeInput(input string) (knowledgeInput, func(), error) {
	if _, err := os.Stat(input); err == nil {
		return knowledgeInput{Path: input, DisplayName: input}, nil, nil
	}

	if spec, ok := parseNPMInstallInput(input); ok {
		name, version := parsePackageSpec(spec)
		tmp, err := os.MkdirTemp("", "unravel-knowledge-npm-*")
		if err != nil {
			return knowledgeInput{}, nil, fmt.Errorf("create npm knowledge temp dir: %w", err)
		}
		cleanup := func() { _ = os.RemoveAll(tmp) }
		dl, err := npm.Download(name, version, tmp)
		if err != nil {
			cleanup()
			return knowledgeInput{}, nil, fmt.Errorf("download npm package %q: %w", spec, err)
		}
		return knowledgeInput{
			Path:        dl.OutputDir,
			DisplayName: fmt.Sprintf("%s@%s", dl.Package, dl.Version),
		}, cleanup, nil
	}

	return knowledgeInput{Path: input, DisplayName: input}, nil, nil
}

func parseNPMInstallInput(input string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(input))
	if len(fields) == 0 {
		return "", false
	}
	if fields[0] != "npm" {
		return "", false
	}

	seenInstall := false
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if f == "install" || f == "i" || f == "add" {
			seenInstall = true
			continue
		}
		if !seenInstall {
			continue
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		if strings.Contains(f, "=") {
			continue
		}
		return strings.Trim(f, `"'`), true
	}
	return "", false
}

func runKnowledgeDiff(_ *cobra.Command, args []string) error {
	oldDir := args[0]
	newDir := args[1]

	rules, err := regressions.LoadRubric(kbDiffRubric)
	if err != nil {
		return fmt.Errorf("load rubric: %w", err)
	}

	result, err := knowledge.DiffWith(oldDir, newDir, rules)
	if err != nil {
		return err
	}

	if kbDiffAI {
		// 07-04 plumbs the real MCP client; for now this is a no-op
		// (regressions.AISecondOpinion returns nil on a nil client).
		_ = regressions.AISecondOpinion(context.Background(), result.Snapshot(), result.Regressions, nil)
	}

	if kbDiffOutput != "" {
		if err := knowledge.WriteDiff(result, kbDiffOutput); err != nil {
			return fmt.Errorf("write diff outputs: %w", err)
		}
	}

	if jsonFormat {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Knowledge Diff: %s vs %s\n", oldDir, newDir)
	fmt.Printf("Summary: %s\n\n", result.Summary)

	if len(result.Added) > 0 {
		fmt.Printf("Added (%d):\n", len(result.Added))
		for _, e := range result.Added {
			fmt.Printf("  + [%s] %s", e.Section, e.Key)
			if e.Value != "" {
				fmt.Printf(": %s", e.Value)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(result.Removed) > 0 {
		fmt.Printf("Removed (%d):\n", len(result.Removed))
		for _, e := range result.Removed {
			fmt.Printf("  - [%s] %s", e.Section, e.Key)
			if e.Value != "" {
				fmt.Printf(": %s", e.Value)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(result.Changed) > 0 {
		fmt.Printf("Changed (%d):\n", len(result.Changed))
		for _, c := range result.Changed {
			fmt.Printf("  ~ [%s] %s\n", c.Section, c.Key)
			fmt.Printf("    old: %s\n", c.OldValue)
			fmt.Printf("    new: %s\n", c.NewValue)
		}
	}

	return nil
}

// ─────────────────────────────────────────────────────────────────────
// runKnowledgeMigrate (07-04, D-05..D-08)
// ─────────────────────────────────────────────────────────────────────

// migrateClientFn is the seam tests use to inject a stub MCP client without
// booting the real ai.Client. Production wiring sets it to nilMCPClient
// (no-op) — Plan 07-05 will swap this for a real MCP-host adapter.
var migrateClientFn = func() migrate.MCPClient { return nil }

// runKnowledgeMigrate is the migrate subcommand entry point. It validates
// the target framework, resolves kb-dir, and delegates to
// migrate.GenerateForFramework.
func runKnowledgeMigrate(cmd *cobra.Command, args []string) error {
	kbDir := args[0]
	fw := strings.ToLower(strings.TrimSpace(kbMigrateTo))
	if !migrate.IsValid(fw) {
		return fmt.Errorf("unknown target framework %q (valid: %s)",
			fw, strings.Join(migrate.ValidFrameworks(), ", "))
	}
	client := migrateClientFn()
	if err := migrate.GenerateForFramework(cmd.Context(), kbDir, fw, client); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	fmt.Printf("Migration hints for %s written under %s/migrations/%s/\n",
		fw, kbDir, fw)
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Phase 23: live-overlay pass (KB-CAP-01..03)
// ─────────────────────────────────────────────────────────────────────

// runLiveOverlay performs the optional live-capture pass and writes a
// knowledge.live.json overlay file alongside the static knowledge.json.
// Per D-12, the static bundle is never mutated. Per D-14, failures are
// non-fatal — caller surfaces a WARN.
func runLiveOverlay(ctx context.Context, appPath, outputDir string, static *knowledge.KnowledgeResult, timeout time.Duration) error {
	fw := detectLiveFramework(static)
	liveResult, err := livecapture.RunLive(ctx, livecapture.Options{
		AppPath:   appPath,
		Framework: fw,
		Timeout:   timeout,
	})
	if err != nil {
		return fmt.Errorf("live capture: %w", err)
	}

	merged, err := overlay.MergeJSON(static, liveResult, overlay.Options{
		StaticTS: static.AnalyzedAt,
		LiveTS:   liveResult.CapturedAt,
	})
	if err != nil {
		return fmt.Errorf("overlay merge: %w", err)
	}

	livePath := filepath.Join(outputDir, "knowledge.live.json")
	if err := knowledge.WriteJSONAtomic(livePath, merged); err != nil {
		return fmt.Errorf("write live: %w", err)
	}
	return nil
}

// detectLiveFramework picks the live-capture launcher target based on
// the static analysis result.
func detectLiveFramework(r *knowledge.KnowledgeResult) livecapture.Framework {
	switch r.Framework {
	case "tauri":
		return livecapture.FrameworkTauri
	case "webview2":
		return livecapture.FrameworkWebView2
	default:
		return livecapture.FrameworkElectron
	}
}
