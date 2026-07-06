/*
Copyright (c) 2026 Security Research

cmd/kb_build.go owns `unravel kb build <path>` — the headless, one-shot
"any artifact → KB" data-plane entry point. It orchestrates the existing,
proven capture helpers (stage → fingerprint → ingest → classify) plus a
static backfill pass, and leaves per-module summaries pending (summary IS
NULL) for the plugin's AI enrichment leg to fill. It adds NO AI path itself
(D-09 safe) and is what the PostToolUse(unravel_app_dissect) hook calls.

License: BSD-3-Clause.
*/
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/internal/elevate"
	"github.com/inovacc/unravel-oss/pkg/config"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"
)

type buildOpts struct {
	jsonOut      bool
	force        bool
	verbose      bool
	skipBackfill bool
}

var kbBuildFlags buildOpts

var kbBuildCmd = &cobra.Command{
	Use:   "build <path>",
	Short: "Headless: dissect ANY artifact and build/update its KB entry (capture + classify + static backfill)",
	Long: `Build a knowledge-base entry for any file, binary, app, bundle or directory
in one shot, without a Claude Code session. Runs the full data-plane chain:

  stage (in-process analyze) → fingerprint → ingest → classify → static backfill

Lone artifacts (a bare .dll/.jar/.wasm/.exe) are accepted: a minimal
fingerprint is synthesized from the file when no app manifest is present.
The AI enrichment leg is NOT run here — modules are left pending (summary IS
NULL); run '/unravel:kb' or 'unravel kb enrich' to fill summaries. Idempotent
and resumable: re-running re-ingests under the same (kb_id, binary_sha256) and
already-summarized modules are preserved.

Examples:
  unravel kb build ./app.dll
  unravel kb build /path/to/App.asar --json
  unravel kb build ./bundle --no-backfill`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := buildKB(cmd.Context(), args[0], kbBuildFlags)
		if err != nil {
			return err
		}
		return printSummary(cmd.OutOrStdout(), res, kbBuildFlags.jsonOut)
	},
}

func init() {
	kbBuildCmd.Flags().BoolVar(&kbBuildFlags.jsonOut, "json", false, "emit ingest.Result as JSON")
	kbBuildCmd.Flags().BoolVar(&kbBuildFlags.force, "force", false, "re-ingest even if (kb_id, binary_sha256) already exists; creates new epoch")
	kbBuildCmd.Flags().BoolVar(&kbBuildFlags.verbose, "verbose", false, "forward verbose flag to the analyzer")
	kbBuildCmd.Flags().BoolVar(&kbBuildFlags.skipBackfill, "no-backfill", false, "skip the pure-Go static backfill pass")
	kbCmd.AddCommand(kbBuildCmd) // top-level `unravel kb build`
}

// buildKB runs the headless capture+classify+backfill chain. It mirrors
// runKbCapture's proven sequence (cmd/kb_capture.go:116) and adds a static
// backfill pass. Exported-to-package so the kb-capture hook (cmd/hook.go) can
// reuse it. Callers own summary rendering.
func buildKB(ctx context.Context, appPath string, opts buildOpts) (*ingest.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if os.Getenv("UNRAVEL_NO_ELEVATE") != "1" {
		if err := elevate.EnsureReadable(appPath, "kb build: target requires Administrator", false); err != nil {
			return nil, fmt.Errorf("elevate: %w", err)
		}
	}

	// 1. In-process analyze into staging.
	stagingDir, clrModules, err := stageKbAnalysis(ctx, appPath)
	if err != nil {
		return nil, fmt.Errorf("stage analysis: %w", err)
	}
	// 2. Fingerprint (lone-artifact synth via srcPath=appPath).
	fpIn, err := loadFingerprintInputs(stagingDir, appPath)
	if err != nil {
		return nil, fmt.Errorf("load fingerprint inputs: %w", err)
	}
	kbID, ksID, err := identity.Fingerprint(fpIn)
	if err != nil {
		return nil, fmt.Errorf("fingerprint staging: %w", err)
	}
	// 3. Promote staging → kb-store layout.
	ksDir, err := promoteKbStaging(stagingDir, kbID, ksID)
	if err != nil {
		return nil, fmt.Errorf("promote staging: %w", err)
	}
	// 4. Open DB (config.yaml only, DPAPI-decrypted) + ingest.
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config (run `unravel db setup` first): %w", err)
	}
	dsn, err := cfg.DSN(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve dsn from config: %w", err)
	}
	sqlDB, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	storeRoot, err := fsutil.KBStoreRoot()
	if err != nil {
		return nil, fmt.Errorf("resolve kb-store root: %w", err)
	}
	var binarySHA string
	if fi, statErr := os.Stat(appPath); statErr == nil && fi.Mode().IsRegular() {
		if binarySHA, err = sha256OfCapturePath(appPath); err != nil {
			return nil, fmt.Errorf("hash input file: %w", err)
		}
	}

	res, err := ingest.Run(ctx, sqlDB, kbID, ksID, ksDir, ingest.Options{
		Force:         opts.force,
		ResolveAlias:  true,
		AllowedRoots:  []string{storeRoot},
		PackageID:     fpIn.PackageID,
		Platform:      fpIn.Platform,
		DisplayName:   fpIn.DisplayName,
		CanonicalName: identity.CanonicalName(fpIn.DisplayName),
		BinarySHA256:  binarySHA,
		CLRModules:    clrModules,
	})
	if err != nil {
		return nil, fmt.Errorf("ingest run: %w", err)
	}

	// 5. Best-effort classify (like capture; failure must not fail build).
	if rep, cerr := classify.Run(ctx, sqlDB, res.KBID, res.Epoch); cerr != nil {
		slog.Warn("classifier failed; module_components skipped", "kb_id", res.KBID, "err", cerr)
	} else if rep != nil {
		slog.Info("post-ingest classify", "kb_id", rep.KBID, "classified", rep.ModulesClassified)
	}

	// 6. Static backfill (pure-Go, idempotent, resumable). Reuses the existing
	// worker command scoped to this app via its flag var. Best-effort.
	//
	// Scope by res.App (the app key ingest.Run actually resolved and wrote to
	// modules.app), NOT a locally re-derived identity.CanonicalName(fpIn.DisplayName)
	// — ingest.Run's precedence is opts.App -> knowledge.json["app"] ->
	// opts.CanonicalName -> slug(opts.DisplayName) -> kbID, which can disagree
	// with a bare DisplayName-slug re-derivation and silently backfill zero
	// rows (or, if empty, the whole table).
	//
	// NOTE (single-shot-per-process only): mutating the backfillStaticApps
	// package global here is safe ONLY because buildKB runs single-shot per
	// process (CLI RunE / hook process) — never call buildKB concurrently
	// in-process, or this save/restore (and the worker/dry-run globals it
	// steers) will race. A future in-process/goroutine caller must pass scope
	// as an explicit argument instead (tracked in docs/BACKLOG.md).
	if !opts.skipBackfill {
		if res.App == "" {
			slog.Warn("kb build: skipping static backfill — no resolved app key", "kb_id", res.KBID)
		} else {
			prevApps := backfillStaticApps
			backfillStaticApps = res.App
			if berr := runKBBackfillStatic(nil, nil); berr != nil {
				slog.Warn("static backfill failed (non-fatal)", "err", berr)
			}
			backfillStaticApps = prevApps
		}
	}

	return res, nil
}
