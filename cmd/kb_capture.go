/*
Copyright (c) 2026 Security Research

kb_capture.go — `unravel kb capture <app-path>` (Phase 30, Plan 30-04).

End-to-end capture pipeline:

  1. Analyze app via in-process knowledge.Run() into a staging directory
     under <kb-store>/staging/<rand>/. Synchronous; NO os/exec subprocess
     fallback (INGE-01 in-process requirement, T-30-04-07 mitigation).
  2. Derive (kb_id, ks_id) via identity.Fingerprint over knowledge.json
     fields (platform, package_id / display_name, app_version,
     captured_at).
  3. Atomically rename staging dir into the canonical layout
     <kb-store>/apps/<kb_id>/versions/<ks_id_fs>/ via os.Rename. Long-path
     wrapping applied on Windows via fsutil.WrapLongPath.
  4. Open *sql.DB and call ingest.Run — single-tx idempotent writer.
  5. Emit summary line (plain text default; --json emits ingest.Result).

Phase boundaries (deliberately deferred — referenced in --help):
  * `unravel kb ingest <dir>` (folder-only mode):  Phase 32.
  * `--force` re-ingest:                            Phase 32.
  * Orphan kb-store/ folder gc on tx rollback:     Phase 34
    (`unravel kb gc --orphan-folders`). Until then a stderr warning is
    emitted on rollback per D-30-PARTIAL-FAILURE.

License: BSD-3-Clause.
*/

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"log/slog"

	"github.com/inovacc/unravel-oss/internal/elevate"
	"github.com/inovacc/unravel-oss/pkg/config"
	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate rule registry
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"
)

// kbCaptureFlags holds the parsed flag values for `unravel kb capture`.
// (Named distinctly from the unrelated top-level `unravel capture` command
// in cmd/capture.go.)
// kbCaptureInput mirrors the CLI flag set 1:1 (D-33-INPUT-MATCH-CLI) and
// carries jsonschema descriptions for MCP tool input schema derivation.
// Field semantics match `unravel kb capture --help` text verbatim.
type kbCaptureInput struct {
	Path           string   `json:"path" jsonschema:"absolute filesystem path to the application binary or directory to capture"`
	Tag            []string `json:"tag,omitempty" jsonschema:"capture tags (free-form labels attached to this capture; repeatable)"`
	Reason         string   `json:"reason,omitempty" jsonschema:"human-readable reason for the capture (audit trail)"`
	By             string   `json:"by,omitempty" jsonschema:"actor identifier (user, ci-job, agent-name) attributed to this capture"`
	Force          bool     `json:"force,omitempty" jsonschema:"bypass idempotency check; create new epoch even if binary_sha256 matches latest"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"override default 600s capture timeout (range 60-1800)"`
}

var kbCaptureFlags struct {
	tags    []string
	reason  string
	by      string
	jsonOut bool
	verbose bool
	force   bool
}

var kbCaptureCmd = &cobra.Command{
	Use:   "capture <app-path>",
	Short: "Capture an app into the KB versioned-store (Phase 30/32)",
	Long: `Run the full capture pipeline:
  1. Analyze app via in-process knowledge.Run() into a staging directory
  2. Fingerprint to derive kb_id + ks_id
  3. Atomically rename staging -> <kb-store>/apps/<kb_id>/versions/<ks_id_fs>/
  4. Single-transaction DB ingest (idempotency, advisory lock, knowledge_sources row,
     module_bodies/modules/files, app_facts, consecutive-epoch kb_diffs)
  5. Print summary line (or JSON via --json)

Phase boundaries:
  - 'unravel kb ingest <dir>' folder-only mode: implemented in Phase 32
  - --force re-ingest: implemented in Phase 32
  - Orphan kb-store/ folder cleanup on tx rollback: deferred to Phase 34
    ('kb gc --orphan-folders'). On rollback you'll see a warning hinting at it.`,
	Args: cobra.ExactArgs(1),
	RunE: runKbCapture,
}

func init() {
	kbCaptureCmd.Flags().StringSliceVar(&kbCaptureFlags.tags, "tag", nil, "capture tags (comma-separated or repeated)")
	kbCaptureCmd.Flags().StringVar(&kbCaptureFlags.reason, "reason", "", "capture reason text")
	kbCaptureCmd.Flags().StringVar(&kbCaptureFlags.by, "by", "", "analyst identifier")
	kbCaptureCmd.Flags().BoolVar(&kbCaptureFlags.jsonOut, "json", false, "emit ingest.Result as JSON")
	kbCaptureCmd.Flags().BoolVar(&kbCaptureFlags.verbose, "verbose", false, "forward verbose flag to knowledge analyzer")
	kbCaptureCmd.Flags().BoolVar(&kbCaptureFlags.force, "force", false, "re-ingest even if (kb_id, binary_sha256) already exists; creates new epoch")
	// Intentionally not registered on the CLI: exposed MCP-only via unravel_kb_capture.
}

func runKbCapture(cmd *cobra.Command, args []string) error {
	appPath := args[0]
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	// Auto-elevate on Windows when target lives under a known
	// Administrator-only directory (e.g. C:\Program Files\WindowsApps).
	// On non-Windows this is a no-op. Skipped via UNRAVEL_NO_ELEVATE=1
	// for headless / CI runs that can't accept UAC prompts.
	if os.Getenv("UNRAVEL_NO_ELEVATE") != "1" {
		if err := elevate.EnsureReadable(appPath, "kb capture: target requires Administrator", false); err != nil {
			return fmt.Errorf("elevate: %w", err)
		}
	}

	// Step 1: in-process analyze into staging dir.
	stagingDir, clrModules, err := stageKbAnalysis(ctx, appPath)
	if err != nil {
		return fmt.Errorf("stage analysis: %w", err)
	}
	// Per D-30-CAPTURE-PIPELINE: staging is kept on failure for analyst retry.

	// Step 2: derive Fingerprint inputs from staging (knowledge.json).
	fpIn, err := loadFingerprintInputs(stagingDir, appPath)
	if err != nil {
		return fmt.Errorf("load fingerprint inputs: %w", err)
	}
	kbID, ksID, err := identity.Fingerprint(fpIn)
	if err != nil {
		return fmt.Errorf("fingerprint staging: %w", err)
	}

	// Step 3: atomic FS rename into kb-store layout.
	ksDir, err := promoteKbStaging(stagingDir, kbID, ksID)
	if err != nil {
		return fmt.Errorf("promote staging: %w", err)
	}
	// From here on: failure leaves orphan ksDir until Phase 34 gc.

	// Step 4: open DB + run single-tx ingest. DSN comes from config.yaml only
	// (DPAPI-decrypted password); no flag, no env override.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config (run `unravel db setup` first): %w", err)
	}
	dsn, err := cfg.DSN(ctx)
	if err != nil {
		return fmt.Errorf("resolve dsn from config: %w", err)
	}
	sqlDB, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()

	storeRoot, err := fsutil.KBStoreRoot()
	if err != nil {
		return fmt.Errorf("resolve kb-store root: %w", err)
	}

	// Source-binary SHA from input file — authoritative for idempotency
	// on archive inputs (APK/IPA). Skip for directory inputs (MSIX, repos)
	// so the ingest writer falls back to walk-derived; os.Open on a
	// directory errors with "Incorrect function" on Windows.
	var binarySHA string
	if fi, statErr := os.Stat(appPath); statErr == nil && fi.Mode().IsRegular() {
		var hashErr error
		binarySHA, hashErr = sha256OfCapturePath(appPath)
		if hashErr != nil {
			return fmt.Errorf("hash input file: %w", hashErr)
		}
	}

	res, err := ingest.Run(ctx, sqlDB, kbID, ksID, ksDir, ingest.Options{
		Tags:          kbCaptureFlags.tags,
		Reason:        kbCaptureFlags.reason,
		By:            kbCaptureFlags.by,
		Force:         kbCaptureFlags.force,
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
		// Tx rolled back; ksDir is now orphan.
		_, _ = fmt.Fprintf(os.Stderr,
			"warning: db ingest failed; kb-store folder %q is orphan; run 'kb gc --orphan-folders' (Phase 34) to clean up\n",
			ksDir)
		return fmt.Errorf("ingest run: %w", err)
	}

	// D-31-APPLY-POST-INGEST: best-effort component classification after the
	// ingest tx has committed. A classifier failure must NOT fail capture —
	// it only logs a warning. Reuses the same *sql.DB handle (no second
	// connection). Phase 30 ingest writer is untouched.
	if rep, cerr := classify.Run(ctx, sqlDB, res.KBID, res.Epoch); cerr != nil {
		slog.Warn("classifier failed; module_components rows skipped",
			"kb_id", res.KBID, "epoch", res.Epoch, "err", cerr)
	} else if rep != nil {
		slog.Info("post-ingest classify",
			"kb_id", rep.KBID, "epoch", rep.Epoch,
			"classified", rep.ModulesClassified, "skipped", rep.Skipped)
	}

	// Step 5: summary output.
	return printSummary(cmd.OutOrStdout(), res, kbCaptureFlags.jsonOut)
}

// stageKbAnalysis runs the in-process knowledge analyzer into a temp dir
// under <kb-store>/staging/<random>/ via knowledge.Run
// (pkg/knowledge/knowledge.go:27).
//
// CRITICAL: This MUST call knowledge.Run directly. NO os/exec, NO
// subprocess spawn — INGE-01 requires in-process invocation for atomic
// capture semantics + reliable error propagation. T-30-04-07 mitigation.
func stageKbAnalysis(ctx context.Context, appPath string) (string, []clr.TypeModule, error) {
	root, err := fsutil.KBStoreRoot()
	if err != nil {
		return "", nil, fmt.Errorf("resolve kb-store root: %w", err)
	}
	id, err := randID()
	if err != nil {
		return "", nil, fmt.Errorf("alloc staging id: %w", err)
	}
	staging := filepath.Join(root, "staging", id)
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return "", nil, fmt.Errorf("mkdir staging: %w", err)
	}
	// Pinned signature from pkg/knowledge/knowledge.go:27:
	//   func Run(path string, opts Options) (*KnowledgeResult, error)
	// Synchronous; no context arg. ctx is unused for the call itself but
	// kept on the function signature for future cancellation wiring.
	_ = ctx
	kr, err := knowledge.Run(appPath, knowledge.Options{
		OutputDir: staging,
		Verbose:   kbCaptureFlags.verbose,
	})
	if err != nil {
		return "", nil, fmt.Errorf("knowledge analysis: %w", err)
	}
	// FIX #1: forward native CLR modules to ingest (no sidecar). nil for non-.NET.
	return staging, kr.CLRModules, nil
}

// promoteKbStaging atomically renames stagingDir into the canonical
// kb-store/apps/<kb_id>/versions/<ks_id_fs>/ layout. The rename is the
// last filesystem step before DB ingest begins.
func promoteKbStaging(stagingDir, kbID, ksID string) (string, error) {
	root, err := fsutil.KBStoreRoot()
	if err != nil {
		return "", fmt.Errorf("resolve kb-store root: %w", err)
	}
	ksFS, err := fsutil.EncodeKsID(ksID)
	if err != nil {
		return "", fmt.Errorf("encode ks_id: %w", err)
	}
	target := filepath.Join(root, "apps", kbID, "versions", ksFS)
	target = fsutil.WrapLongPath(target)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", fmt.Errorf("mkdir target parent: %w", err)
	}
	if err := os.Rename(stagingDir, target); err != nil {
		return "", fmt.Errorf("rename staging to target: %w", err)
	}
	return target, nil
}

// loadFingerprintInputs reads <stagingDir>/knowledge.json and returns the
// minimum set of fields required by identity.Fingerprint. Missing fields
// are tolerated as long as Fingerprint's own contract is met (Platform
// required; PackageID OR DisplayName required).
func loadFingerprintInputs(stagingDir, srcPath string) (identity.FingerprintInputs, error) {
	in := identity.FingerprintInputs{CapturedAt: time.Now().UnixMilli()}
	f, err := os.Open(filepath.Join(stagingDir, "knowledge.json"))
	if err != nil {
		return in, fmt.Errorf("open knowledge.json: %w", err)
	}
	defer func() { _ = f.Close() }()
	const maxKnowledgeJSON = 64 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(f, maxKnowledgeJSON))
	if err != nil {
		return in, fmt.Errorf("read knowledge.json: %w", err)
	}
	raw := map[string]any{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return in, fmt.Errorf("parse knowledge.json: %w", err)
	}
	if v, ok := raw["platform"].(string); ok {
		in.Platform = v
	}
	if v, ok := raw["package_id"].(string); ok {
		in.PackageID = v
	}
	if v, ok := raw["display_name"].(string); ok {
		in.DisplayName = v
	}
	if v, ok := raw["app_version"].(string); ok {
		in.AppVersion = v
	}
	if v, ok := raw["captured_at"].(float64); ok && v > 0 {
		in.CapturedAt = int64(v)
	}
	if in.Platform == "" {
		// Lone-artifact fallback: a bare .dll/.jar/.wasm/.exe has no app
		// manifest, so knowledge.json carries no platform. Synthesize a
		// minimal, valid fingerprint from the source file rather than
		// rejecting the input. srcPath == "" preserves the old strict
		// behavior (e.g. the `kb enrich ingest <ks_dir>` path).
		if srcPath == "" {
			return in, errors.New("knowledge.json missing platform field")
		}
		base := filepath.Base(srcPath)
		in.Platform = identity.PlatformForArtifact(base)
		if in.DisplayName == "" {
			in.DisplayName = base
		}
	}
	return in, nil
}

// printSummary emits either plain text (default) or JSON Result struct.
func printSummary(w io.Writer, res *ingest.Result, asJSON bool) error {
	if res == nil {
		return errors.New("nil ingest result")
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if res.Skipped {
		_, err := fmt.Fprintf(w, "skipped kb_id=%s reason=%q\n", res.KBID, res.SkippedReason)
		return err
	}
	riskScore := "n/a"
	if res.RiskScore != nil {
		riskScore = strconv.Itoa(*res.RiskScore)
	}
	// res.Epoch is int64 per Plan 30-03 Result struct.
	_, err := fmt.Fprintf(w,
		"captured kb_id=%s ks_id=%s epoch=%d depth=%d risk_score=%s risk_level=%s diffs=%d\n",
		res.KBID, res.KSID, res.Epoch,
		res.DepthScore, riskScore, res.RiskLevel, res.DiffsWritten)
	return err
}

// randID returns a 16-char hex token used as the per-run staging dir
// suffix. crypto/rand only — no math/rand seeding hazard.
func randID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// sha256OfCapturePath returns the hex-encoded SHA-256 of the file at
// path. Seeds ingest.Options.BinarySHA256 from the source-binary input.
func sha256OfCapturePath(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
