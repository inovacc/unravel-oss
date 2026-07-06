/*
Copyright (c) 2026 Security Research

kb_import.go — `unravel kb import` (Phase 43, Plan 43-02).

Imports a D-43-BUNDLE-SCHEMA-V1 bundle (.kbb.tar.gz file or directory tree)
back into a Postgres KB. Idempotent on re-import (KBIM-03) via ON CONFLICT
DO NOTHING per table.
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	kbexport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

var kbImportFlags struct {
	bundle        string
	dsn           string
	jsonOut       bool
	verifyKey     string // v2.9 P54 BNDL-02: Ed25519 public key path for V2 verification.
	allowUnsigned bool   // hardening #8: explicit opt-out for importing without --verify-key.
}

var kbImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a D-43 KB bundle (.kbb.tar.gz or directory)",
	Long: `Import a D-43-BUNDLE-SCHEMA-V1 bundle into a KB Postgres database.

The bundle source may be either:
  - a .kbb.tar.gz file produced by ` + "`unravel kb export --bundle`" + `
  - a directory tree at <root>/<kb_id>.kbb/ (or that directory directly)

The import is idempotent: re-importing the same bundle is a no-op (rows
collide on their UNIQUE keys and are skipped). Bundle integrity is enforced
via sha256 checksum verification of knowledge.json (T-43-06) and
path-traversal guards on tar entries (T-43-05).`,
	RunE: runKbImport,
}

func init() {
	kbImportCmd.Flags().StringVar(&kbImportFlags.bundle, "bundle", "", "path to bundle (.kbb.tar.gz file or directory)")
	kbImportCmd.Flags().StringVar(&kbImportFlags.verifyKey, "verify-key", "", "path to Ed25519 public key (32 bytes raw); '-' reads stdin. Rejects unsigned/invalid V2 bundles. V1 bundles import with deprecation warning regardless.")
	kbImportCmd.Flags().BoolVar(&kbImportFlags.allowUnsigned, "allow-unsigned", false, "explicitly acknowledge importing a bundle without signature verification (suppresses the provenance warning). Has no effect when --verify-key is set.")
	kb_output.BindDSNFlag(kbImportCmd, &kbImportFlags.dsn)
	kb_output.BindJSONFlag(kbImportCmd, &kbImportFlags.jsonOut)
	_ = kbImportCmd.MarkFlagRequired("bundle")

	kbTransferCmd.AddCommand(kbImportCmd)
}

func runKbImport(cmd *cobra.Command, _ []string) error {
	if kbImportFlags.bundle == "" {
		return errors.New("kb_import: --bundle is required")
	}
	if _, err := os.Stat(kbImportFlags.bundle); err != nil {
		return fmt.Errorf("kb_import: bundle path: %w", err)
	}

	// v2.9 P54 (BNDL-02): pre-flight signature/version check before delegating
	// to kbimport.Import. ADR-0007. Hardening #8: emit a loud provenance
	// warning when importing without --verify-key (default), unless the
	// operator explicitly opts out via --allow-unsigned.
	if err := preflightVerifyBundle(kbImportFlags.bundle, kbImportFlags.verifyKey, kbImportFlags.allowUnsigned); err != nil {
		return err
	}

	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	dsn, err := kb_output.ResolveDSN(kbImportFlags.dsn)
	if err != nil {
		return err
	}

	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()

	report, err := kbstore.Import(ctx, db, kbstore.ImportOptions{
		BundlePath:    kbImportFlags.bundle,
		VerifyKeyPath: kbImportFlags.verifyKey,
	})
	if err != nil {
		return err
	}

	if kbImportFlags.jsonOut {
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, report)
	}

	totalConflicts := 0
	for _, n := range report.ConflictsSkipped {
		totalConflicts += n
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"imported kb_id=%s new_rows=%d conflicts_skipped=%d (sources=%d facts=%d diffs=%d)\n",
		report.KBID, report.ImportedCount, totalConflicts,
		report.Counts.KnowledgeSources, report.Counts.AppFacts, report.Counts.KBDiffs)
	return nil
}

// preflightVerifyBundle reads bundle.json, parses bundle_schema_version, and:
//   - V1: emits a deprecation warning (calendar removal 2026-09-07).
//   - V2 + verifyKey set: delegates to kbstore.VerifyBundleProvenance, which
//     requires the sibling .sig and validates the Ed25519 signature over the
//     canonical manifest. Failure aborts the import.
//   - V2 + verifyKey empty: imports unsigned. Hardening #8 — this now emits a
//     LOUD provenance warning unless the operator passes --allow-unsigned to
//     explicitly acknowledge the unverified import. The default is NOT flipped
//     (that would be a breaking change under the deprecation policy); the
//     warning + opt-out scaffold surface the risk for an operator decision.
//
// Signature verification itself is the shared kbstore.VerifyBundleProvenance
// seam so the CLI and the supervisor/MCP import path enforce identical rules
// (hardening #7).
func preflightVerifyBundle(bundlePath, verifyKeyPath string, allowUnsigned bool) error {
	manifestBytes, err := kbstore.ReadManifestBytes(bundlePath)
	if err != nil {
		return fmt.Errorf("preflight: %w", err)
	}
	manifest, err := kbexport.UnmarshalManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("preflight: parse bundle.json: %w", err)
	}
	switch manifest.BundleSchemaVersion {
	case 1:
		slog.Warn("kb_import: importing D-43 V1 bundle (deprecated)",
			"removal_date", "2026-09-07",
			"see", ".planning/notes/2026-05-07-bundle-schema-v2.md")
		if verifyKeyPath != "" {
			slog.Warn("kb_import: --verify-key ignored for V1 bundle (V1 has no signature surface)")
		}
		return nil
	case 2:
		if verifyKeyPath == "" {
			if !allowUnsigned {
				slog.Warn("kb_import: importing V2 bundle WITHOUT signature verification — provenance unestablished; a tampered bundle would be accepted. Pass --verify-key <pubkey> to enforce the Ed25519 signature, or --allow-unsigned to acknowledge this risk.",
					"bundle", bundlePath, "kb_id", manifest.KbID)
			}
			return nil
		}
		return kbstore.VerifyBundleProvenance(bundlePath, verifyKeyPath)
	default:
		return fmt.Errorf("kb_import: unsupported bundle_schema_version %d", manifest.BundleSchemaVersion)
	}
}
