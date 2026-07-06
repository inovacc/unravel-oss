/*
Copyright (c) 2026 Security Research

kb_ingest.go — `unravel kb ingest <ks_dir>` (Phase 32, Plan 32-07).

Folder-only re-ingest subcommand. Re-ingests an existing KS folder (already
promoted to kb-store/apps/...) without FS rename. Useful for repairing DB
state after manual intervention or logic updates.

License: BSD-3-Clause.
*/

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"
)

var kbIngestFlags struct {
	tags   []string
	reason string
	by     string
	json   bool
	force  bool
}

var ingestCmd = &cobra.Command{
	Use:   "ingest <ks_dir>",
	Short: "Re-ingest an existing KS folder into the KB (Phase 32)",
	Long: `Re-ingest an existing knowledge-source folder already located under the
kb-store apps/ hierarchy. Unlike 'kb capture', this command does NOT run
the analyzer and does NOT rename the folder. It reads knowledge.json from
the target directory to derive identity.`,
	Args: cobra.ExactArgs(1),
	RunE: runKbIngest,
}

func init() {
	ingestCmd.Flags().StringSliceVar(&kbIngestFlags.tags, "tag", nil, "capture tags")
	ingestCmd.Flags().StringVar(&kbIngestFlags.reason, "reason", "", "capture reason")
	ingestCmd.Flags().StringVar(&kbIngestFlags.by, "by", "", "analyst identifier")
	ingestCmd.Flags().BoolVar(&kbIngestFlags.json, "json", false, "emit JSON")
	ingestCmd.Flags().BoolVar(&kbIngestFlags.force, "force", false, "re-ingest despite identical binary_sha256")
	kbEnrichCmd.AddCommand(ingestCmd)
}

func runKbIngest(cmd *cobra.Command, args []string) error {
	ksDir := filepath.Clean(args[0])
	if strings.Contains(ksDir, "..") {
		return fmt.Errorf("ks_dir cannot contain '..': %s", ksDir)
	}
	if _, err := os.Stat(ksDir); err != nil {
		return fmt.Errorf("stat ks_dir: %w", err)
	}

	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	// derive Fingerprint inputs from directory (knowledge.json).
	fpIn, err := loadFingerprintInputs(ksDir, "")
	if err != nil {
		return fmt.Errorf("load fingerprint inputs: %w", err)
	}
	kbID, ksID, err := identity.Fingerprint(fpIn)
	if err != nil {
		return fmt.Errorf("fingerprint directory: %w", err)
	}

	dsn, err := kb_output.ResolveDSN("")
	if err != nil {
		return err
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

	res, err := ingest.Run(ctx, sqlDB, kbID, ksID, ksDir, ingest.Options{
		Tags:          kbIngestFlags.tags,
		Reason:        kbIngestFlags.reason,
		By:            kbIngestFlags.by,
		Force:         kbIngestFlags.force,
		ResolveAlias:  true,
		AllowedRoots:  []string{storeRoot},
		PackageID:     fpIn.PackageID,
		Platform:      fpIn.Platform,
		DisplayName:   fpIn.DisplayName,
		CanonicalName: identity.CanonicalName(fpIn.DisplayName),
	})
	if err != nil {
		return fmt.Errorf("ingest run: %w", err)
	}

	// Use printSummary from kb_capture.go (it's package-level).
	return printSummary(cmd.OutOrStdout(), res, kbIngestFlags.json)
}
