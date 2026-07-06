/*
Copyright (c) 2026 Security Research
*/
// knowledge_doctor.go — `unravel knowledge doctor` integrity command.
//
// Runs the soft-FK orphan check, embedding-dim mismatch check, and
// fact_history row count. With --fix it backfills module_deps.to_id and
// pads any seconds-resolution fact_history.observed_at rows to milliseconds.
//
// All operations are idempotent and read-mostly without --fix.
package cmd

import (
	"fmt"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"

	"github.com/spf13/cobra"
)

var (
	doctorDB  string
	doctorFix bool
)

var kbDoctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Audit knowledge.db integrity — orphans, embedding dims, fact_history precision",
	Long: `Reports schema-coherence issues that don't trip CREATE TABLE IF NOT EXISTS:
soft-FK orphans (modules.body_sha256 / module_enrichment.body_sha256 →
module_bodies), module_embeddings whose vector blob length disagrees with
dim×4 (f32) or dim×2 (f16), and fact_history.observed_at values still in
seconds.

With --fix the doctor backfills module_deps.to_id and pads pre-2026-04-26
fact_history rows ×1000. Embedding dim mismatches are reported but not
auto-repaired (the data is write-only from external embedders).`,
	RunE: runKBDoctor,
}

func init() {
	kbDoctorCmd.Flags().StringVar(&doctorDB, "database", "", "Path to knowledge.db (required)")
	kbDoctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "Apply repairable migrations (backfill to_id, pad observed_at)")
	_ = kbDoctorCmd.MarkFlagRequired("database")
	kbOpsCmd.AddCommand(kbDoctorCmd)
}

func runKBDoctor(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(doctorDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	mods, enr, err := kbdb.CheckOrphans(db)
	if err != nil {
		return err
	}
	dimBad, err := kbdb.CheckEmbeddingDims(db)
	if err != nil {
		return err
	}
	histN, err := kbdb.CountFactHistory(db)
	if err != nil {
		return err
	}

	fmt.Printf("knowledge doctor — %s\n", doctorDB)
	fmt.Printf("  orphan modules         (modules.body_sha256 → module_bodies):       %d\n", mods)
	fmt.Printf("  orphan enrichment      (module_enrichment.body_sha256 → bodies):    %d\n", enr)
	fmt.Printf("  bad embedding dims     (length(vector) ≠ dim*4 and ≠ dim*2):        %d\n", dimBad)
	fmt.Printf("  fact_history rows                                                    %d\n", histN)

	if !doctorFix {
		fmt.Println("\nrun again with --fix to apply repairable migrations.")
		return nil
	}

	fmt.Println("\napplying --fix migrations...")

	resolved, err := kbstore.BackfillModuleDepsToID(db)
	if err != nil {
		return fmt.Errorf("backfill to_id: %w", err)
	}
	fmt.Printf("  backfill module_deps.to_id:   touched=%d (NULL stays NULL for external deps)\n", resolved)

	padded, err := kbdb.MigrateFactHistoryToMillis(db)
	if err != nil {
		return fmt.Errorf("migrate fact_history: %w", err)
	}
	fmt.Printf("  pad fact_history ×1000:       padded=%d\n", padded)

	fmt.Println("done.")
	return nil
}
