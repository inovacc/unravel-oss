/*
Copyright (c) 2026 Security Research
*/
// Package cmd / knowledge_findings.go houses the `unravel kb findings`
// subcommands: list, show, resolve, summary. They register directly under
// the kbFindingsCmd group parent declared in cmd/kb.go.
//
// Symbols owned by this file:
//
//	kbFindingsListCmd             — `kb findings list`
//	kbFindingsShowCmd             — `kb findings show`  (alias for list --id)
//	kbFindingsResolveCmd          — `kb findings resolve`
//	kbFindingsSummaryCmd          — `kb findings summary`
//	runKBFindingsList             — RunE for list
//	runKBFindingsShow             — RunE for show
//	runKBFindingsResolve          — RunE for resolve
//	runKBFindingsSummary          — RunE for summary
//
// Cross-file references resolved via package-scoped `package cmd`:
//
//	kbOpenDB — declared in knowledge_kb_extract_index.go
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/findings"

	"github.com/spf13/cobra"
)

// ─────────────────────────────────────────────────────────────────────
// flag-backing variables
// ─────────────────────────────────────────────────────────────────────

var (
	findingsDB string

	// list / show
	findingsApp      string
	findingsModuleID int64
	findingsStance   string
	findingsStatus   string
	findingsLimit    int

	// show (single finding by id)
	findingsShowID int64

	// resolve
	findingsResolveID         int64
	findingsResolveStatus     string
	findingsResolveBy         string
	findingsResolveResolvedAt int64

	// summary
	findingsSummaryApp string
)

// ─────────────────────────────────────────────────────────────────────
// cobra command declarations
// ─────────────────────────────────────────────────────────────────────

var kbFindingsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List KB AI findings with optional filters",
	RunE:  runKBFindingsList,
}

var kbFindingsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a single finding by id",
	RunE:  runKBFindingsShow,
}

var kbFindingsResolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Resolve a finding (accepted|rejected|applied|superseded)",
	RunE:  runKBFindingsResolve,
}

var kbFindingsSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Aggregated finding counts by stance and status",
	RunE:  runKBFindingsSummary,
}

// ─────────────────────────────────────────────────────────────────────
// init: flag wiring + registration
// ─────────────────────────────────────────────────────────────────────

func init() {
	// persistent --database flag on the group parent so all subcommands inherit it
	kbFindingsCmd.PersistentFlags().StringVar(&findingsDB, "database", "", "DSN override (defaults to config.yaml)")

	// list flags
	kbFindingsListCmd.Flags().StringVar(&findingsApp, "app", "", "filter by KB app slug")
	kbFindingsListCmd.Flags().Int64Var(&findingsModuleID, "module-id", 0, "filter by module id (0 = all)")
	kbFindingsListCmd.Flags().StringVar(&findingsStance, "stance", "", "filter by stance: affirm|contradict|augment|uncertain")
	kbFindingsListCmd.Flags().StringVar(&findingsStatus, "status", "", "filter by status: open|accepted|rejected|applied|superseded")
	kbFindingsListCmd.Flags().IntVar(&findingsLimit, "limit", 0, "max rows (0 = default cap of 500)")

	// show flags
	kbFindingsShowCmd.Flags().Int64Var(&findingsShowID, "id", 0, "finding id")
	_ = kbFindingsShowCmd.MarkFlagRequired("id")

	// resolve flags
	kbFindingsResolveCmd.Flags().Int64Var(&findingsResolveID, "id", 0, "finding id")
	kbFindingsResolveCmd.Flags().StringVar(&findingsResolveStatus, "status", "", "accepted|rejected|applied|superseded")
	kbFindingsResolveCmd.Flags().StringVar(&findingsResolveBy, "by", "", "resolver identifier")
	kbFindingsResolveCmd.Flags().Int64Var(&findingsResolveResolvedAt, "resolved-at", 0, "epoch-ms; 0 = now")
	_ = kbFindingsResolveCmd.MarkFlagRequired("id")
	_ = kbFindingsResolveCmd.MarkFlagRequired("status")

	// summary flags
	kbFindingsSummaryCmd.Flags().StringVar(&findingsSummaryApp, "app", "", "KB app slug; empty = all apps")

	// register subcommands under the kb findings group parent (cmd/kb.go)
	kbFindingsCmd.AddCommand(kbFindingsListCmd)
	kbFindingsCmd.AddCommand(kbFindingsShowCmd)
	kbFindingsCmd.AddCommand(kbFindingsResolveCmd)
	kbFindingsCmd.AddCommand(kbFindingsSummaryCmd)
}

// ─────────────────────────────────────────────────────────────────────
// RunE implementations
// ─────────────────────────────────────────────────────────────────────

func runKBFindingsList(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(findingsDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	filter := findings.Filter{
		App:      findingsApp,
		ModuleID: findingsModuleID,
		Stance:   findingsStance,
		Status:   findingsStatus,
		Limit:    findingsLimit,
	}

	rows, err := findings.List(db, filter)
	if err != nil {
		return fmt.Errorf("findings list: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func runKBFindingsShow(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(findingsDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	filter := findings.Filter{
		// List with no app/stance/status filter but scoped by id via limit=1
		// There's no single-row Get in the store, so we list all and match.
		Limit: 500,
	}

	rows, err := findings.List(db, filter)
	if err != nil {
		return fmt.Errorf("findings show: %w", err)
	}

	for _, f := range rows {
		if f.ID == findingsShowID {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(f)
		}
	}

	return fmt.Errorf("findings show: no finding with id=%d", findingsShowID)
}

func runKBFindingsResolve(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(findingsDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	resolvedAt := findingsResolveResolvedAt
	if resolvedAt == 0 {
		resolvedAt = time.Now().UnixMilli()
	}

	if err := findings.Resolve(db, findingsResolveID, findingsResolveStatus, findingsResolveBy, resolvedAt); err != nil {
		return fmt.Errorf("findings resolve: %w", err)
	}

	fmt.Printf("resolved finding id=%d status=%s\n", findingsResolveID, findingsResolveStatus)
	return nil
}

func runKBFindingsSummary(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(findingsDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	sum, err := findings.Summary(db, findingsSummaryApp)
	if err != nil {
		return fmt.Errorf("findings summary: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(sum)
}
