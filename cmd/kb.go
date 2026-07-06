/*
Copyright (c) 2026 Security Research
*/

package cmd

import "github.com/spf13/cobra"

// kbCmd is the parent command for knowledge-base operations. Phase 29 ships
// `merge` only; Phase 32 lands `show`, `list`, `diff`, etc.
var kbCmd = &cobra.Command{
	Use:   "kb",
	Short: "Knowledge base operations (merge; Phase 32 lands more)",
	Long: `Operate on the unravel knowledge base.

Phase 29 ships ` + "`merge`" + ` only — analysts use it to collapse identity
forks (cert rotation, display-name churn) the moment they appear. Phase 32
will land ` + "`show`, `list`, `diff`" + ` and other read-side subcommands.`,
}

// kbCatalogCmd groups the browse/read-side knowledge-base subcommands.
var kbCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Browse and read the knowledge base",
}

// kbEnrichCmd groups the populate/enrich knowledge-base subcommands.
var kbEnrichCmd = &cobra.Command{
	Use:   "enrich",
	Short: "Populate and enrich knowledge-base rows",
}

// kbFindingsCmd groups the adjudication-findings subcommands.
var kbFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Adjudication findings",
}

// kbDriftCmd groups the knowledge-base drift-tracking subcommands.
var kbDriftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Knowledge-base drift tracking",
}

// kbGapsCmd groups the knowledge-gap workflow subcommands.
var kbGapsCmd = &cobra.Command{
	Use:   "gaps",
	Short: "Knowledge gap workflow",
}

// kbTransferCmd groups the export/import/diff data-movement subcommands.
var kbTransferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Move knowledge-base data (export/import/diff)",
}

// kbOpsCmd groups the knowledge-base maintenance subcommands.
var kbOpsCmd = &cobra.Command{
	Use:   "ops",
	Short: "Knowledge-base maintenance",
}

func init() {
	rootCmd.AddCommand(kbCmd)
	kbCmd.AddCommand(kbCatalogCmd, kbEnrichCmd, kbFindingsCmd, kbDriftCmd, kbGapsCmd, kbTransferCmd, kbOpsCmd)
}
