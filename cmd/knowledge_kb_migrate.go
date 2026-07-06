/*
Copyright (c) 2026 Security Research
*/
// Package cmd / knowledge_kb_migrate.go hosts the `unravel knowledge migrate`
// cobra command (Phase 66 Plan 05; D-66-01, D-66-03, D-66-06 commit #5).
//
// Deliberate deviation from strict D-66-03 co-location: the shared run
// function `runKnowledgeMigrate` and its test-override seam
// `migrateClientFn` remain in cmd/knowledge.go. Both `kbMigrateCmd` (here)
// and `knowledgeMigrateCmd` (Plan 06) wire their RunE to the same shared
// function, so the function lives next to its semantic owner — the
// `knowledge` tree — and is reached from this file via package scope.
//
// init() registration of this command (AddCommand + flag binds) stays in
// cmd/knowledge.go's init() per D-66-04 to preserve cobra registration
// order (TestKnowledgeHelpGolden is the load-bearing gate).
package cmd

import (
	"github.com/spf13/cobra"
)

// ── migrate (07-04) ──

var kbMigrateCmd = &cobra.Command{
	Use:   "migrate <kb-dir>",
	Short: "Generate cross-framework migration hints. Token cost applies.",
	Long: `Generate per-component cross-framework migration hints under
<kb-dir>/migrations/<framework>/<component>/migration.json + summary.md.

Lazy: only this subcommand triggers MCP-backed migration hint generation.
Default 'unravel knowledge' does NOT produce migrations.

Valid target frameworks: react, vue, angular, svelte, wpf, winui3, flutter, react-native.

Examples:
  unravel knowledge migrate ./knowledge-myapp --to react
  unravel knowledge migrate ./knowledge-myapp --to vue`,
	Args: cobra.ExactArgs(1),
	RunE: runKnowledgeMigrate,
}
