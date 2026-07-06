/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// archiveSpec describes a package-archive command family (info/extract/verify)
// that shares identical CLI plumbing. Per-format behaviour — the analyzer
// package invoked and the human-readable printers — stays in the typed Run
// functions in each format's file; only the cobra scaffolding is shared here.
type archiveSpec struct {
	use   string // command word: "msi", "msix", "rpm"
	short string // parent Short
	long  string // parent Long

	infoShort    string
	extractShort string
	verifyShort  string

	jsonFlag *bool // bound to the format's package-level --json var

	runInfo    func(*cobra.Command, []string)
	runExtract func(*cobra.Command, []string)
	runVerify  func(*cobra.Command, []string)
}

// newArchiveCmd builds the parent command, its info/extract/verify
// subcommands, and the persistent --json flag, identically to the former
// hand-written msi/msix/rpm command files.
func newArchiveCmd(s archiveSpec) *cobra.Command {
	parent := &cobra.Command{Use: s.use, Short: s.short, Long: s.long}

	parent.AddCommand(
		&cobra.Command{Use: "info <file>", Short: s.infoShort, Args: cobra.ExactArgs(1), Run: s.runInfo},
		&cobra.Command{Use: "extract <file>", Short: s.extractShort, Args: cobra.ExactArgs(1), Run: s.runExtract},
		&cobra.Command{Use: "verify <file>", Short: s.verifyShort, Args: cobra.ExactArgs(1), Run: s.runVerify},
	)
	parent.PersistentFlags().BoolVar(s.jsonFlag, "json", false, "Output as JSON")

	return parent
}

// emitArchive is the shared error/JSON/print tail used by every archive
// subcommand Run function. On error it prints and exits(1); otherwise it emits
// JSON when jsonFormat is set, or calls printText (a typed closure) for the
// human-readable rendering.
func emitArchive(jsonFormat bool, err error, result any, printText func()) {
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

		return
	}

	printText()
}
