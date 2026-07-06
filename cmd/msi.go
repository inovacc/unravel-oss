/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/msi"

	"github.com/spf13/cobra"
)

var msiJSONFormat bool

var msiCmd = newArchiveCmd(archiveSpec{
	use:   "msi",
	short: "MSI package analysis and extraction",
	long: `Parse, extract, and analyze Windows Installer (.msi) packages.

MSI files are OLE Compound Document (CFBF) containers holding a relational
database with tables describing the installation (files, registry, custom
actions, etc.).

Subcommands:
  info      - Display package metadata, properties, files, and custom actions
  extract   - Extract OLE streams to disk
  verify    - Check for Authenticode digital signatures`,
	infoShort:    "Display MSI package metadata and structure",
	extractShort: "Extract OLE streams to disk",
	verifyShort:  "Check for Authenticode digital signatures",
	jsonFlag:     &msiJSONFormat,
	runInfo:      runMsiInfo,
	runExtract:   runMsiExtract,
	runVerify:    runMsiVerify,
})

func init() {
	rootCmd.AddCommand(msiCmd)
}

func runMsiInfo(_ *cobra.Command, args []string) {
	info, err := msi.Info(args[0])
	emitArchive(msiJSONFormat, err, info, func() { out.PrintMsiInfo(info) })
}

func runMsiExtract(_ *cobra.Command, args []string) {
	report, err := msi.Extract(args[0], output)
	emitArchive(msiJSONFormat, err, report, func() { out.PrintMsiExtract(report) })
}

func runMsiVerify(_ *cobra.Command, args []string) {
	result, err := msi.Verify(args[0])
	emitArchive(msiJSONFormat, err, result, func() { out.PrintMsiVerify(result) })
}
