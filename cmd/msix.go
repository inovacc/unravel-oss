/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/msix"

	"github.com/spf13/cobra"
)

var msixJSONFormat bool

var msixCmd = newArchiveCmd(archiveSpec{
	use:   "msix",
	short: "MSIX package analysis and extraction",
	long: `Parse, extract, and analyze Windows MSIX/APPX packages.

MSIX files are ZIP-based containers with AppxManifest.xml describing the
package identity, capabilities, dependencies, and entry points.

Subcommands:
  info      - Display package metadata, capabilities, and applications
  extract   - Extract package contents to disk
  verify    - Check for AppxSignature.p7x digital signatures`,
	infoShort:    "Display MSIX package metadata and structure",
	extractShort: "Extract MSIX package contents to disk",
	verifyShort:  "Check for AppxSignature.p7x digital signatures",
	jsonFlag:     &msixJSONFormat,
	runInfo:      runMsixInfo,
	runExtract:   runMsixExtract,
	runVerify:    runMsixVerify,
})

func init() {
	rootCmd.AddCommand(msixCmd)
}

func runMsixInfo(_ *cobra.Command, args []string) {
	info, err := msix.Info(args[0])
	emitArchive(msixJSONFormat, err, info, func() { out.PrintMsixInfo(info) })
}

func runMsixExtract(_ *cobra.Command, args []string) {
	report, err := msix.Extract(args[0], output)
	emitArchive(msixJSONFormat, err, report, func() { out.PrintMsixExtract(report) })
}

func runMsixVerify(_ *cobra.Command, args []string) {
	result, err := msix.Verify(args[0])
	emitArchive(msixJSONFormat, err, result, func() { out.PrintMsixVerify(result) })
}
