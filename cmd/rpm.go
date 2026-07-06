/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/pkg/rpm"

	"github.com/spf13/cobra"
)

var rpmJSONFormat bool

var rpmCmd = newArchiveCmd(archiveSpec{
	use:   "rpm",
	short: "RPM package analysis and extraction",
	long: `Parse, extract, and analyze RPM package files.

RPM files contain:
  Lead       - Legacy identification (96 bytes)
  Signature  - Cryptographic signatures and checksums
  Header     - Package metadata (name, version, deps)
  Payload    - Compressed CPIO archive

Subcommands:
  info      - Display package metadata from header tags
  extract   - Extract payload contents to disk
  verify    - Check signature and hash information`,
	infoShort:    "Display package metadata from header tags",
	extractShort: "Extract payload contents to disk",
	verifyShort:  "Check signature and hash information",
	jsonFlag:     &rpmJSONFormat,
	runInfo:      runRpmInfo,
	runExtract:   runRpmExtract,
	runVerify:    runRpmVerify,
})

func init() {
	rootCmd.AddCommand(rpmCmd)
}

func runRpmInfo(_ *cobra.Command, args []string) {
	info, err := rpm.Info(args[0])
	emitArchive(rpmJSONFormat, err, info, func() { out.PrintRpmInfo(info) })
}

func runRpmExtract(_ *cobra.Command, args []string) {
	report, err := rpm.Extract(args[0], output)
	emitArchive(rpmJSONFormat, err, report, func() { out.PrintRpmExtract(report) })
}

func runRpmVerify(_ *cobra.Command, args []string) {
	result, err := rpm.Verify(args[0])
	emitArchive(rpmJSONFormat, err, result, func() { out.PrintRpmVerify(result) })
}
