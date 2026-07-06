/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/inovacc/unravel-oss/pkg/frida/autogen"
	"github.com/inovacc/unravel-oss/pkg/inject"

	"github.com/spf13/cobra"
)

var (
	fridaFromSeamsOutDir   string
	fridaFromSeamsPlatform string
)

var fridaFromSeamsCmd = &cobra.Command{
	Use:   "from-seams <report.json>",
	Short: "Generate per-seam Frida JS + criteria.json from a SeamReport",
	Long: `Reads a SeamReport (the JSON output of "unravel inject scan") and emits
one <id>.js + <id>.criteria.json file per seam under -o.

Linux-target scripts include a kernel.yama.ptrace_scope preflight at the top
of the generated JS. Windows / macOS scripts have no preflight in v2.4.

Examples:
  unravel frida from-seams ./report.json -o ./scripts/
  unravel frida from-seams ./report.json -o ./scripts/ --platform linux
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read report: %w", err)
		}
		var report inject.ScanResult
		if err := json.Unmarshal(raw, &report); err != nil {
			return fmt.Errorf("parse report: %w", err)
		}
		opts := autogen.Options{Platform: fridaFromSeamsPlatform}
		res, err := autogen.Generate(report, fridaFromSeamsOutDir, opts)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "Wrote %d scripts to %s (skipped=%d)\n",
			len(res.Scripts), res.OutDir, res.Skipped)
		return nil
	},
}

func init() {
	fridaFromSeamsCmd.Flags().StringVarP(&fridaFromSeamsOutDir, "output", "o", "", "Output directory (required)")
	fridaFromSeamsCmd.Flags().StringVar(&fridaFromSeamsPlatform, "platform", "", "Filter platform: windows | macos | linux")
	_ = fridaFromSeamsCmd.MarkFlagRequired("output")
	fridaCmd.AddCommand(fridaFromSeamsCmd)
}
