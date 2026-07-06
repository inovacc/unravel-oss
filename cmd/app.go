/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// appCmd groups the whole-app / cross-cutting operations that used to live as
// bare verbs at the root (scan, dissect, detect, forensic, heuristic, schema,
// reconstruct, inject, ...). Per the command-taxonomy redesign, the root no
// longer exposes bare verbs; they are re-parented under `app`.
var appCmd = &cobra.Command{
	Use:   "app",
	Short: "Whole-app / cross-cutting operations",
}

func init() {
	rootCmd.AddCommand(appCmd)
}
