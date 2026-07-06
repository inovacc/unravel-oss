/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/dpapidump"

	"github.com/spf13/cobra"
)

var (
	dpapiDumpMKRoots      []string
	dpapiDumpProfiles     []string
	dpapiDumpMaxFiles     int
	dpapiDumpOutputDir    string
	dpapiDumpJSONOnlyFlag bool
)

var dpapiDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Flag-only enumeration of DPAPI master keys + Chromium-wrapped secrets",
	Long: `Walk DPAPI master-key directories and Chromium profile envelopes WITHOUT
decrypting anything. Per D-14 / D-18, the default surface reports only the
presence + size + algorithm wrapper. Decryption is a separate path
(see ` + "`unravel dpapi decrypt`" + `, windows+cgo only).

If --master-key-root is omitted, defaults to %APPDATA%\Microsoft\Protect
on Windows; non-Windows must specify roots explicitly (useful for offline
analysis of a copied profile).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := dpapidump.DumpOptions{
			MasterKeyRoots:   dpapiDumpMKRoots,
			ChromiumProfiles: dpapiDumpProfiles,
			MaxFiles:         dpapiDumpMaxFiles,
		}
		res, err := dpapidump.Dump(opts)
		if err != nil {
			return err
		}

		if dpapiDumpJSONOnlyFlag || dpapiDumpOutputDir == "" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		}
		if err := os.MkdirAll(dpapiDumpOutputDir, 0o755); err != nil {
			return fmt.Errorf("mkdir output: %w", err)
		}
		path := filepath.Join(dpapiDumpOutputDir, "dpapi-dump.json")
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		defer func() { _ = f.Close() }()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(res); encErr != nil {
			return encErr
		}
		fmt.Printf("Master keys     : %d\n", len(res.MasterKeys))
		fmt.Printf("Chromium scanned: %d\n", len(res.Chromium))
		fmt.Printf("Errors          : %d\n", len(res.Errors))
		fmt.Printf("JSON            : %s\n", path)
		return nil
	},
}

func init() {
	dpapiCmd.AddCommand(dpapiDumpCmd)
	dpapiDumpCmd.Flags().StringSliceVar(&dpapiDumpMKRoots, "master-key-root", nil, "DPAPI master-key directory (repeatable; empty = default %APPDATA%\\Microsoft\\Protect on Windows)")
	dpapiDumpCmd.Flags().StringSliceVar(&dpapiDumpProfiles, "chromium-profile", nil, "Chromium profile directory containing Local State (repeatable)")
	dpapiDumpCmd.Flags().IntVar(&dpapiDumpMaxFiles, "max-files", 256, "max master-key files reported per root")
	dpapiDumpCmd.Flags().StringVarP(&dpapiDumpOutputDir, "output", "o", "", "directory for dpapi-dump.json (empty = stdout JSON)")
	dpapiDumpCmd.Flags().BoolVar(&dpapiDumpJSONOnlyFlag, "json", false, "force stdout JSON output even with --output set")
}
