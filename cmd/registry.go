/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winregistry"

	"github.com/spf13/cobra"
)

var (
	regDumpDepth    int
	regDumpMaxVals  int
	regDumpDryRun   bool
	regDumpKeyFile  string
	regDumpOutDir   string
	regDumpJSONOnly bool
)

var registryCmd = &cobra.Command{
	Use:   "registry",
	Short: "Windows registry forensic dumps",
	Long: `Scoped read-only Windows registry walker.

Emits JSON manifest + NDJSON stream + .reg replay file. Pure-Go on Windows;
returns a structured "not supported" error on other OSes.`,
}

var registryDumpCmd = &cobra.Command{
	Use:   "dump <key>...",
	Short: "Dump one or more registry keys to JSON/NDJSON/.reg",
	Long: `Dump scoped registry keys.

Keys must be hive-prefixed: HKLM\..., HKCU\..., HKCR\..., HKU\..., HKCC\...
Pass multiple --key flags or a --key-file with one path per line.

Each key is walked up to --depth subkey levels (default 3, capped at 20).
Per-key values are truncated at --max-values (default 256, capped at 4096)
to keep output bounded on wide keys like HKLM\SYSTEM\CurrentControlSet\Enum.

Outputs:
  <output>/registry-dump.json   — full structured tree
  <output>/registry-dump.ndjson — one KeyDump per line for streaming readers
  <output>/registry-dump.reg    — Windows .reg replay (REGEDIT4 v5)

Use --dry-run to preview the surface that would be touched without
reading any values.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		keys := append([]string{}, args...)
		if regDumpKeyFile != "" {
			data, err := os.ReadFile(regDumpKeyFile)
			if err != nil {
				return fmt.Errorf("read key file: %w", err)
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				keys = append(keys, line)
			}
		}
		if len(keys) == 0 {
			return fmt.Errorf("at least one --key or positional path is required")
		}

		res, err := winregistry.Dump(winregistry.DumpOptions{
			Keys:            keys,
			MaxDepth:        regDumpDepth,
			MaxValuesPerKey: regDumpMaxVals,
			DryRun:          regDumpDryRun,
		})
		if err != nil && res == nil {
			return err
		}

		// JSON-only mode: stdout JSON, no disk writes.
		if regDumpJSONOnly || regDumpOutDir == "" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(res); encErr != nil {
				return encErr
			}
			return err // propagate ErrNotSupported on non-Windows
		}

		if err := os.MkdirAll(regDumpOutDir, 0o755); err != nil {
			return fmt.Errorf("mkdir output: %w", err)
		}

		jsonPath := filepath.Join(regDumpOutDir, "registry-dump.json")
		if writeErr := writeJSON(jsonPath, res); writeErr != nil {
			return writeErr
		}
		ndjsonPath := filepath.Join(regDumpOutDir, "registry-dump.ndjson")
		if writeErr := writeNDJSON(ndjsonPath, res); writeErr != nil {
			return writeErr
		}
		regPath := filepath.Join(regDumpOutDir, "registry-dump.reg")
		if writeErr := writeRegReplay(regPath, res); writeErr != nil {
			return writeErr
		}

		fmt.Printf("Keys captured : %d\n", len(res.Keys))
		fmt.Printf("Errors        : %d\n", len(res.Errors))
		fmt.Printf("JSON          : %s\n", jsonPath)
		fmt.Printf("NDJSON        : %s\n", ndjsonPath)
		fmt.Printf(".reg replay   : %s\n", regPath)
		return err
	},
}

func writeJSON(path string, res *winregistry.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func writeNDJSON(path string, res *winregistry.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	for _, kd := range res.Keys {
		if encErr := enc.Encode(kd); encErr != nil {
			return encErr
		}
	}
	return nil
}

func writeRegReplay(path string, res *winregistry.Result) error {
	var b strings.Builder
	b.WriteString("Windows Registry Editor Version 5.00\r\n\r\n")
	for _, kd := range res.Keys {
		if kd.Err != "" || kd.Path == "" {
			continue
		}
		b.WriteString("[" + kd.Path + "]\r\n")
		for _, v := range kd.Values {
			name := v.Name
			if name == "" {
				name = "@"
			} else {
				name = `"` + name + `"`
			}
			switch v.Type {
			case "REG_SZ":
				b.WriteString(name + `="` + escapeRegString(v.String) + `"` + "\r\n")
			case "REG_EXPAND_SZ":
				b.WriteString(name + `=hex(2):` + bytesToHex([]byte(v.String)) + "\r\n")
			case "REG_DWORD":
				if v.DWORD != nil {
					b.WriteString(fmt.Sprintf("%s=dword:%08x\r\n", name, *v.DWORD))
				}
			default:
				// REG_BINARY / REG_MULTI_SZ / fallback — emit as hex.
				b.WriteString(name + `=hex:` + v.Binary + "\r\n")
			}
		}
		b.WriteString("\r\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func escapeRegString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func bytesToHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, hex[c>>4], hex[c&0x0F])
	}
	return string(out)
}

func init() {
	rootCmd.AddCommand(registryCmd)
	registryCmd.AddCommand(registryDumpCmd)
	registryDumpCmd.Flags().IntVar(&regDumpDepth, "depth", 3, "max subkey recursion depth (capped at 20)")
	registryDumpCmd.Flags().IntVar(&regDumpMaxVals, "max-values", 256, "max values captured per key (capped at 4096)")
	registryDumpCmd.Flags().BoolVar(&regDumpDryRun, "dry-run", false, "walk subkeys but skip value reads")
	registryDumpCmd.Flags().StringVar(&regDumpKeyFile, "key-file", "", "file with one key path per line (additive to positional args)")
	registryDumpCmd.Flags().StringVarP(&regDumpOutDir, "output", "o", "", "directory for json/ndjson/.reg outputs (empty = stdout JSON only)")
	registryDumpCmd.Flags().BoolVar(&regDumpJSONOnly, "json", false, "force stdout JSON output even with --output set")
}
