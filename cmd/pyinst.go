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

	"github.com/inovacc/unravel-oss/pkg/pyinst"
	"github.com/inovacc/unravel-oss/pkg/zipapp"

	"github.com/spf13/cobra"
)

var pyinstCmd = &cobra.Command{
	Use:   "pyinst",
	Short: "Python executable analysis (PyInstaller, zipapp)",
	Long: `Analyze and extract Python executables.

Supports:
  PyInstaller  - CArchive-based standalone executables
  Zipapp       - ZIP-based Python applications (pip/pipx wrappers)

Subcommands:
  info      - Show metadata and file listing
  extract   - Extract all bundled files
  check     - Quick detection check`,
}

var pyinstInfoCmd = &cobra.Command{
	Use:   "info <binary>",
	Short: "Show Python executable metadata",
	Args:  cobra.ExactArgs(1),
	Run:   runPyinstInfo,
}

var pyinstExtractCmd = &cobra.Command{
	Use:   "extract <binary>",
	Short: "Extract bundled files from Python executable",
	Args:  cobra.ExactArgs(1),
	Run:   runPyinstExtract,
}

var pyinstCheckCmd = &cobra.Command{
	Use:   "check <binary>",
	Short: "Check if binary is a Python executable",
	Args:  cobra.ExactArgs(1),
	Run:   runPyinstCheck,
}

func init() {
	rootCmd.AddCommand(pyinstCmd)
	pyinstCmd.AddCommand(pyinstInfoCmd)
	pyinstCmd.AddCommand(pyinstExtractCmd)
	pyinstCmd.AddCommand(pyinstCheckCmd)

	pyinstCmd.PersistentFlags().BoolVar(&jsonFormat, "json", false, "Output as JSON")
}

func runPyinstCheck(_ *cobra.Command, args []string) {
	path := args[0]
	name := filepath.Base(path)

	isPyInst, _ := pyinst.IsPyInstaller(path)
	isZipApp, _ := zipapp.IsZipAppBinary(path)

	if jsonFormat {
		fmt.Printf(`{"path":%q,"is_pyinstaller":%v,"is_zipapp":%v}`, path, isPyInst, isZipApp)
		fmt.Println()
		return
	}

	if isPyInst {
		fmt.Printf("%s: PyInstaller executable\n", name)
	} else if isZipApp {
		fmt.Printf("%s: Python zipapp\n", name)
	} else {
		fmt.Printf("%s: not a recognized Python executable\n", name)
	}
}

func runPyinstInfo(_ *cobra.Command, args []string) {
	path := args[0]

	isPyInst, _ := pyinst.IsPyInstaller(path)
	if isPyInst {
		showPyInstInfo(path)
		return
	}

	isZipApp, _ := zipapp.IsZipAppBinary(path)
	if isZipApp {
		showZipAppInfo(path)
		return
	}

	fmt.Printf("%s is not a recognized Python executable.\n", filepath.Base(path))
	os.Exit(1)
}

func showPyInstInfo(path string) {
	result, err := pyinst.Analyze(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("File:          %s\n", result.Name)
	fmt.Printf("Size:          %s\n", pyinstFmtSize(result.Size))
	fmt.Printf("Type:          PyInstaller %s\n", result.InstallerVer)
	fmt.Printf("Python:        %s\n", result.PyVersion)
	if result.PyLibName != "" {
		fmt.Printf("Python Lib:    %s\n", result.PyLibName)
	}
	fmt.Printf("Entries:       %d\n", result.EntryCount)
	fmt.Printf("Overlay:       0x%X\n", result.OverlayPos)

	if len(result.MainScripts) > 0 {
		fmt.Printf("Main Scripts:  %s\n", strings.Join(result.MainScripts, ", "))
	}

	if len(result.Entries) > 0 {
		fmt.Println()
		fmt.Printf("%-4s %-8s %-40s %10s %10s %s\n", "#", "TYPE", "NAME", "COMPRESSED", "SIZE", "")
		fmt.Println(strings.Repeat("-", 90))

		for i, e := range result.Entries {
			flag := ""
			if e.IsCompressed {
				flag = "[zlib]"
			}
			fmt.Printf("%-4d %-8s %-40s %10s %10s %s\n",
				i+1, e.TypeDesc, pyinstTrunc(e.Name, 40),
				pyinstFmtSize(int64(e.CompressedSize)), pyinstFmtSize(int64(e.UncompressedSize)), flag)
		}
	}
}

func showZipAppInfo(path string) {
	result, err := zipapp.Analyze(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if jsonFormat {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("File:          %s\n", result.Name)
	fmt.Printf("Size:          %s\n", pyinstFmtSize(result.Size))
	fmt.Printf("Type:          Python zipapp")
	if result.HasPEStub {
		fmt.Print(" (PE stub)")
	}
	if result.HasShebang {
		fmt.Printf(" (shebang: %s)", result.Shebang)
	}
	fmt.Println()
	fmt.Printf("ZIP Offset:    0x%X\n", result.ZipOffset)
	fmt.Printf("Files:         %d\n", result.FileCount)
	fmt.Printf("Total Size:    %s\n", pyinstFmtSize(result.TotalSize))

	if result.MainPy != "" {
		fmt.Printf("\n__main__.py:\n")
		for _, line := range strings.Split(result.MainPy, "\n") {
			fmt.Printf("  %s\n", line)
		}
	}

	if len(result.Files) > 0 {
		fmt.Printf("\nBundled Files:\n")
		for _, f := range result.Files {
			fmt.Printf("  %-50s %10s\n", f.Path, pyinstFmtSize(f.Size))
		}
	}
}

func runPyinstExtract(_ *cobra.Command, args []string) {
	path := args[0]
	outDir := output
	if outDir == "" {
		base := filepath.Base(path)
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		outDir = name + "_extracted"
	}

	isPyInst, _ := pyinst.IsPyInstaller(path)
	if isPyInst {
		fmt.Printf("Extracting PyInstaller binary: %s\n\n", filepath.Base(path))

		result, err := pyinst.Extract(path, outDir, verbose)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if jsonFormat {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("\nPython:        %s\n", result.PyVersion)
		fmt.Printf("Entries:       %d\n", result.EntryCount)
		fmt.Printf("Main Scripts:  %s\n", strings.Join(result.MainScripts, ", "))
		fmt.Printf("Output:        %s\n", outDir)
		return
	}

	isZipApp, _ := zipapp.IsZipAppBinary(path)
	if isZipApp {
		fmt.Printf("Extracting Python zipapp: %s\n\n", filepath.Base(path))

		result, err := zipapp.Extract(path, outDir, verbose)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if jsonFormat {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("\nFiles:   %d\n", result.FileCount)
		fmt.Printf("Output:  %s\n", outDir)
		return
	}

	fmt.Printf("%s is not a recognized Python executable.\n", filepath.Base(path))
	os.Exit(1)
}

func pyinstFmtSize(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024.0)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func pyinstTrunc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}
