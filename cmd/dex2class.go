/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"github.com/inovacc/unravel-oss/internal/boundedzip"
	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/dex2class"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler"

	"github.com/spf13/cobra"
)

var dex2classCmd = &cobra.Command{
	Use:   "dex2java <file.dex|file.apk>",
	Short: "Convert DEX bytecode to Java source (native-first, judge-assisted)",
	Long: `Full DEX → Java source pipeline using the native Go decompiler first:
  1. Parse DEX file (pkg/android/dex)
  2. Translate Dalvik bytecode to JVM .class files (pkg/android/dex2class)
  3. Decompile .class to Java source (pkg/java/decompiler)

If CFR and codex are installed, unravel can use them to cross-check and
judge the native output for better fidelity. No Java runtime is required
for the default native path.`,
	Args: cobra.ExactArgs(1),
	Run:  runDex2Java,
}

func init() {
	androidStaticCmd.AddCommand(dex2classCmd)
}

func runDex2Java(_ *cobra.Command, args []string) {
	path := args[0]

	// Parse DEX files from APK
	parseResult, err := dex.ScanAPK(path)
	if err != nil {
		fmt.Printf("Error parsing DEX: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d DEX files, %d classes, %d methods\n",
		len(parseResult.DexFiles), parseResult.TotalClasses, parseResult.TotalMethods)

	// Limit memory: aggressive GC + 2GB soft limit to prevent OOM
	debug.SetGCPercent(20)                       // GC at 20% growth instead of default 100%
	debug.SetMemoryLimit(2 * 1024 * 1024 * 1024) // 2GB soft limit

	translator := &dex2class.Translator{Verbose: verbose}
	hybrid := decompiler.NewHybridDecompiler()

	totalClasses := 0
	totalDecompiled := 0
	totalErrors := 0

	for _, df := range parseResult.DexFiles {
		rawDEX, err := readDEXBytes(path, df.Name)
		if err != nil {
			fmt.Printf("  [%s] Error reading: %v\n", df.Name, err)
			continue
		}

		// Stream: translate + decompile + write one class at a time.
		// Never holds more than one .class in memory.
		dexClasses := 0
		errs, err := translator.TranslateStreaming(&df, rawDEX, func(cf *dex2class.ClassOutput) error {
			dexClasses++
			totalClasses++

			if len(cf.Data) == 0 {
				return nil
			}

			// Skip decompilation if no output dir — just count
			if output == "" {
				cf.Data = nil
				totalDecompiled++
				return nil
			}

			source, derr := hybrid.DecompileBytes(cf.Data)
			cf.Data = nil

			// Aggressively return memory to OS every 200 classes.
			// The decompiler pipeline creates large ASTs per class that
			// Go's GC retains until explicitly freed.
			if totalClasses%200 == 0 {
				runtime.GC()
				debug.FreeOSMemory()
			}

			if derr != nil {
				if verbose {
					fmt.Printf("    FAIL %s: %v\n", cf.ClassName, derr)
				}
				totalErrors++
				return nil
			}

			totalDecompiled++

			javaPath := filepath.Join(output, cf.ClassName+".java")
			if merr := os.MkdirAll(filepath.Dir(javaPath), 0o755); merr == nil {
				_ = os.WriteFile(javaPath, []byte(source), 0o644)
			}

			return nil
		})
		rawDEX = nil // release DEX bytes

		if err != nil {
			fmt.Printf("  [%s] Error: %v\n", df.Name, err)
			continue
		}

		totalErrors += len(errs)
		fmt.Printf("  [%s] %d classes (%d errors)\n", df.Name, dexClasses, len(errs))
	}

	fmt.Printf("\nPipeline: %d classes translated, %d decompiled to Java, %d errors\n",
		totalClasses, totalDecompiled, totalErrors)

	if output != "" {
		fmt.Printf("Java sources written to %s\n", output)
	}
}

func readDEXBytes(apkOrDexPath, dexName string) ([]byte, error) {
	if filepath.Ext(apkOrDexPath) == ".dex" {
		return os.ReadFile(apkOrDexPath)
	}
	return readZipEntry(apkOrDexPath, dexName)
}

func readZipEntry(zipPath, entryName string) ([]byte, error) {
	zr, err := boundedzip.OpenReader(zipPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if f.Name == entryName {
			return zr.ReadEntry(f)
		}
	}
	return nil, fmt.Errorf("entry %q not found in %s", entryName, zipPath)
}
