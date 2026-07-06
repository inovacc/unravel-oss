/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	out "github.com/inovacc/unravel-oss/cmd/output"
	"github.com/inovacc/unravel-oss/internal/ai"
	"github.com/inovacc/unravel-oss/pkg/java/archive"
	javabeautify "github.com/inovacc/unravel-oss/pkg/java/beautify"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/compare"

	"github.com/spf13/cobra"
)

var (
	javaJSONFormat   bool
	javaOutputDir    string
	javaCFROnly      bool
	javaBeautifyFlag bool
	javaNoAI         bool
)

var javaCmd = &cobra.Command{
	Use:   "java",
	Short: "Java archive and class file analysis",
	Long: `Parse, extract, decompile, and analyze Java archives and class files.

Supported formats:
  .class - Compiled Java class file (CAFEBABE magic)
  .jar   - Java Archive (ZIP with classes + resources)
  .war   - Web Application Archive (servlet container deployment)
  .ear   - Enterprise Application Archive (EJB/WAR container)

Subcommands:
  info      - Display metadata for class files or Java archives
  decompile - Decompile class files to Java source (pure Go, no Java required)
  extract   - Extract archive contents to disk
  manifest  - Show MANIFEST.MF and deployment descriptors`,
}

var javaInfoCmd = &cobra.Command{
	Use:   "info <file>",
	Short: "Display Java class or archive metadata",
	Args:  cobra.ExactArgs(1),
	Run:   runJavaInfo,
}

var javaDecompileCmd = &cobra.Command{
	Use:   "decompile <file>",
	Short: "Decompile Java class files to source",
	Args:  cobra.ExactArgs(1),
	Run:   runJavaDecompile,
}

var javaExtractCmd = &cobra.Command{
	Use:   "extract <file>",
	Short: "Extract Java archive contents to disk",
	Args:  cobra.ExactArgs(1),
	Run:   runJavaExtract,
}

var javaManifestCmd = &cobra.Command{
	Use:   "manifest <file>",
	Short: "Show MANIFEST.MF and deployment descriptors",
	Args:  cobra.ExactArgs(1),
	Run:   runJavaManifest,
}

// javaBeautifyCmd re-runs only AI beautification on a pre-decompiled tree
// (06-04 Task 1, D-03 + D-15). Mirrors `unravel dotnet decompile --no-ai`
// pattern but operates on an already-decompiled raw/ tree.
var javaBeautifyCmd = &cobra.Command{
	Use:   "beautify <decompiled-tree-dir>",
	Short: "Re-run AI beautification on an existing decompiled Java tree",
	Long: `Walk a pre-existing decompiled Java tree (raw/ output of a prior
'unravel java decompile' run) and emit a parallel beautified/ tree plus
manifest.json. No decompile step is performed.

Path-traversal sanitisation rejects '..' segments at the CLI boundary
(T-06-01). Use --no-ai to produce raw-only output (sanity-check mode).`,
	Args: cobra.ExactArgs(1),
	RunE: runJavaBeautifySubcommand,
}

var javaCompareCmd = &cobra.Command{
	Use:   "compare <file.class|file.jar>",
	Short: "Compare native decompiler output against external decompilers (CFR, Procyon, Vineflower)",
	Long: `Decompile .class files with unravel's native Go decompiler and compare
output against external Java decompilers when available.

Reports metrics (line count, import count, method count, completeness)
and differences (missing imports, method count mismatches) per class.

External decompilers are auto-detected from PATH or common install locations.
If none are found, only native output metrics are reported.`,
	Args: cobra.ExactArgs(1),
	Run:  runJavaCompare,
}

func init() {
	rootCmd.AddCommand(javaCmd)
	javaCmd.AddCommand(javaInfoCmd)
	javaCmd.AddCommand(javaDecompileCmd)
	javaCmd.AddCommand(javaExtractCmd)
	javaCmd.AddCommand(javaManifestCmd)
	javaCmd.AddCommand(javaCompareCmd)
	javaCmd.AddCommand(javaBeautifyCmd)

	javaCmd.PersistentFlags().BoolVar(&javaJSONFormat, "json", false, "Output as JSON")
	javaDecompileCmd.Flags().StringVarP(&javaOutputDir, "output", "o", "", "Output directory")
	javaDecompileCmd.Flags().BoolVar(&javaCFROnly, "cfr", false, "Use CFR decompiler only (requires Java)")
	javaDecompileCmd.Flags().BoolVar(&javaBeautifyFlag, "beautify", false, "Run AI beautification on decompiled output (D-03)")
	javaDecompileCmd.Flags().BoolVar(&javaNoAI, "no-ai", false, "Skip AI beautification and the external LLM judge (deterministic raw tree only)")
	javaExtractCmd.Flags().StringVarP(&javaOutputDir, "output", "o", "", "Output directory")
	javaCompareCmd.Flags().StringVarP(&javaOutputDir, "output", "o", "", "Output directory for golden files")
	javaBeautifyCmd.Flags().StringVarP(&javaOutputDir, "output", "o", "", "Output directory")
	javaBeautifyCmd.Flags().BoolVar(&javaNoAI, "no-ai", false, "Skip AI beautification (raw tree only)")
}

// sanitizeJavaCmdPath rejects path-traversal segments at the Cobra
// boundary (T-06-01 / D-19). Mirrors sanitizeDotnetPath in dotnet.go.
// mustExist=true requires the input path to exist; outputs are mkdir'd.
func sanitizeJavaCmdPath(p string, mustExist bool) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	cleaned := filepath.Clean(p)
	for _, seg := range strings.Split(filepath.ToSlash(cleaned), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path contains '..' segment: %q", p)
		}
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if mustExist {
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("stat path: %w", err)
		}
	}
	return abs, nil
}

// javaCmdAIBeautifier adapts an *ai.Client to javabeautify.Beautifier.
type javaCmdAIBeautifier struct {
	c *ai.Client
}

func (a *javaCmdAIBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	resp, err := a.c.Analyze(ctx, prompt, input)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}

// runBeautifyOrchestrator constructs an Orchestrator from sanitised paths
// + optional AI client and walks the decompiled tree at rawTreeDir,
// writing beautified/<jar>/... + manifest.json under outAbs. Shared by
// `java decompile --beautify` and `java beautify` subcommands.
func runBeautifyOrchestrator(ctx context.Context, rawTreeDir, outAbs string, aiEnabled bool) (*javabeautify.BeautifyReport, error) {
	dr := &javabeautify.DecompileResult{DecompilerVersion: "unravel-java-decompiler"}

	// Each direct child of rawTreeDir is treated as a JarOutput entry.
	// Honors D-21: this CLI seam owns the local DecompileResult shape.
	if entries, err := os.ReadDir(rawTreeDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			jarDir := filepath.Join(rawTreeDir, e.Name())
			fileCount := 0
			_ = filepath.WalkDir(jarDir, func(p string, d os.DirEntry, werr error) error {
				if werr != nil || d.IsDir() {
					return nil
				}
				if strings.EqualFold(filepath.Ext(p), ".java") {
					fileCount++
				}
				return nil
			})
			dr.Jars = append(dr.Jars, javabeautify.JarOutput{
				Name:              e.Name(),
				Path:              jarDir,
				OutDir:            jarDir,
				FileCount:         fileCount,
				DecompilerVersion: "unravel-java-decompiler",
				Decompiled:        true,
			})
		}
	}

	bopts := javabeautify.BeautifyOptions{AIEnabled: aiEnabled}
	var beautifier javabeautify.Beautifier
	if aiEnabled {
		client, cerr := ai.NewClient()
		if cerr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: AI disabled (%v); writing raw-only manifest\n", cerr)
			bopts.AIEnabled = false
		} else {
			beautifier = &javaCmdAIBeautifier{c: client}
		}
	}

	orch := javabeautify.NewOrchestrator(beautifier, bopts)
	return orch.Run(ctx, dr, javabeautify.RunOptions{
		Output: outAbs,
		Input:  rawTreeDir,
		Mode:   "beautify",
	})
}

// runJavaBeautifySubcommand handles `unravel java beautify <existing-decompiled-tree>`.
func runJavaBeautifySubcommand(cmd *cobra.Command, args []string) error {
	inAbs, err := sanitizeJavaCmdPath(args[0], true)
	if err != nil {
		return fmt.Errorf("input path: %w", err)
	}

	outDir := javaOutputDir
	if outDir == "" {
		outDir = inAbs + "-beautified"
	}
	outAbs, err := sanitizeJavaCmdPath(outDir, false)
	if err != nil {
		return fmt.Errorf("output path: %w", err)
	}

	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return fmt.Errorf("mkdir output: %w", err)
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// `unravel java beautify <dir>`: <dir> is treated as the raw tree.
	report, err := runBeautifyOrchestrator(ctx, inAbs, outAbs, !javaNoAI)
	if err != nil {
		return fmt.Errorf("beautify: %w", err)
	}

	if javaJSONFormat {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	out.PrintJavaBeautifyReport(report, os.Stdout)
	return nil
}

func isClassFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".class")
}

func isJavaArchive(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war" || ext == ".ear"
}

// runJavaDisplay implements the shared structure of the java info/manifest
// subcommands: render a .class file directly (identical for both commands), or
// extract an archive and hand it to archiveRender for the command-specific
// display projection + printer.
func runJavaDisplay(path string, archiveRender func(info *archive.ArchiveInfo)) {
	if isClassFile(path) {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}

		cf, err := classfile.Parse(data)
		if err != nil {
			fmt.Printf("Error parsing class file: %v\n", err)
			os.Exit(1)
		}

		display := classFileToDisplay(cf)

		if javaJSONFormat {
			j, _ := json.MarshalIndent(display, "", "  ")
			fmt.Println(string(j))

			return
		}

		out.PrintJavaClassInfo(display)

		return
	}

	if isJavaArchive(path) {
		ctx := context.Background()
		a := archive.New(slog.Default())

		info, err := a.Extract(ctx, path)
		if err != nil {
			fmt.Printf("Error analyzing archive: %v\n", err)
			os.Exit(1)
		}

		defer func() { _ = info.Cleanup() }()

		archiveRender(info)

		return
	}

	fmt.Printf("Error: unsupported file type: %s\n", filepath.Ext(path))
	fmt.Println("Supported formats: .class, .jar, .war, .ear")
	os.Exit(1)
}

func runJavaInfo(_ *cobra.Command, args []string) {
	runJavaDisplay(args[0], func(info *archive.ArchiveInfo) {
		display := archiveInfoToDisplay(info)

		if javaJSONFormat {
			j, _ := json.MarshalIndent(display, "", "  ")
			fmt.Println(string(j))

			return
		}

		out.PrintJavaArchiveInfo(display)
	})
}

func runJavaDecompile(_ *cobra.Command, args []string) {
	path := args[0]

	// Create hybrid decompiler (native + CFR fallback)
	hybrid := decompiler.NewHybridDecompiler()
	hybrid.FallbackOnly = javaCFROnly

	// The source judge shells out to an external LLM CLI (codex) per indecisive
	// class, so it is an AI call: --no-ai must disable it to keep raw-only runs
	// fast and deterministic (otherwise a whole-JAR decompile stalls for minutes
	// on per-class judge round-trips).
	if javaNoAI {
		hybrid.Judge = nil
	}

	if javaCFROnly && !hybrid.HasFallback() {
		fmt.Println("Error: --cfr requires Java runtime and cfr.jar")
		fmt.Println("Install Java and place cfr.jar in tools/ or the unravel tools directory")
		fmt.Println("(Windows: %LOCALAPPDATA%\\Unravel\\tools\\; POSIX: ~/unravel/tools/)")
		os.Exit(1)
	}

	if hybrid.HasFallback() {
		fmt.Printf("Using: native + CFR fallback (%s)\n", hybrid.CFRPath)
	}
	if hybrid.Judge != nil {
		fmt.Println("Judge: codex")
	}

	if isClassFile(path) {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("Error reading file: %v\n", err)
			os.Exit(1)
		}

		source, err := hybrid.DecompileBytes(data)
		if err != nil {
			fmt.Printf("Error decompiling class: %v\n", err)
			os.Exit(1)
		}

		if javaOutputDir != "" {
			baseName := strings.TrimSuffix(filepath.Base(path), ".class") + ".java"
			outPath := filepath.Join(javaOutputDir, baseName)

			if err := os.MkdirAll(javaOutputDir, 0o755); err != nil {
				fmt.Printf("Error creating output directory: %v\n", err)
				os.Exit(1)
			}

			if err := os.WriteFile(outPath, []byte(source), 0o644); err != nil {
				fmt.Printf("Error writing file: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Decompiled: %s -> %s\n", filepath.Base(path), outPath)

			return
		}

		fmt.Println(source)

		return
	}

	if isJavaArchive(path) {
		ctx := context.Background()
		a := archive.New(slog.Default())

		info, err := a.Extract(ctx, path)
		if err != nil {
			fmt.Printf("Error extracting archive: %v\n", err)
			os.Exit(1)
		}

		defer func() { _ = info.Cleanup() }()

		outDir := javaOutputDir
		if outDir == "" {
			baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			outDir = baseName + "-decompiled"
		}

		if err := os.MkdirAll(outDir, 0o755); err != nil {
			fmt.Printf("Error creating output directory: %v\n", err)
			os.Exit(1)
		}

		// Try whole-JAR decompilation with CFR if available and --cfr flag
		if javaCFROnly && hybrid.HasFallback() {
			if err := hybrid.DecompileJAR(path, outDir); err != nil {
				fmt.Printf("CFR JAR decompilation failed: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Decompiled with CFR to: %s\n", outDir)

			return
		}

		var decompiled, errCount int
		var errorDetails []string

		for _, classRel := range info.ClassFiles {
			classPath := filepath.Join(info.ExtractDir, filepath.FromSlash(classRel))

			data, err := os.ReadFile(classPath)
			if err != nil {
				errCount++
				errorDetails = append(errorDetails, fmt.Sprintf("%s: %v", classRel, err))

				continue
			}

			source, err := hybrid.DecompileBytes(data)
			if err != nil {
				errCount++
				errorDetails = append(errorDetails, fmt.Sprintf("%s: %v", classRel, err))

				continue
			}

			javaPath := strings.TrimSuffix(classRel, ".class") + ".java"
			outPath := filepath.Join(outDir, filepath.FromSlash(javaPath))

			if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
				errCount++

				continue
			}

			if err := os.WriteFile(outPath, []byte(source), 0o644); err != nil {
				errCount++

				continue
			}

			decompiled++
		}

		summary := &out.JavaDecompileSummary{
			TotalClasses: len(info.ClassFiles),
			Decompiled:   decompiled,
			Errors:       errCount,
			OutputDir:    outDir,
			ErrorDetails: errorDetails,
		}

		if javaJSONFormat {
			j, _ := json.MarshalIndent(summary, "", "  ")
			fmt.Println(string(j))

			return
		}

		out.PrintJavaDecompileSummary(summary)

		// 06-04 Task 1 / D-03: when --beautify is set, chain orchestrator.
		// Output layout: <outDir>/raw/<jar>/  (already produced) +
		// <outDir>/beautified/<jar>/ via the orchestrator.
		if javaBeautifyFlag {
			beautifyOut := filepath.Join(filepath.Dir(outDir), filepath.Base(outDir)+"-beautify-out")
			if absOut, sanErr := sanitizeJavaCmdPath(beautifyOut, false); sanErr == nil {
				_ = os.MkdirAll(absOut, 0o755)
				ctx := context.Background()
				if rep, berr := runBeautifyOrchestrator(ctx, outDir, absOut, !javaNoAI); berr != nil {
					_, _ = fmt.Fprintf(os.Stderr, "beautify: %v\n", berr)
				} else {
					out.PrintJavaBeautifyReport(rep, os.Stdout)
				}
			}
		}

		return
	}

	fmt.Printf("Error: unsupported file type: %s\n", filepath.Ext(path))
	fmt.Println("Supported formats: .class, .jar, .war, .ear")
	os.Exit(1)
}

func runJavaExtract(_ *cobra.Command, args []string) {
	path := args[0]

	if !isJavaArchive(path) {
		fmt.Printf("Error: unsupported file type: %s\n", filepath.Ext(path))
		fmt.Println("Supported formats: .jar, .war, .ear")
		os.Exit(1)
	}

	ctx := context.Background()
	a := archive.New(slog.Default())

	info, err := a.Extract(ctx, path)
	if err != nil {
		fmt.Printf("Error extracting archive: %v\n", err)
		os.Exit(1)
	}

	// Copy from temp to user-specified output dir
	outDir := javaOutputDir
	if outDir == "" {
		baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		outDir = baseName + "-extracted"
	}

	if err := copyDir(info.ExtractDir, outDir); err != nil {
		_ = info.Cleanup()
		fmt.Printf("Error copying to output directory: %v\n", err)
		os.Exit(1)
	}

	_ = info.Cleanup()

	display := archiveInfoToDisplay(info)
	display.Path = outDir

	if javaJSONFormat {
		j, _ := json.MarshalIndent(display, "", "  ")
		fmt.Println(string(j))

		return
	}

	fmt.Printf("Extracted %s to %s\n", info.Type.String(), outDir)
	fmt.Printf("  Classes: %d\n", display.ClassCount)
	fmt.Printf("  Java files: %d\n", display.JavaCount)
	fmt.Printf("  Nested JARs: %d\n", len(display.NestedJARs))
}

func runJavaManifest(_ *cobra.Command, args []string) {
	runJavaDisplay(args[0], func(info *archive.ArchiveInfo) {
		display := manifestToDisplay(info)

		if javaJSONFormat {
			j, _ := json.MarshalIndent(display, "", "  ")
			fmt.Println(string(j))

			return
		}

		out.PrintJavaManifest(display)
	})
}

// classFileToDisplay converts a parsed classfile to display struct.
func classFileToDisplay(cf *classfile.ClassFile) *out.JavaClassDisplay {
	display := &out.JavaClassDisplay{
		ClassName:        cf.ClassNameDotted(),
		JavaVersion:      cf.JavaVersion(),
		AccessFlags:      cf.AccessFlags.ClassAccessString(),
		SuperClass:       strings.ReplaceAll(cf.SuperClassName(), "/", "."),
		FieldCount:       len(cf.Fields),
		MethodCount:      len(cf.Methods),
		SourceFile:       cf.SourceFile(),
		ConstantPoolSize: int(cf.ConstantPool.Count()),
	}

	for _, idx := range cf.Interfaces {
		name := strings.ReplaceAll(cf.ConstantPool.ClassName(idx), "/", ".")
		display.Interfaces = append(display.Interfaces, name)
	}

	return display
}

// archiveInfoToDisplay converts archive info to display struct.
func archiveInfoToDisplay(info *archive.ArchiveInfo) *out.JavaArchiveDisplay {
	display := &out.JavaArchiveDisplay{
		Type:       info.Type.String(),
		Path:       info.Path,
		ClassCount: len(info.ClassFiles),
		JavaCount:  len(info.JavaFiles),
		NestedJARs: info.NestedJARs,
		HasWebXML:  info.WebXML != nil,
		HasAppXML:  info.AppXML != nil,
		HasPOM:     info.POM != nil,
		SpringBoot: info.SpringConfig != nil,
	}

	if info.Manifest != nil {
		display.ManifestMainClass = info.Manifest.MainClass
		display.ManifestVersion = info.Manifest.ImplementationVersion
	}

	if info.POM != nil {
		for _, dep := range info.POM.Dependencies {
			display.Dependencies = append(display.Dependencies,
				fmt.Sprintf("%s:%s:%s", dep.GroupID, dep.ArtifactID, dep.Version))
		}
	}

	return display
}

// manifestToDisplay converts archive info to manifest display.
func manifestToDisplay(info *archive.ArchiveInfo) *out.JavaManifestDisplay {
	display := &out.JavaManifestDisplay{
		Entries: make(map[string]string),
	}

	if info.Manifest != nil {
		display.MainClass = info.Manifest.MainClass
		display.ClassPath = strings.Join(info.Manifest.ClassPath, " ")
		display.ManifestVersion = info.Manifest.ImplementationVersion

		for k, v := range info.Manifest.Entries {
			display.Entries[k] = v
		}
	}

	if info.WebXML != nil {
		wd := &out.WebXMLDisplay{}
		for _, s := range info.WebXML.Servlets {
			wd.Servlets = append(wd.Servlets, s.Name)
		}
		for _, f := range info.WebXML.Filters {
			wd.Filters = append(wd.Filters, f.Name)
		}
		for _, l := range info.WebXML.Listeners {
			wd.Listeners = append(wd.Listeners, l.Class)
		}
		display.WebXML = wd
	}

	if info.AppXML != nil {
		ad := &out.AppXMLDisplay{}
		for _, m := range info.AppXML.Modules {
			label := m.Type + ": " + m.URI
			if m.ContextRoot != "" {
				label += " (context: " + m.ContextRoot + ")"
			}
			ad.Modules = append(ad.Modules, label)
		}
		display.AppXML = ad
	}

	if info.POM != nil {
		pd := &out.POMDisplay{
			GroupID:    info.POM.GroupID,
			ArtifactID: info.POM.ArtifactID,
			Version:    info.POM.Version,
		}
		for _, dep := range info.POM.Dependencies {
			pd.Dependencies = append(pd.Dependencies,
				fmt.Sprintf("%s:%s:%s", dep.GroupID, dep.ArtifactID, dep.Version))
		}
		display.POM = pd
	}

	return display
}

// copyDir copies a directory tree from src to dst.
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(target, data, 0o644)
	})
}

func runJavaCompare(_ *cobra.Command, args []string) {
	path := args[0]

	native := &decompiler.NativeDecompiler{}
	h := compare.NewHarness(native.DecompileBytes)
	defer h.Close()

	// Report available decompilers
	fmt.Println("Available decompilers:")
	fmt.Println("  [native] unravel (always available)")
	for dc, toolPath := range h.ExternalTools {
		fmt.Printf("  [%s] %s\n", dc, toolPath)
	}
	if len(h.ExternalTools) == 0 {
		fmt.Println("  (no external decompilers found — install CFR, Procyon, or Vineflower for cross-comparison)")
	}
	fmt.Println()

	var results []*compare.Result

	if isClassFile(path) {
		// Single .class file
		result, err := h.CompareFile(path)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		results = append(results, result)
	} else if isJavaArchive(path) {
		// JAR/WAR/EAR — extract and compare all classes
		fmt.Printf("Extracting classes from %s...\n", filepath.Base(path))

		extractor := archive.New(slog.Default(), archive.WithNativeDecompiler())
		ai, err := extractor.Extract(context.Background(), path)
		if err != nil {
			fmt.Printf("Error extracting archive: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = ai.Cleanup() }()

		extractDir := ai.ExtractDir
		fmt.Printf("Found %d classes\n\n", len(ai.ClassFiles))

		// Compare each .class file
		err = filepath.Walk(extractDir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".class") {
				return err
			}
			result, err := h.CompareFile(p)
			if err != nil {
				if verbose {
					fmt.Printf("  SKIP %s: %v\n", filepath.Base(p), err)
				}
				return nil
			}
			results = append(results, result)
			return nil
		})
		if err != nil {
			fmt.Printf("Error walking classes: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Error: unsupported file type (expected .class, .jar, .war, or .ear)\n")
		os.Exit(1)
	}

	// Print results
	for _, r := range results {
		fmt.Printf("╭─ %s\n", r.ClassName)

		for dc, m := range r.Metrics {
			status := "✓"
			if m.SyntaxErrors > 0 {
				status = "✗"
			}
			fmt.Printf("│  %s %-12s lines=%-4d imports=%-3d methods=%-3d classes=%-2d completeness=%.0f%%\n",
				status, dc, m.LineCount, m.ImportCount, m.MethodCount, m.ClassCount, m.Completeness*100)
		}

		for dc, errMsg := range r.Errors {
			fmt.Printf("│  ✗ %-12s error: %s\n", dc, errMsg)
		}

		if len(r.Differences) > 0 {
			fmt.Println("│  Differences:")
			for _, d := range r.Differences {
				fmt.Printf("│    [%s] %s: %s\n", d.Decompiler, d.Category, d.Description)
			}
		}

		fmt.Println("╰─")
	}

	// Summary
	fmt.Println()
	fmt.Print(compare.Summary(results))

	// Write golden files if output dir specified
	if javaOutputDir != "" {
		goldenDir := filepath.Join(javaOutputDir, "golden")
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			fmt.Printf("Error creating output dir: %v\n", err)
			return
		}

		for _, r := range results {
			for dc, output := range r.Outputs {
				ext := ".java"
				if dc != compare.DecompilerNative {
					ext = "." + string(dc) + ".java"
				}
				outPath := filepath.Join(goldenDir, r.ClassName+ext)
				if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err == nil {
					_ = os.WriteFile(outPath, []byte(output), 0o644)
				}
			}
		}
		fmt.Printf("\nGolden files written to %s\n", goldenDir)
	}

	if javaJSONFormat {
		data, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(data))
	}
}
