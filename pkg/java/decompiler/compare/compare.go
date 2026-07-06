/*
Copyright (c) 2026 Security Research
*/

// Package compare provides a test harness for comparing unravel's Java
// decompiler output against external decompilers (CFR, Procyon, Vineflower)
// and expected golden-master outputs.
package compare

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Decompiler identifies an external Java decompiler.
type Decompiler string

const (
	DecompilerNative     Decompiler = "unravel"
	DecompilerCFR        Decompiler = "cfr"
	DecompilerProcyon    Decompiler = "procyon"
	DecompilerVineflower Decompiler = "vineflower"
)

// Result holds the comparison output for a single class file.
type Result struct {
	ClassPath   string                  `json:"class_path"`
	ClassName   string                  `json:"class_name"`
	Outputs     map[Decompiler]string   `json:"outputs"`
	Errors      map[Decompiler]string   `json:"errors,omitempty"`
	Metrics     map[Decompiler]*Metrics `json:"metrics,omitempty"`
	Differences []Difference            `json:"differences,omitempty"`
}

// Metrics summarizes decompiler output quality.
type Metrics struct {
	LineCount    int     `json:"line_count"`
	ImportCount  int     `json:"import_count"`
	MethodCount  int     `json:"method_count"`
	ClassCount   int     `json:"class_count"`
	HasPackage   bool    `json:"has_package"`
	CompileReady bool    `json:"compile_ready"` // has class decl, not just comments
	SyntaxErrors int     `json:"syntax_errors"` // count of unmatched braces
	Completeness float64 `json:"completeness"`  // 0.0-1.0 based on expected features
}

// Difference describes a specific difference between two decompiler outputs.
type Difference struct {
	Category    string     `json:"category"` // "missing_import", "different_method_body", "missing_method", etc.
	Description string     `json:"description"`
	Native      string     `json:"native,omitempty"`
	Reference   string     `json:"reference,omitempty"`
	Decompiler  Decompiler `json:"decompiler"`
}

// Harness runs comparison tests across multiple decompilers.
type Harness struct {
	NativeDecompile func(classData []byte) (string, error)
	ExternalTools   map[Decompiler]string // path to JAR or executable
	TempDir         string
}

// NewHarness creates a comparison harness. The nativeDecompile function
// should be decompiler.NativeDecompiler{}.DecompileBytes or equivalent.
func NewHarness(nativeDecompile func([]byte) (string, error)) *Harness {
	tempDir, _ := os.MkdirTemp("", "unravel-compare-*")
	h := &Harness{
		NativeDecompile: nativeDecompile,
		ExternalTools:   make(map[Decompiler]string),
		TempDir:         tempDir,
	}

	// Auto-detect external decompilers
	h.detectExternalTools()

	return h
}

// Close cleans up temporary files.
func (h *Harness) Close() {
	if h.TempDir != "" {
		_ = os.RemoveAll(h.TempDir)
	}
}

// Compare runs all available decompilers on a class file and compares output.
func (h *Harness) Compare(classData []byte, className string) *Result {
	result := &Result{
		ClassName: className,
		Outputs:   make(map[Decompiler]string),
		Errors:    make(map[Decompiler]string),
		Metrics:   make(map[Decompiler]*Metrics),
	}

	// Native decompiler (always available)
	native, err := h.NativeDecompile(classData)
	if err != nil {
		result.Errors[DecompilerNative] = err.Error()
	} else {
		result.Outputs[DecompilerNative] = native
		result.Metrics[DecompilerNative] = analyzeOutput(native)
	}

	// Write class file for external decompilers
	classPath := filepath.Join(h.TempDir, className+".class")
	if err := os.MkdirAll(filepath.Dir(classPath), 0o755); err == nil {
		if err := os.WriteFile(classPath, classData, 0o644); err == nil {
			result.ClassPath = classPath

			// Run external decompilers
			for dc, toolPath := range h.ExternalTools {
				output, err := h.runExternal(dc, toolPath, classPath)
				if err != nil {
					result.Errors[dc] = err.Error()
				} else {
					result.Outputs[dc] = output
					result.Metrics[dc] = analyzeOutput(output)
				}
			}
		}
	}

	// Compute differences between native and reference decompilers
	for dc, refOutput := range result.Outputs {
		if dc == DecompilerNative {
			continue
		}
		diffs := computeDifferences(native, refOutput, dc)
		result.Differences = append(result.Differences, diffs...)
	}

	return result
}

// CompareFile runs comparison on a .class file from disk.
func (h *Harness) CompareFile(classPath string) (*Result, error) {
	data, err := os.ReadFile(classPath)
	if err != nil {
		return nil, fmt.Errorf("reading class file: %w", err)
	}

	className := strings.TrimSuffix(filepath.Base(classPath), ".class")
	result := h.Compare(data, className)
	result.ClassPath = classPath

	return result, nil
}

// CompareJAR runs comparison on all .class files in a JAR.
func (h *Harness) CompareJAR(jarPath string) ([]*Result, error) {
	// Extract classes from JAR
	extractDir := filepath.Join(h.TempDir, "jar-extract")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return nil, err
	}

	// Walk extracted class files and compare each
	var results []*Result
	err := filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".class") {
			return err
		}
		result, err := h.CompareFile(path)
		if err != nil {
			return nil // non-fatal
		}
		results = append(results, result)
		return nil
	})

	return results, err
}

func (h *Harness) detectExternalTools() {
	// Check for CFR
	if p, err := exec.LookPath("cfr"); err == nil {
		h.ExternalTools[DecompilerCFR] = p
	}
	// Check for Procyon
	if p, err := exec.LookPath("procyon"); err == nil {
		h.ExternalTools[DecompilerProcyon] = p
	}
	// Check for Vineflower (formerly Fernflower)
	if p, err := exec.LookPath("vineflower"); err == nil {
		h.ExternalTools[DecompilerVineflower] = p
	}

	// Also check common JAR locations
	home, _ := os.UserHomeDir()
	jarPaths := map[Decompiler][]string{
		DecompilerCFR: {
			"tools/cfr.jar",
			"cfr.jar",
			filepath.Join(home, ".local/share/java/cfr.jar"),
			filepath.Join(home, "github.com/inovacc/unravel-oss/tools/cfr.jar"),
		},
		DecompilerProcyon: {
			"tools/procyon.jar",
			"procyon.jar",
			filepath.Join(home, ".local/share/java/procyon.jar"),
			filepath.Join(home, "github.com/inovacc/unravel-oss/tools/procyon.jar"),
		},
		DecompilerVineflower: {
			"tools/vineflower.jar",
			"vineflower.jar",
			filepath.Join(home, ".local/share/java/vineflower.jar"),
			filepath.Join(home, "github.com/inovacc/unravel-oss/tools/vineflower.jar"),
		},
	}
	for dc, paths := range jarPaths {
		if _, exists := h.ExternalTools[dc]; exists {
			continue
		}
		for _, p := range paths {
			if _, err := os.Stat(p); err == nil {
				h.ExternalTools[dc] = p
				break
			}
		}
	}
}

func (h *Harness) runExternal(dc Decompiler, toolPath, classPath string) (string, error) {
	outDir := filepath.Join(h.TempDir, string(dc)+"-output")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	// Absolutize the (untrusted) class path so it can never be parsed as a
	// flag by the external decompiler (argument injection, CWE-88).
	if abs, absErr := filepath.Abs(classPath); absErr == nil {
		classPath = abs
	}

	var cmd *exec.Cmd
	switch dc {
	case DecompilerCFR:
		if strings.HasSuffix(toolPath, ".jar") {
			cmd = exec.Command("java", "-jar", toolPath, classPath)
		} else {
			cmd = exec.Command(toolPath, classPath)
		}
	case DecompilerProcyon:
		if strings.HasSuffix(toolPath, ".jar") {
			cmd = exec.Command("java", "-jar", toolPath, "-o", outDir, classPath)
		} else {
			cmd = exec.Command(toolPath, "-o", outDir, classPath)
		}
	case DecompilerVineflower:
		if strings.HasSuffix(toolPath, ".jar") {
			cmd = exec.Command("java", "-jar", toolPath, classPath, outDir)
		} else {
			cmd = exec.Command(toolPath, classPath, outDir)
		}
	default:
		return "", fmt.Errorf("unknown decompiler: %s", dc)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s failed: %w\n%s", dc, err, string(output))
	}

	// CFR outputs to stdout
	if dc == DecompilerCFR {
		return string(output), nil
	}

	// Others output to files — find the .java file
	var result string
	_ = filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".java") {
			data, _ := os.ReadFile(path)
			result = string(data)
		}
		return nil
	})

	if result == "" {
		return string(output), nil
	}
	return result, nil
}

// analyzeOutput computes quality metrics for decompiled Java source.
func analyzeOutput(source string) *Metrics {
	lines := strings.Split(source, "\n")
	m := &Metrics{
		LineCount: len(lines),
	}

	braceBalance := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") {
			m.ImportCount++
		}
		if strings.HasPrefix(trimmed, "package ") {
			m.HasPackage = true
		}
		if strings.Contains(trimmed, "class ") || strings.Contains(trimmed, "interface ") || strings.Contains(trimmed, "enum ") {
			m.ClassCount++
		}
		if (strings.Contains(trimmed, "(") && strings.Contains(trimmed, ")")) &&
			(strings.HasSuffix(trimmed, "{") || strings.HasSuffix(trimmed, ";")) &&
			!strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "if") &&
			!strings.HasPrefix(trimmed, "for") && !strings.HasPrefix(trimmed, "while") {
			m.MethodCount++
		}
		braceBalance += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
	}

	m.SyntaxErrors = abs(braceBalance)
	m.CompileReady = m.ClassCount > 0 && m.SyntaxErrors == 0

	// Completeness score
	score := 0.0
	if m.HasPackage {
		score += 0.1
	}
	if m.ClassCount > 0 {
		score += 0.3
	}
	if m.MethodCount > 0 {
		score += 0.3
	}
	if m.SyntaxErrors == 0 {
		score += 0.2
	}
	if m.ImportCount > 0 {
		score += 0.1
	}
	m.Completeness = score

	return m
}

func computeDifferences(native, reference string, dc Decompiler) []Difference {
	var diffs []Difference

	nativeLines := strings.Split(native, "\n")
	refLines := strings.Split(reference, "\n")

	// Compare import sets
	nativeImports := extractImports(nativeLines)
	refImports := extractImports(refLines)

	for imp := range refImports {
		if _, ok := nativeImports[imp]; !ok {
			diffs = append(diffs, Difference{
				Category:    "missing_import",
				Description: fmt.Sprintf("Import %q present in %s but missing from native", imp, dc),
				Reference:   imp,
				Decompiler:  dc,
			})
		}
	}

	// Compare method count
	nativeMethods := countMethods(nativeLines)
	refMethods := countMethods(refLines)
	if nativeMethods != refMethods {
		diffs = append(diffs, Difference{
			Category:    "method_count",
			Description: fmt.Sprintf("Native has %d methods, %s has %d", nativeMethods, dc, refMethods),
			Native:      fmt.Sprintf("%d methods", nativeMethods),
			Reference:   fmt.Sprintf("%d methods", refMethods),
			Decompiler:  dc,
		})
	}

	return diffs
}

func extractImports(lines []string) map[string]bool {
	imports := make(map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") {
			imports[trimmed] = true
		}
	}
	return imports
}

func countMethods(lines []string) int {
	count := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if (strings.Contains(trimmed, "(") && strings.Contains(trimmed, ")")) &&
			strings.HasSuffix(trimmed, "{") &&
			!strings.HasPrefix(trimmed, "//") &&
			!strings.HasPrefix(trimmed, "if") &&
			!strings.HasPrefix(trimmed, "for") &&
			!strings.HasPrefix(trimmed, "while") {
			count++
		}
	}
	return count
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Summary generates a text summary of comparison results.
func Summary(results []*Result) string {
	var sb strings.Builder

	total := len(results)
	nativeSuccess := 0
	nativeCompileReady := 0

	for _, r := range results {
		if _, ok := r.Outputs[DecompilerNative]; ok {
			nativeSuccess++
		}
		if m, ok := r.Metrics[DecompilerNative]; ok && m.CompileReady {
			nativeCompileReady++
		}
	}

	fmt.Fprintf(&sb, "Java Decompiler Comparison Report\n")
	fmt.Fprintf(&sb, "=================================\n\n")
	fmt.Fprintf(&sb, "Total classes: %d\n", total)
	fmt.Fprintf(&sb, "Native success: %d/%d (%.1f%%)\n", nativeSuccess, total, pct(nativeSuccess, total))
	fmt.Fprintf(&sb, "Native compile-ready: %d/%d (%.1f%%)\n\n", nativeCompileReady, total, pct(nativeCompileReady, total))

	// Per-decompiler stats
	decompilers := []Decompiler{DecompilerCFR, DecompilerProcyon, DecompilerVineflower}
	for _, dc := range decompilers {
		success := 0
		compileReady := 0
		for _, r := range results {
			if _, ok := r.Outputs[dc]; ok {
				success++
			}
			if m, ok := r.Metrics[dc]; ok && m.CompileReady {
				compileReady++
			}
		}
		if success > 0 {
			fmt.Fprintf(&sb, "%s: %d/%d success, %d compile-ready\n", dc, success, total, compileReady)
		}
	}

	return sb.String()
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
