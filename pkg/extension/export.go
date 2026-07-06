/*
Copyright © 2026 Security Research
*/
package extension

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// ExportResult holds the overall export outcome.
type ExportResult struct {
	OutputDir  string
	Total      int
	Exported   int
	Skipped    int
	Extensions []ExtensionInfo
	Browsers   []BrowserProfile
}

// ExportAllExtensions discovers, analyses, copies, beautifies, and reports on every extension.
func ExportAllExtensions(m *manifest.Manifest, filterBrowser, outputDir string, verbose bool) (*ExportResult, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	fmt.Println("Scanning browser extensions...")

	scanResult := ScanAllExtensions(m, filterBrowser, verbose)

	if scanResult.TotalExts == 0 {
		fmt.Println("No extensions found.")
		return &ExportResult{OutputDir: outputDir}, nil
	}

	fmt.Printf("Found %d extensions across %d browser profiles\n\n", scanResult.TotalExts, len(scanResult.Browsers))

	res := &ExportResult{
		OutputDir:  outputDir,
		Total:      scanResult.TotalExts,
		Browsers:   scanResult.Browsers,
		Extensions: scanResult.Extensions,
	}

	type workItem struct {
		idx  int
		info ExtensionInfo
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	sem := make(chan struct{}, runtime.NumCPU())

	for i, ext := range scanResult.Extensions {
		wg.Add(1)

		go func(w workItem) {
			defer wg.Done()

			sem <- struct{}{}

			defer func() { <-sem }()

			dirName := sanitizeName(w.info.Name, w.info.Browser)
			destDir := filepath.Join(outputDir, dirName)

			if err := os.MkdirAll(destDir, 0o755); err != nil {
				if verbose {
					fmt.Printf("  [SKIP] %s: mkdir: %v\n", w.info.Name, err)
				}

				mu.Lock()

				res.Skipped++

				mu.Unlock()

				return
			}

			if err := copyExtensionDir(w.info.Path, destDir); err != nil {
				if verbose {
					fmt.Printf("  [SKIP] %s: copy: %v\n", w.info.Name, err)
				}

				mu.Lock()

				res.Skipped++

				mu.Unlock()

				return
			}

			beautified := beautifyJSFiles(destDir, verbose)

			generateReport(&w.info, destDir, beautified)

			mu.Lock()

			res.Exported++

			mu.Unlock()

			if verbose {
				fmt.Printf("  [OK] %s (%s) -> %s\n", w.info.Name, w.info.Browser, dirName)
			}
		}(workItem{idx: i, info: ext})
	}

	wg.Wait()

	generateSummary(res, scanResult.RiskSummary)

	fmt.Printf("\nExport complete: %d/%d extensions exported to %s\n", res.Exported, res.Total, outputDir)

	if res.Skipped > 0 {
		fmt.Printf("Skipped: %d\n", res.Skipped)
	}

	return res, nil
}

// sanitizeName produces a filesystem-safe directory name from the extension name and browser.
func sanitizeName(name, browser string) string {
	re := regexp.MustCompile(`[<>:"/\\|?*&]+`)
	safe := re.ReplaceAllString(name, "_")

	// Collapse runs of underscores/spaces
	safe = regexp.MustCompile(`[_\s]+`).ReplaceAllString(safe, "_")
	safe = strings.Trim(safe, "_ ")

	if len(safe) > 80 {
		safe = safe[:80]
		safe = strings.TrimRight(safe, "_ ")
	}

	if safe == "" {
		safe = "unknown"
	}

	return fmt.Sprintf("%s_(%s)", safe, browser)
}

// copyExtensionDir recursively copies the extension version directory to destDir,
// skipping the _metadata subdirectory.
func copyExtensionDir(srcDir, destDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable
		}

		rel, _ := filepath.Rel(srcDir, path)

		// Skip _metadata directory
		if info.IsDir() && info.Name() == "_metadata" {
			return filepath.SkipDir
		}

		dest := filepath.Join(destDir, rel)

		if info.IsDir() {
			return os.MkdirAll(dest, 0o755)
		}

		return copyFile(path, dest)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}

	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, in)

	return err
}

// beautifyJSFiles walks destDir, beautifying .js and .mjs files in-place.
// Skips files larger than 5 MB or files that already appear formatted.
// Returns the count of files beautified.
func beautifyJSFiles(dir string, verbose bool) int {
	const maxSize = 5 * 1024 * 1024

	count := 0

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".js" && ext != ".mjs" {
			return nil
		}

		if info.Size() > maxSize {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		content := string(data)

		// Heuristic: if average line length < 200, it's already formatted
		lines := strings.Split(content, "\n")
		if len(lines) > 1 {
			totalLen := 0
			for _, l := range lines {
				totalLen += len(l)
			}

			avgLen := totalLen / len(lines)
			if avgLen < 200 {
				return nil
			}
		}

		beautified := beautifyJS(content)
		if writeErr := os.WriteFile(path, []byte(beautified), 0o644); writeErr != nil {
			return nil
		}

		count++

		return nil
	})

	return count
}

// generateReport writes a per-extension REPORT.md into the exported directory.
func generateReport(info *ExtensionInfo, destDir string, beautifiedCount int) {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# %s\n\n", info.Name))

	b.WriteString("## Overview\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	b.WriteString(fmt.Sprintf("| **ID** | `%s` |\n", info.ID))
	b.WriteString(fmt.Sprintf("| **Version** | %s |\n", info.Version))
	b.WriteString(fmt.Sprintf("| **Manifest Version** | V%d |\n", info.ManifestVer))
	b.WriteString(fmt.Sprintf("| **Browser** | %s |\n", info.Browser))
	b.WriteString(fmt.Sprintf("| **Profile** | %s |\n", info.Profile))
	b.WriteString(fmt.Sprintf("| **Source Path** | `%s` |\n", info.Path))
	b.WriteString(fmt.Sprintf("| **Risk** | **%s** (score: %d) |\n", info.RiskLevel, info.RiskScore))
	b.WriteString(fmt.Sprintf("| **JS Files Beautified** | %d |\n", beautifiedCount))
	b.WriteString("\n")

	// Permissions
	totalPerms := len(info.Permissions.All)
	b.WriteString(fmt.Sprintf("## Permissions (%d)\n\n", totalPerms))

	for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		perms := info.Permissions.ByRisk[level]
		if len(perms) == 0 {
			continue
		}

		b.WriteString(fmt.Sprintf("### %s\n\n", level))

		for _, p := range perms {
			b.WriteString(fmt.Sprintf("- `%s`\n", p))
		}

		b.WriteString("\n")
	}

	// Host Permissions
	if len(info.Permissions.Hosts) > 0 {
		b.WriteString(fmt.Sprintf("## Host Permissions (%d)\n\n", len(info.Permissions.Hosts)))

		for _, h := range info.Permissions.Hosts {
			b.WriteString(fmt.Sprintf("- `%s`\n", h))
		}

		b.WriteString("\n")
	}

	// Content Scripts
	if len(info.ContentScripts) > 0 {
		b.WriteString(fmt.Sprintf("## Content Scripts (%d)\n\n", len(info.ContentScripts)))

		for i, cs := range info.ContentScripts {
			b.WriteString(fmt.Sprintf("### Script %d\n\n", i+1))

			if len(cs.Matches) > 0 {
				b.WriteString(fmt.Sprintf("- **Matches:** %s\n", strings.Join(cs.Matches, ", ")))
			}

			if cs.RunAt != "" {
				b.WriteString(fmt.Sprintf("- **Run At:** %s\n", cs.RunAt))
			}

			for _, js := range cs.JS {
				b.WriteString(fmt.Sprintf("- JS: `%s`\n", js))
			}

			for _, css := range cs.CSS {
				b.WriteString(fmt.Sprintf("- CSS: `%s`\n", css))
			}

			b.WriteString("\n")
		}
	}

	// Suspicious Code Patterns
	if len(info.CodeFindings) > 0 {
		b.WriteString(fmt.Sprintf("## Suspicious Code Patterns (%d)\n\n", len(info.CodeFindings)))

		for _, f := range info.CodeFindings {
			b.WriteString(fmt.Sprintf("- **[%s]** %s\n", f.Risk, f.Pattern))

			file := f.File
			if f.Line > 0 {
				file = fmt.Sprintf("%s:%d", f.File, f.Line)
			}

			b.WriteString(fmt.Sprintf("  - File: `%s`\n", file))

			if f.Context != "" {
				b.WriteString(fmt.Sprintf("  - Context: `...%s...`\n", f.Context))
			}
		}

		b.WriteString("\n")
	}

	// Stealth Indicators
	if len(info.StealthFlags) > 0 {
		b.WriteString(fmt.Sprintf("## Stealth Indicators (%d)\n\n", len(info.StealthFlags)))

		for _, f := range info.StealthFlags {
			b.WriteString(fmt.Sprintf("- **[%s]** %s\n", f.Risk, f.Name))
			b.WriteString(fmt.Sprintf("  - %s\n", f.Description))

			if f.File != "" {
				b.WriteString(fmt.Sprintf("  - File: `%s`\n", f.File))
			}

			b.WriteString(fmt.Sprintf("  - Evidence: `%s`\n", f.Evidence))
		}

		b.WriteString("\n")
	}

	// Cheating Indicators
	if len(info.CheatingFlags) > 0 {
		b.WriteString(fmt.Sprintf("## Cheating Indicators (%d)\n\n", len(info.CheatingFlags)))

		for _, f := range info.CheatingFlags {
			b.WriteString(fmt.Sprintf("- %s\n", f))
		}

		b.WriteString("\n")
	}

	// File listing
	b.WriteString("## Files\n\n")
	b.WriteString("```\n")

	_ = filepath.Walk(destDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		rel, _ := filepath.Rel(destDir, path)
		if rel == "." || rel == "REPORT.md" {
			return nil
		}

		depth := strings.Count(rel, string(os.PathSeparator))

		prefix := strings.Repeat("  ", depth)
		if fi.IsDir() {
			b.WriteString(fmt.Sprintf("%s%s/\n", prefix, fi.Name()))
		} else {
			b.WriteString(fmt.Sprintf("%s%s\n", prefix, fi.Name()))
		}

		return nil
	})

	b.WriteString("```\n")

	_ = os.WriteFile(filepath.Join(destDir, "REPORT.md"), []byte(b.String()), 0o644)
}

// generateSummary writes a global SUMMARY.md at the output root.
func generateSummary(res *ExportResult, riskSummary map[string]int) {
	var b strings.Builder

	b.WriteString("# Extension Export Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- **Browsers Found:** %d profiles\n", len(res.Browsers)))
	b.WriteString(fmt.Sprintf("- **Total Extensions:** %d\n", res.Total))
	b.WriteString(fmt.Sprintf("- **Exported:** %d\n", res.Exported))

	if res.Skipped > 0 {
		b.WriteString(fmt.Sprintf("- **Skipped:** %d\n", res.Skipped))
	}

	b.WriteString("\n")

	// Risk Distribution
	b.WriteString("## Risk Distribution\n\n")
	b.WriteString("| Risk Level | Count |\n")
	b.WriteString("|------------|-------|\n")

	for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		count := riskSummary[level]
		b.WriteString(fmt.Sprintf("| %s | %d |\n", level, count))
	}

	b.WriteString("\n")

	// Per-browser breakdown
	b.WriteString("## Browser Breakdown\n\n")
	b.WriteString("| Browser | Profile | Extensions |\n")
	b.WriteString("|---------|---------|------------|\n")

	for _, bp := range res.Browsers {
		b.WriteString(fmt.Sprintf("| %s | %s | %d |\n", bp.Browser, bp.Profile, bp.ExtCount))
	}

	b.WriteString("\n")

	// Full extension table
	sorted := make([]ExtensionInfo, len(res.Extensions))
	copy(sorted, res.Extensions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].RiskScore > sorted[j].RiskScore
	})

	b.WriteString("## All Extensions\n\n")
	b.WriteString("| Name | Browser | Risk | Score | Perms | Findings |\n")
	b.WriteString("|------|---------|------|-------|-------|----------|\n")

	for _, ext := range sorted {
		findings := len(ext.CodeFindings) + len(ext.StealthFlags) + len(ext.CheatingFlags)

		name := ext.Name
		if len(name) > 45 {
			name = name[:42] + "..."
		}

		b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %d | %d |\n",
			name, ext.Browser, ext.RiskLevel, ext.RiskScore,
			len(ext.Permissions.All), findings))
	}

	b.WriteString("\n")

	// Top risk extensions
	b.WriteString("## Top Risk Extensions\n\n")

	for _, ext := range sorted {
		if ext.RiskLevel != "CRITICAL" && ext.RiskLevel != "HIGH" {
			break
		}

		b.WriteString(fmt.Sprintf("### %s (%s)\n\n", ext.Name, ext.Browser))
		b.WriteString(fmt.Sprintf("- **Risk:** %s (score: %d)\n", ext.RiskLevel, ext.RiskScore))
		b.WriteString(fmt.Sprintf("- **ID:** `%s`\n", ext.ID))
		b.WriteString(fmt.Sprintf("- **Permissions:** %d total (%d critical, %d high)\n",
			len(ext.Permissions.All), ext.Permissions.Critical, ext.Permissions.High))

		if len(ext.CodeFindings) > 0 {
			b.WriteString(fmt.Sprintf("- **Code Findings:** %d\n", len(ext.CodeFindings)))
		}

		if len(ext.StealthFlags) > 0 {
			b.WriteString(fmt.Sprintf("- **Stealth Indicators:** %d\n", len(ext.StealthFlags)))
		}

		if len(ext.CheatingFlags) > 0 {
			b.WriteString(fmt.Sprintf("- **Cheating Indicators:** %d\n", len(ext.CheatingFlags)))
		}

		b.WriteString("\n")
	}

	_ = os.WriteFile(filepath.Join(res.OutputDir, "SUMMARY.md"), []byte(b.String()), 0o644)
}
