/*
Copyright (c) 2026 Security Research
*/
package secret

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/inovacc/unravel-oss/pkg/garble"
)

// Finding represents a single detected secret.
type Finding struct {
	Type       SecretType `json:"type"`
	Value      string     `json:"value"` // masked: first 4 + "***" + last 4
	RawLength  int        `json:"raw_length"`
	File       string     `json:"file"`
	Confidence string     `json:"confidence"` // "high" or "medium"
}

// ScanResult holds the results of scanning an APK for secrets.
type ScanResult struct {
	TotalFindings  int       `json:"total_findings"`
	HighConfidence int       `json:"high_confidence"`
	MedConfidence  int       `json:"medium_confidence"`
	FilesScanned   int       `json:"files_scanned"`
	Findings       []Finding `json:"findings"`
}

// Scan opens an APK as a ZIP and scans entries for hardcoded secrets.
func Scan(apkPath string) (*ScanResult, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, fmt.Errorf("open apk: %w", err)
	}

	defer func() { _ = zr.Close() }()

	result := &ScanResult{}
	seen := make(map[string]bool) // dedup by type+masked_value

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}

		strategy := classifyEntry(f.Name)
		if strategy == scanSkip {
			continue
		}

		data, err := readZipEntry(f)
		if err != nil {
			continue
		}

		result.FilesScanned++

		var content string

		switch strategy {
		case scanBinaryStrings:
			content = extractPrintableStrings(data, 8)
		case scanText:
			content = string(data)
		}

		// Embedded keystore detection (runs on raw data, before content check).
		for _, finding := range scanEmbeddedKeystore(data, f.Name) {
			key := string(finding.Type) + ":" + finding.Value
			if !seen[key] {
				seen[key] = true
				result.Findings = append(result.Findings, finding)
			}
		}

		if content == "" {
			continue
		}

		// Run pattern matching.
		for _, pat := range patterns {
			matches := pat.Pattern.FindAllString(content, 20)
			for _, match := range matches {
				key := string(pat.Type) + ":" + maskValue(match)
				if seen[key] {
					continue
				}

				seen[key] = true

				result.Findings = append(result.Findings, Finding{
					Type:       pat.Type,
					Value:      maskValue(match),
					RawLength:  len(match),
					File:       f.Name,
					Confidence: pat.Confidence,
				})
			}
		}

		// Firebase config detection.
		if strategy == scanText {
			for _, finding := range scanFirebaseConfig(content, f.Name) {
				key := string(finding.Type) + ":" + finding.Value
				if !seen[key] {
					seen[key] = true
					result.Findings = append(result.Findings, finding)
				}
			}
		}

		// High-entropy string detection for text files.
		if strategy == scanText {
			for _, word := range extractCandidateTokens(content) {
				if len(word) < 20 || len(word) > 200 {
					continue
				}

				entropy := garble.ShannonEntropy(word)
				if entropy > 4.5 {
					key := string(TypeHighEntropy) + ":" + maskValue(word)
					if seen[key] {
						continue
					}

					seen[key] = true

					result.Findings = append(result.Findings, Finding{
						Type:       TypeHighEntropy,
						Value:      maskValue(word),
						RawLength:  len(word),
						File:       f.Name,
						Confidence: "medium",
					})
				}
			}
		}
	}

	// Compute stats.
	result.TotalFindings = len(result.Findings)
	for _, f := range result.Findings {
		switch f.Confidence {
		case "high":
			result.HighConfidence++
		case "medium":
			result.MedConfidence++
		}
	}

	return result, nil
}

// scanStrategy determines how to extract strings from a ZIP entry.
type scanStrategy int

const (
	scanSkip          scanStrategy = iota
	scanBinaryStrings              // extract printable ASCII from binary content
	scanText                       // treat as text/json/xml
)

// classifyEntry decides the scan strategy for a ZIP entry by its path.
func classifyEntry(name string) scanStrategy {
	lower := strings.ToLower(name)

	// DEX files.
	if strings.HasSuffix(lower, ".dex") {
		return scanBinaryStrings
	}

	// Native libraries.
	if strings.HasSuffix(lower, ".so") {
		return scanBinaryStrings
	}

	// XML resources.
	if strings.HasSuffix(lower, ".xml") {
		// Binary XML in res/ won't yield much from text scan,
		// but we try binary string extraction.
		if strings.HasPrefix(lower, "res/") {
			return scanBinaryStrings
		}

		return scanText
	}

	// Assets directory — scan text-like files.
	if strings.HasPrefix(lower, "assets/") {
		ext := filepath.Ext(lower)
		switch ext {
		case ".json", ".js", ".html", ".htm", ".css", ".txt", ".properties",
			".yaml", ".yml", ".toml", ".cfg", ".conf", ".ini", ".env":
			return scanText
		default:
			return scanBinaryStrings
		}
	}

	// Resources table.
	if lower == "resources.arsc" {
		return scanBinaryStrings
	}

	// Skip images, compiled resources, signing metadata.
	ext := filepath.Ext(lower)
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
		".ttf", ".otf", ".woff", ".woff2",
		".ogg", ".mp3", ".wav", ".mp4",
		".sf", ".rsa", ".dsa", ".ec", ".mf":
		return scanSkip
	}

	// Default: try text scan for unknown files.
	return scanText
}

// readZipEntry reads the content of a ZIP file entry.
func readZipEntry(f *zip.File) ([]byte, error) {
	// Limit to 10MB to avoid memory issues.
	const maxSize = 10 * 1024 * 1024
	if f.UncompressedSize64 > maxSize {
		return nil, fmt.Errorf("file too large: %d bytes", f.UncompressedSize64)
	}

	rc, err := f.Open()
	if err != nil {
		return nil, err
	}

	defer func() { _ = rc.Close() }()

	return io.ReadAll(rc)
}

// extractPrintableStrings extracts ASCII printable strings of at least minLen.
func extractPrintableStrings(data []byte, minLen int) string {
	var (
		result  strings.Builder
		current []byte
	)

	for _, b := range data {
		if b >= 0x20 && b < 0x7f {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				result.Write(current)
				result.WriteByte('\n')
			}

			current = current[:0]
		}
	}

	if len(current) >= minLen {
		result.Write(current)
		result.WriteByte('\n')
	}

	return result.String()
}

// extractCandidateTokens splits content into words that could be tokens/keys.
func extractCandidateTokens(content string) []string {
	// Split on whitespace, quotes, equals, colons, commas.
	replacer := strings.NewReplacer(
		"\"", " ", "'", " ", "=", " ", ":", " ",
		",", " ", ";", " ", "(", " ", ")", " ",
		"<", " ", ">", " ", "{", " ", "}", " ",
	)
	cleaned := replacer.Replace(content)

	return strings.Fields(cleaned)
}

// scanDirFile holds a file path + relative path for the worker pool.
type scanDirFile struct {
	path    string
	relPath string
	ext     string
}

// ScanDirectory walks a decompiled source directory and scans text files for secrets.
// It uses a worker pool for concurrent scanning.
func ScanDirectory(dir string) (*ScanResult, error) {
	// Collect files first.
	var files []scanDirFile

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Skip files > 1MB (decompiled sources are small; large = generated/binary).
		if info.Size() > 1*1024*1024 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".java", ".kt", ".smali", ".xml", ".json", ".properties", ".yml", ".yaml", ".txt", ".html", ".js":
		default:
			return nil
		}

		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = path
		}

		files = append(files, scanDirFile{path: path, relPath: relPath, ext: ext})

		return nil
	})

	// DEBUG: one line per scan target, reusing the already-collected file
	// list (no extra traversal). Gated behind slog DEBUG level so it is
	// silent unless --debug is on. No behavior change.
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		for _, f := range files {
			slog.Debug("secrets scan target",
				"scan_dir", dir,
				"rel_path", f.relPath,
				"ext", f.ext,
			)
		}
	}

	// Worker pool: scan files concurrently.
	const numWorkers = 8

	type fileResult struct {
		findings []Finding
	}

	fileCh := make(chan scanDirFile, numWorkers*2)
	resultCh := make(chan fileResult, numWorkers*2)

	var wg sync.WaitGroup

	for range numWorkers {

		wg.Go(func() {

			for f := range fileCh {
				data, err := os.ReadFile(f.path)
				if err != nil {
					continue
				}

				content := string(data)
				var findings []Finding
				localSeen := make(map[string]bool)

				// Only run high-confidence patterns on .smali to avoid noise.
				pats := patterns
				if f.ext == ".smali" {
					pats = highConfPatterns
				}

				for _, pat := range pats {
					matches := pat.Pattern.FindAllString(content, 10)
					for _, match := range matches {
						key := string(pat.Type) + ":" + maskValue(match)
						if localSeen[key] {
							continue
						}

						localSeen[key] = true

						findings = append(findings, Finding{
							Type:       pat.Type,
							Value:      maskValue(match),
							RawLength:  len(match),
							File:       f.relPath,
							Confidence: pat.Confidence,
						})
					}
				}

				// Firebase config detection.
				for _, finding := range scanFirebaseConfig(content, f.relPath) {
					key := string(finding.Type) + ":" + finding.Value
					if !localSeen[key] {
						localSeen[key] = true
						findings = append(findings, finding)
					}
				}

				// BuildConfig field extraction.
				for _, finding := range scanBuildConfig(content, f.relPath) {
					key := string(finding.Type) + ":" + finding.Value
					if !localSeen[key] {
						localSeen[key] = true
						findings = append(findings, finding)
					}
				}

				// High-entropy only for small config-like files (skip .java/.smali).
				if f.ext != ".smali" && f.ext != ".java" && len(data) < 100*1024 {
					for _, word := range extractCandidateTokens(content) {
						if len(word) < 20 || len(word) > 200 {
							continue
						}

						entropy := garble.ShannonEntropy(word)
						if entropy > 4.5 {
							key := string(TypeHighEntropy) + ":" + maskValue(word)
							if localSeen[key] {
								continue
							}

							localSeen[key] = true

							findings = append(findings, Finding{
								Type:       TypeHighEntropy,
								Value:      maskValue(word),
								RawLength:  len(word),
								File:       f.relPath,
								Confidence: "medium",
							})
						}
					}
				}

				resultCh <- fileResult{findings: findings}
			}
		})
	}

	// Feed files to workers.
	go func() {
		for _, f := range files {
			fileCh <- f
		}

		close(fileCh)
		wg.Wait()
		close(resultCh)
	}()

	// Collect results.
	result := &ScanResult{FilesScanned: len(files)}
	globalSeen := make(map[string]bool)

	for fr := range resultCh {
		for _, f := range fr.findings {
			key := string(f.Type) + ":" + f.Value
			if globalSeen[key] {
				continue
			}

			globalSeen[key] = true
			result.Findings = append(result.Findings, f)
		}
	}

	result.TotalFindings = len(result.Findings)
	for _, f := range result.Findings {
		switch f.Confidence {
		case "high":
			result.HighConfidence++
		case "medium":
			result.MedConfidence++
		}
	}

	return result, nil
}

// MergeResults merges src findings into dst, deduplicating by type+value.
func MergeResults(dst, src *ScanResult) {
	if src == nil || dst == nil {
		return
	}

	seen := make(map[string]bool)
	for _, f := range dst.Findings {
		seen[string(f.Type)+":"+f.Value] = true
	}

	for _, f := range src.Findings {
		key := string(f.Type) + ":" + f.Value
		if seen[key] {
			continue
		}

		seen[key] = true
		dst.Findings = append(dst.Findings, f)
	}

	dst.FilesScanned += src.FilesScanned
	dst.TotalFindings = len(dst.Findings)

	dst.HighConfidence = 0
	dst.MedConfidence = 0

	for _, f := range dst.Findings {
		switch f.Confidence {
		case "high":
			dst.HighConfidence++
		case "medium":
			dst.MedConfidence++
		}
	}
}

// maskValue masks a secret value showing first 4 and last 4 chars.
func maskValue(s string) string {
	if len(s) <= 12 {
		return s[:min(4, len(s))] + "***"
	}

	return s[:4] + "***" + s[len(s)-4:]
}
