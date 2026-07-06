package heuristic

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Scanner performs heuristic analysis on source code files.
type Scanner struct {
	patterns []compiledPattern
	verbose  bool
}

type compiledPattern struct {
	Pattern
	compiled []*regexp.Regexp
	literals []string // fallback for patterns that fail to compile
}

// NewScanner creates a scanner with the given patterns.
func NewScanner(patterns []Pattern, verbose bool) *Scanner {
	s := &Scanner{verbose: verbose}
	for _, p := range patterns {
		cp := compiledPattern{Pattern: p}
		for _, raw := range p.Patterns {
			re, err := regexp.Compile(raw)
			if err != nil {
				cp.literals = append(cp.literals, raw)
			} else {
				cp.compiled = append(cp.compiled, re)
			}
		}
		s.patterns = append(s.patterns, cp)
	}
	return s
}

// NewDefaultScanner creates a scanner with all built-in patterns.
func NewDefaultScanner(verbose bool) *Scanner {
	return NewScanner(DefaultPatterns(), verbose)
}

// scannable file extensions
var scannableExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".py": true, ".pyw": true, ".go": true, ".java": true, ".kt": true, ".kts": true,
	".rb": true, ".php": true, ".cs": true, ".vbs": true, ".vba": true, ".ps1": true,
	".psm1": true, ".bat": true, ".cmd": true, ".sh": true, ".bash": true,
	".json": true, ".yaml": true, ".yml": true, ".xml": true, ".html": true, ".htm": true,
	".sql": true, ".r": true, ".lua": true, ".pl": true, ".pm": true,
	".swift": true, ".m": true, ".mm": true, ".rs": true, ".c": true, ".cpp": true, ".h": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".properties": true,
	".gradle": true, ".groovy": true, ".scala": true, ".dart": true, ".ex": true, ".exs": true,
}

// ScanFile analyzes a single file and returns findings.
func (s *Scanner) ScanFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	// Skip files > 10MB
	if info.Size() > 10*1024*1024 {
		return nil, nil
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return s.scanLines(path, lines), nil
}

// ScanContent analyzes raw content and returns findings.
func (s *Scanner) ScanContent(name, content string) []Finding {
	lines := strings.Split(content, "\n")
	return s.scanLines(name, lines)
}

func (s *Scanner) scanLines(file string, lines []string) []Finding {
	var findings []Finding
	seen := make(map[string]bool) // dedup: patternID+line

	fullContent := strings.Join(lines, "\n")

	for _, cp := range s.patterns {
		// Try multi-line patterns on full content
		for _, re := range cp.compiled {
			locs := re.FindAllStringIndex(fullContent, 50) // cap at 50 matches per pattern
			for _, loc := range locs {
				lineNum := strings.Count(fullContent[:loc[0]], "\n") + 1
				key := fmt.Sprintf("%s:%d", cp.ID, lineNum)
				if seen[key] {
					continue
				}
				seen[key] = true

				evidence := extractContext(fullContent, loc[0], loc[1], 60)
				matchedText := fullContent[loc[0]:loc[1]]
				if len(matchedText) > 120 {
					matchedText = matchedText[:120] + "..."
				}

				findings = append(findings, Finding{
					PatternID:   cp.ID,
					Name:        cp.Name,
					Description: cp.Description,
					Category:    cp.Category,
					Severity:    cp.Severity,
					Weight:      cp.Weight,
					File:        file,
					Line:        lineNum,
					Evidence:    evidence,
					MatchedText: matchedText,
				})
			}
		}

		// Literal fallbacks
		for _, lit := range cp.literals {
			for i, line := range lines {
				idx := strings.Index(line, lit)
				if idx < 0 {
					continue
				}
				key := fmt.Sprintf("%s:%d", cp.ID, i+1)
				if seen[key] {
					continue
				}
				seen[key] = true

				evidence := extractContext(line, idx, idx+len(lit), 60)
				findings = append(findings, Finding{
					PatternID:   cp.ID,
					Name:        cp.Name,
					Description: cp.Description,
					Category:    cp.Category,
					Severity:    cp.Severity,
					Weight:      cp.Weight,
					File:        file,
					Line:        i + 1,
					Evidence:    evidence,
					MatchedText: lit,
				})
			}
		}
	}

	// Additional heuristic: entropy analysis on long strings
	findings = append(findings, s.entropyAnalysis(file, lines)...)

	return findings
}

// entropyAnalysis finds suspiciously high-entropy strings (encoded payloads).
func (s *Scanner) entropyAnalysis(file string, lines []string) []Finding {
	var findings []Finding

	longStringRe := regexp.MustCompile("[\"'`]([A-Za-z0-9+/=_-]{60,})[\"'`]")

	for i, line := range lines {
		matches := longStringRe.FindAllStringSubmatch(line, 5)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			str := m[1]
			entropy := shannonEntropy(str)
			if entropy > 5.0 && len(str) > 80 {
				findings = append(findings, Finding{
					PatternID:   "heur-high-entropy",
					Name:        "High-Entropy Encoded String",
					Description: fmt.Sprintf("String with Shannon entropy %.2f (len=%d) — likely encoded payload", entropy, len(str)),
					Category:    CategoryObfuscation,
					Severity:    SeverityHigh,
					Weight:      20,
					File:        file,
					Line:        i + 1,
					Evidence:    truncate(str, 80),
					MatchedText: truncate(str, 60),
				})
			}
		}
	}

	return findings
}

// ScanDirectory recursively scans a directory for malicious patterns.
func (s *Scanner) ScanDirectory(dir string) (*Result, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			base := filepath.Base(path)
			// Skip common non-source directories
			if base == "node_modules" || base == ".git" || base == "vendor" ||
				base == "__pycache__" || base == ".venv" || base == "dist" ||
				base == "build" || base == ".next" || base == "coverage" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if scannableExts[ext] {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	return s.scanFiles(files), nil
}

func (s *Scanner) scanFiles(files []string) *Result {
	workers := min(runtime.NumCPU(), 8)

	type fileResult struct {
		findings []Finding
	}

	results := make([]fileResult, len(files))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for i, f := range files {
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			findings, err := s.ScanFile(path)
			if err != nil {
				if s.verbose {
					fmt.Fprintf(os.Stderr, "[WARN] %s: %v\n", path, err)
				}
				return
			}
			results[idx] = fileResult{findings: findings}
		}(i, f)
	}
	wg.Wait()

	// Aggregate
	result := &Result{
		FilesScanned: len(files),
		Categories:   make(map[Category]*CategorySummary),
	}

	for _, fr := range results {
		for _, f := range fr.findings {
			result.TotalFindings++
			cat, ok := result.Categories[f.Category]
			if !ok {
				cat = &CategorySummary{Category: f.Category}
				result.Categories[f.Category] = cat
			}
			cat.Count++
			cat.Score += f.Weight
			cat.Findings = append(cat.Findings, f)
			if severityRank(f.Severity) > severityRank(cat.MaxSev) {
				cat.MaxSev = f.Severity
			}
		}
	}

	// Calculate threat score
	for _, cat := range result.Categories {
		result.ThreatScore += cat.Score
	}

	// Determine threat level
	switch {
	case result.ThreatScore >= 200:
		result.ThreatLevel = "CRITICAL"
	case result.ThreatScore >= 100:
		result.ThreatLevel = "HIGH"
	case result.ThreatScore >= 40:
		result.ThreatLevel = "MEDIUM"
	case result.ThreatScore > 0:
		result.ThreatLevel = "LOW"
	default:
		result.ThreatLevel = "CLEAN"
	}

	// Top findings (sorted by weight desc)
	var all []Finding
	for _, cat := range result.Categories {
		all = append(all, cat.Findings...)
	}
	sort.Slice(all, func(i, j int) bool {
		if severityRank(all[i].Severity) != severityRank(all[j].Severity) {
			return severityRank(all[i].Severity) > severityRank(all[j].Severity)
		}
		return all[i].Weight > all[j].Weight
	})
	if len(all) > 20 {
		all = all[:20]
	}
	result.TopFindings = all

	return result
}

// BuildResult creates a Result from a list of files and findings.
func BuildResult(files []string, findings []Finding) *Result {
	s := &Scanner{}
	_ = s // just need scanFiles logic
	result := &Result{
		FilesScanned: len(files),
		Categories:   make(map[Category]*CategorySummary),
	}

	for _, f := range findings {
		result.TotalFindings++
		cat, ok := result.Categories[f.Category]
		if !ok {
			cat = &CategorySummary{Category: f.Category}
			result.Categories[f.Category] = cat
		}
		cat.Count++
		cat.Score += f.Weight
		cat.Findings = append(cat.Findings, f)
		if severityRank(f.Severity) > severityRank(cat.MaxSev) {
			cat.MaxSev = f.Severity
		}
	}

	for _, cat := range result.Categories {
		result.ThreatScore += cat.Score
	}

	switch {
	case result.ThreatScore >= 200:
		result.ThreatLevel = "CRITICAL"
	case result.ThreatScore >= 100:
		result.ThreatLevel = "HIGH"
	case result.ThreatScore >= 40:
		result.ThreatLevel = "MEDIUM"
	case result.ThreatScore > 0:
		result.ThreatLevel = "LOW"
	default:
		result.ThreatLevel = "CLEAN"
	}

	var all []Finding
	for _, cat := range result.Categories {
		all = append(all, cat.Findings...)
	}
	sort.Slice(all, func(i, j int) bool {
		if severityRank(all[i].Severity) != severityRank(all[j].Severity) {
			return severityRank(all[i].Severity) > severityRank(all[j].Severity)
		}
		return all[i].Weight > all[j].Weight
	})
	if len(all) > 20 {
		all = all[:20]
	}
	result.TopFindings = all

	return result
}

func extractContext(content string, start, end, padding int) string {
	ctxStart := max(start-padding, 0)
	ctxEnd := min(end+padding, len(content))
	ctx := content[ctxStart:ctxEnd]
	// Replace newlines for display
	ctx = strings.ReplaceAll(ctx, "\n", "↵")
	ctx = strings.ReplaceAll(ctx, "\r", "")
	return ctx
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
