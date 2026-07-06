package npm

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
)

// BatchResult holds results from analyzing multiple packages.
type BatchResult struct {
	Packages     []BatchEntry `json:"packages"`
	TotalRisk    int          `json:"total_risk"`                  // average risk score
	HighRisk     int          `json:"high_risk"`                   // count with score > 50
	CriticalPkgs []string     `json:"critical_packages,omitempty"` // score > 75
}

// BatchEntry holds the result for a single package in a batch analysis.
type BatchEntry struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Analysis *AnalysisResult `json:"analysis,omitempty"`
	Error    string          `json:"error,omitempty"`
}

// BatchAnalyze downloads and analyzes multiple packages concurrently.
// maxConcurrency controls parallelism; if <= 0 it defaults to 4.
func BatchAnalyze(ctx context.Context, packages []string, maxConcurrency int) (*BatchResult, error) {
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		entries = make([]BatchEntry, len(packages))
		sem     = make(chan struct{}, maxConcurrency)
	)

	for i, spec := range packages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, pkgSpec string) {
			defer wg.Done()
			defer func() { <-sem }()

			entry := analyzeOnePackage(ctx, pkgSpec)

			mu.Lock()
			entries[idx] = entry
			mu.Unlock()
		}(i, spec)
	}

	wg.Wait()

	// Compute summary statistics.
	result := &BatchResult{Packages: entries}

	var riskSum, analyzed int
	for _, e := range entries {
		if e.Analysis == nil {
			continue
		}
		analyzed++
		riskSum += e.Analysis.RiskScore

		if e.Analysis.RiskScore > 50 {
			result.HighRisk++
		}
		if e.Analysis.RiskScore > 75 {
			result.CriticalPkgs = append(result.CriticalPkgs, e.Name)
		}
	}

	if analyzed > 0 {
		result.TotalRisk = riskSum / analyzed
	}

	return result, nil
}

// analyzeOnePackage downloads a single package to a temp directory, runs
// Analyze, and cleans up.
func analyzeOnePackage(_ context.Context, spec string) BatchEntry {
	name, version := parseSpec(spec)

	entry := BatchEntry{Name: name, Version: version}

	tmpDir, err := os.MkdirTemp("", "unravel-npm-batch-*")
	if err != nil {
		entry.Error = fmt.Sprintf("creating temp dir: %v", err)
		return entry
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dl, err := Download(name, version, tmpDir)
	if err != nil {
		entry.Error = fmt.Sprintf("download: %v", err)
		return entry
	}
	entry.Version = dl.Version

	analysis, err := Analyze(tmpDir)
	if err != nil {
		entry.Error = fmt.Sprintf("analyze: %v", err)
		return entry
	}

	entry.Analysis = analysis
	return entry
}

// parseSpec splits "pkg@version" into name and version, handling scoped packages.
func parseSpec(spec string) (string, string) {
	// Handle scoped packages: @scope/pkg@version
	if strings.HasPrefix(spec, "@") {
		rest := spec[1:]
		idx := strings.LastIndex(rest, "@")
		if idx > 0 {
			return spec[:idx+1], rest[idx+1:]
		}
		return spec, ""
	}

	idx := strings.LastIndex(spec, "@")
	if idx > 0 {
		return spec[:idx], spec[idx+1:]
	}
	return spec, ""
}
