/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// CWERegistrar is the function-pointer seam used to feed CWE ids observed
// during dependency enrichment back into a downstream registry (e.g.
// pkg/forensic.RegisterCWE for Phase 10 reports — D-07).
//
// pkg/knowledge does NOT import pkg/forensic directly; that would create a
// cycle (pkg/forensic.regression.go imports pkg/knowledge for Diff). The
// CLI / MCP wiring layer registers the real function via SetCWERegistrar in
// an init() block; tests can override or read through the no-op default.
type CWERegistrar func(id, description string)

var cweRegistrar CWERegistrar = func(string, string) {}

// SetCWERegistrar installs the runtime CWE id sink. Idempotent: the most
// recent registration wins. Call from cmd/ or test setup; keep
// pkg/knowledge free of pkg/forensic.
func SetCWERegistrar(fn CWERegistrar) {
	if fn == nil {
		cweRegistrar = func(string, string) {}
		return
	}
	cweRegistrar = fn
}

// DepExtractor is implemented per ecosystem (npm, NuGet, Go modules, PyPI).
// Per-ecosystem packages register their extractor in init() via
// RegisterDepExtractor; the knowledge pipeline iterates the registry when
// --enrich is on. This is the seam Phase 14-03 (npm + .NET) and 14-04
// (Go + PyPI) plug into.
type DepExtractor interface {
	// Ecosystem identifies the OSV-canonical ecosystem string.
	Ecosystem() cve.Ecosystem
	// Detect returns true when the extractor is applicable to the given app
	// (e.g. presence of package.json for npm).
	Detect(appDir string) bool
	// Extract returns the declared dep list. Each DepInput.Private is set
	// when the extractor recognizes a private/internal scoped package per
	// D-08; the cve.Client skips API calls for such inputs.
	Extract(appDir string) ([]cve.DepInput, error)
}

var depExtractors []DepExtractor

// RegisterDepExtractor is called by per-ecosystem packages in their init()
// to plug into the enrichment pipeline. Idempotent against repeated init
// (duplicate ecosystems are tolerated; the pipeline simply runs both).
func RegisterDepExtractor(e DepExtractor) {
	if e == nil {
		return
	}
	depExtractors = append(depExtractors, e)
}

// DepExtractors returns the currently registered extractor list. Callers
// must NOT mutate the returned slice; treat it as read-only.
func DepExtractors() []DepExtractor {
	return depExtractors
}

// DepsSummary is the aggregate written to dependencies/summary.json.
type DepsSummary struct {
	GeneratedAt        time.Time      `json:"generated_at"`
	TotalDeps          int            `json:"total_deps"`
	VulnerableCount    int            `json:"vulnerable_count"`
	SeverityHistogram  map[string]int `json:"severity_histogram"`
	OldestOutdatedMaj  int            `json:"oldest_outdated_major"`
	SkippedReasons     map[string]int `json:"skipped_reasons,omitempty"`
	EcosystemBreakdown map[string]int `json:"ecosystem_breakdown"`
}

// SkippedDep is the marker emitted as cve.json when the upstream client
// could not enrich a particular dep. KB still ships per the WARN-degrade
// contract (D-01 + plan must-have).
type SkippedDep struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// sanitizePackageName converts a package name into a filesystem-safe
// segment. Rules (single source of truth):
//   - replaces "/" with "__" so scoped npm names like "@scope/pkg" become
//     "@scope__pkg".
//   - drops every char NOT matching [a-zA-Z0-9._@-].
//   - rejects ".." outright (returns "" — caller skips).
//   - caps the resulting segment at 80 chars.
//
// The output is always a single path segment with no separators; the
// downstream WriteFileAtomic provides the path-traversal trust boundary.
func sanitizePackageName(name string) string {
	if name == "" || name == ".." || strings.Contains(name, "..") {
		return ""
	}
	repl := strings.ReplaceAll(name, "/", "__")
	repl = strings.ReplaceAll(repl, "\\", "__")
	var b strings.Builder
	for _, r := range repl {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '@', r == '-':
			b.WriteRune(r)
		default:
			// drop
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return ""
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// WriteEnrichedDeps emits per-dep cve.json files plus an aggregate
// summary.json under outDir/dependencies/. For every Vulnerability.CWE id
// observed across the input, forensic.RegisterCWE is called so Phase 10
// reports' "CWE Mappings" auto-populate (D-07).
//
// Layout:
//
//	outDir/
//	  dependencies/
//	    <ecosystem>/
//	      <package-sanitized>/
//	        cve.json          (full cve.EnrichedDep, OR SkippedDep marker)
//	    summary.json
//
// Skipped/error entries (Status != "ok") still land on disk as a
// SkippedDep marker so the user can see why enrichment did not land.
func WriteEnrichedDeps(outDir string, deps []cve.EnrichedDep) error {
	if outDir == "" {
		return fmt.Errorf("WriteEnrichedDeps: outDir required")
	}

	summary := DepsSummary{
		GeneratedAt:        time.Now().UTC(),
		TotalDeps:          len(deps),
		SeverityHistogram:  map[string]int{},
		SkippedReasons:     map[string]int{},
		EcosystemBreakdown: map[string]int{},
	}

	for _, d := range deps {
		eco := strings.ToLower(string(d.Ecosystem))
		if eco == "" {
			eco = "unknown"
		}
		summary.EcosystemBreakdown[eco]++

		pkgSeg := sanitizePackageName(d.Package)
		if pkgSeg == "" {
			// path-traversal or empty name — drop into a "_invalid" bucket
			// rather than failing; surface via SkippedReasons.
			summary.SkippedReasons["invalid-package-name"]++
			continue
		}

		depDir := filepath.Join(outDir, "dependencies", eco, pkgSeg)
		cvePath := filepath.Join(depDir, "cve.json")

		if d.Status != "ok" && d.Status != "" {
			marker := SkippedDep{Status: d.Status, Reason: d.Reason}
			reason := d.Reason
			if reason == "" {
				reason = d.Status
			}
			summary.SkippedReasons[reason]++
			if err := WriteJSONAtomic(cvePath, marker); err != nil {
				return fmt.Errorf("write skipped marker for %s/%s: %w", eco, pkgSeg, err)
			}
			continue
		}

		// ok path — full record.
		if err := WriteJSONAtomic(cvePath, d); err != nil {
			return fmt.Errorf("write cve.json for %s/%s: %w", eco, pkgSeg, err)
		}

		if len(d.Vulnerabilities) > 0 {
			summary.VulnerableCount++
			// register every CWE id across this dep's vulns so Phase 10
			// reports auto-pick up dep-derived CWEs (D-07). Description
			// left empty preserves any pre-seeded longer text in the
			// forensic registry.
			for _, v := range d.Vulnerabilities {
				lvl := strings.ToLower(v.Severity.Level)
				if lvl == "" {
					lvl = "none"
				}
				summary.SeverityHistogram[lvl]++
				for _, cwe := range v.CWE {
					cweRegistrar(cwe, "")
				}
			}
		}

		if d.OutdatedBy != nil && d.OutdatedBy.Major > summary.OldestOutdatedMaj {
			summary.OldestOutdatedMaj = d.OutdatedBy.Major
		}
	}

	// stable map ordering for deterministic JSON output
	summary.SeverityHistogram = sortedCopy(summary.SeverityHistogram)
	summary.SkippedReasons = sortedCopy(summary.SkippedReasons)
	summary.EcosystemBreakdown = sortedCopy(summary.EcosystemBreakdown)

	summaryPath := filepath.Join(outDir, "dependencies", "summary.json")
	if err := WriteJSONAtomic(summaryPath, summary); err != nil {
		return fmt.Errorf("write summary.json: %w", err)
	}
	return nil
}

// sortedCopy returns a copy of m with keys in ascending order. Go map
// iteration order is randomized; tests + diff-tooling want deterministic
// JSON, so we re-key into an ordered insertion via a fresh map (Go's
// encoding/json sorts map keys alphabetically — sufficient for our
// determinism contract).
func sortedCopy(m map[string]int) map[string]int {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]int, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}
