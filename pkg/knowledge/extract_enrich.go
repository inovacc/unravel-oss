/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/inovacc/unravel-oss/pkg/cve"
)

// runDepEnrichment is the Phase 14 dependency enrichment driver. It
// iterates the registered DepExtractors, calls cve.Client.Query per
// ecosystem, and writes per-dep cve.json + summary.json into outDir/
// dependencies/. WARN-degrades on per-extractor / per-query errors so the
// KB still ships when offline/ratelimited (D-01).
//
// D-08 audit-trail: an info-level log line is emitted at the start so the
// fact dep names left the host is visible in operator logs.
func runDepEnrichment(ctx context.Context, appDir string, opts ExtractOptions) error {
	slog.Info("dependency enrichment ON — sending dep names to OSV/NVD/GHSA per D-08 audit-trail")

	if opts.OutputDir == "" {
		return fmt.Errorf("Enrich requires OutputDir to be set")
	}

	cveClient := cve.NewClient(cve.Options{Online: true})
	var allDeps []cve.EnrichedDep

	for _, ex := range DepExtractors() {
		if !ex.Detect(appDir) {
			continue
		}
		deps, err := ex.Extract(appDir)
		if err != nil {
			slog.Warn("dep extract failed", "ecosystem", ex.Ecosystem(), "err", err)
			continue
		}
		// D-08 override: when EnrichIncludePrivate is set, force-clear the
		// Private flag so private/scoped packages are also queried.
		if opts.EnrichIncludePrivate {
			for i := range deps {
				deps[i].Private = false
			}
		}
		enriched, err := cveClient.Query(ctx, deps)
		if err != nil {
			slog.Warn("cve query failed", "ecosystem", ex.Ecosystem(), "err", err)
			// WARN-degrade: synthesize skipped markers so the user sees the
			// gap in cve.json files instead of a silently empty directory.
			for _, d := range deps {
				allDeps = append(allDeps, cve.EnrichedDep{
					Ecosystem:       d.Ecosystem,
					Package:         d.Name,
					VersionDeclared: d.Version,
					Status:          "skipped",
					Reason:          "cve-query-error",
				})
			}
			continue
		}
		allDeps = append(allDeps, enriched...)
	}

	if len(allDeps) == 0 {
		slog.Info("dependency enrichment: no extractors matched", "appDir", appDir)
		return nil
	}
	if err := WriteEnrichedDeps(opts.OutputDir, allDeps); err != nil {
		return fmt.Errorf("write enriched deps: %w", err)
	}
	return nil
}
