package knowledge

import (
	"fmt"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"log/slog"
	"time"
)

type Options struct {
	OutputDir string
	Verbose   bool
	// WithAI enables the source-fidelity beautify tracks (D-14, Plan 07-04).
	// Off by default. When true, Run delegates to ExtractV2 with WithAI=true
	// so per-language beautifiers (Java/JS/Bundle/C#) and the MCP-backed
	// component classifier are invoked.
	WithAI bool

	// Enrich (Phase 14) opts into dependency CVE/CWE/freshness enrichment
	// via pkg/cve. Off by default per D-08 audit-trail; sends dep names to
	// OSV/NVD/GHSA. EnrichIncludePrivate overrides the default skip-private
	// behavior.
	Enrich               bool
	EnrichIncludePrivate bool
}

func Run(path string, opts Options) (*KnowledgeResult, error) {
	start := time.Now()

	dr, err := dissect.Run(path, dissect.Options{
		Verbose: opts.Verbose,
	})
	if err != nil {
		return nil, fmt.Errorf("dissect: %w", err)
	}

	var result *KnowledgeResult
	if opts.WithAI || opts.Enrich {
		result = ExtractV2(dr, ExtractOptions{
			WithAI:               opts.WithAI,
			Enrich:               opts.Enrich,
			EnrichIncludePrivate: opts.EnrichIncludePrivate,
			AppDir:               dr.Path,
			OutputDir:            opts.OutputDir,
		})
	} else {
		result = Extract(dr)
	}
	result.Duration = time.Since(start)

	if opts.Verbose && result.GoBinary != nil {
		slog.Info("Go binary analyzed",
			"module", result.GoBinary.ModulePath,
			"go_version", result.GoBinary.GoVersion,
			"garbled", result.GoBinary.IsGarbled)
	}
	if opts.Verbose && result.Packaging != nil {
		slog.Info("packaging analyzed",
			"format", result.Packaging.Format,
			"name", result.Packaging.Name,
			"files", result.Packaging.FileCount)
	}
	if opts.Verbose && result.DataDir != nil {
		slog.Info("data directory found", "path", result.DataDir.Path)
		if result.DataDir.LocalStorage != nil {
			slog.Info("localStorage parsed",
				"origins", result.DataDir.LocalStorage.Stats.OriginCount,
				"entries", result.DataDir.LocalStorage.Stats.TotalEntries)
		}
		if result.DataDir.Cache != nil {
			slog.Info("HTTP cache parsed",
				"entries", result.DataDir.Cache.EntryCount,
				"domains", len(result.DataDir.Cache.Domains))
		}
		if result.DataDir.Preferences != nil {
			slog.Info("preferences loaded", "keys", len(result.DataDir.Preferences))
		}
		if result.DataDir.AppState != nil {
			slog.Info("app state files found", "count", len(result.DataDir.AppState))
		}
		if result.DataDir.Cookies != nil {
			slog.Info("cookies parsed",
				"total", result.DataDir.Cookies.Stats.Total,
				"domains", result.DataDir.Cookies.Stats.DomainCount)
		}
		if result.DataDir.IndexedDB != nil {
			slog.Info("IndexedDB parsed",
				"databases", result.DataDir.IndexedDB.Stats.DatabaseCount,
				"entries", result.DataDir.IndexedDB.Stats.TotalEntries)
		}
		if result.DataDir.DIPS != nil {
			slog.Info("DIPS parsed", "sites", result.DataDir.DIPS.Total)
		}
	}

	if opts.OutputDir != "" {
		if err := WriteDirectory(result, opts.OutputDir); err != nil {
			return nil, fmt.Errorf("write knowledge: %w", err)
		}
	}

	return result, nil
}
