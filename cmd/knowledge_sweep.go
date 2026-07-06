/*
Copyright (c) 2026 Security Research
*/
// Package cmd / knowledge_sweep.go hosts the `knowledge sweep` subcommand
// and the shared `enrichProgressEvery` helper still referenced by
// knowledge_synth_names and knowledge_topics. The file was originally
// named knowledge_kb_enrich.go and held four AI-augmented commands.
//
// History: this file previously held four AI-augmented commands
// (`knowledge enrich/fill/ask` plus `sweep`). The enrich CLI was removed
// on 2026-05-23 when the MCP sampling pivot landed (the legacy
// sampling-based enrich MCP tool owned enrichment then; the unravel-enrich
// plugin owns it now); fill + ask followed in the same session
// since their `kbllm.Call`-based subprocess fanout is incompatible with
// the sampling-only kbllm.Call. Restore equivalents — if needed — by
// shipping `unravel_kb_enrich_fill` / `unravel_kb_enrich_ask` MCP tools.
//
// Cross-file package-scope references (all `package cmd`):
//   - kbOpenDB                          — declared in cmd/knowledge_kb_extract_index.go
//   - runKBExtract, runKBIndex          — declared in cmd/knowledge_kb_extract_index.go
//   - sweepRegistry is consumed by runKBDissectApp (knowledge_kb_query.go)
//     via package scope.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/asar"

	"github.com/spf13/cobra"
)

// enrichProgressEvery reports whether progress should be logged: at the
// every-th item, or when done==total. Originally a runKBEnrich helper;
// retained because knowledge_synth_names and knowledge_topics use it
// for their own progress reporting.
func enrichProgressEvery(done, every, total int) bool {
	if total <= 0 || every <= 0 {
		return false
	}
	if done == total {
		return true
	}
	return done > 0 && done%every == 0
}

var kbSweepCmd = &cobra.Command{
	Use:   "sweep",
	Short: "Auto-extract + auto-index every supported app's cache into one knowledge DB",
	Long: `For each app in the built-in registry (or the comma-separated --apps list),
locate its WebView2 / Electron HTTP cache, extract the JS bundles to
<root>/<App>/08-extracted-modules, then index them into the shared DB.

Supported apps: whatsapp, teams, slack, linkedin, discord, claude, outlook, telegram.
Apps whose cache dir does not exist on this machine are skipped silently.`,
	RunE: runKBSweep,
}

// kbSweepTargetsCmd prints the built-in sweep app registry (the static
// appCache table below). This is the CLI surface for the compiled-in
// registry — distinct from `kb catalog apps`, which lists apps present in
// the live Postgres knowledge base.
var kbSweepTargetsCmd = &cobra.Command{
	Use:   "sweep-targets",
	Short: "List the built-in sweep app registry (static)",
	Run: func(_ *cobra.Command, _ []string) {
		names := make([]string, 0, len(sweepRegistry))
		for _, a := range sweepRegistry {
			names = append(names, a.name)
		}
		sort.Strings(names)
		for _, n := range names {
			for _, a := range sweepRegistry {
				if a.name == n {
					fmt.Printf("%s\n", n)
					for _, p := range a.cachePaths {
						fmt.Printf("  %s\n", p)
					}
					break
				}
			}
		}
	},
}

// ─────────────────────────────────────────────────────────────────────
// sweep + app cache registry
// ─────────────────────────────────────────────────────────────────────

// appCache describes where each known app stores its WebView2 / Electron HTTP
// cache. Paths use placeholders %LOCALAPPDATA% and %APPDATA% which are
// substituted at runtime. The first cachePath that resolves on disk wins.
type appCache struct {
	name       string   // logical app name used as the SQL `app` column
	cachePaths []string // candidate Cache_Data dirs (try in order)
	// asarGlobs lists glob patterns that match Electron app.asar archives.
	// When matched, sweep extracts the asar to <root>/<App>/asar/ and
	// indexes its .js files under the same app name so cache + asar bodies
	// share one namespace.
	asarGlobs []string
}

var sweepRegistry = []appCache{
	{
		name: "whatsapp",
		cachePaths: []string{
			`%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalCache\EBWebView\Default\Cache\Cache_Data`,
		},
	},
	{
		name: "teams",
		cachePaths: []string{
			`%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\WV2Profile_tfw\Cache\Cache_Data`,
			`%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\WV2Profile_tfl\Cache\Cache_Data`,
			`%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\Default\Cache\Cache_Data`,
		},
	},
	{
		name: "slack",
		cachePaths: []string{
			// MSIX (Microsoft Store) Slack — WebView2-based. Only the network
			// HTTP cache (Cache_Data, f_NNN files) yields recoverable JS source.
			// Code Cache/js was tried previously but its <16hex>_0 entries are
			// V8 compiled-bytecode blobs (not JS source); extracting them
			// always yields 0 bundles, so we skip it. MSIX Slack therefore has
			// inherently low module coverage compared to Electron Slack — the
			// browser fetches most code on demand from a.slack-edge.com and
			// only caches a handful of large bundles.
			`%LOCALAPPDATA%\Packages\91750D7E.Slack_8she8kybcnzg4\LocalCache\Roaming\Slack\Cache\Cache_Data`,
			`%APPDATA%\Slack\Cache\Cache_Data`,
		},
	},
	{
		name: "linkedin",
		cachePaths: []string{
			`%LOCALAPPDATA%\Packages\7EE7776C.LinkedInforWindows_w1wdnht996qgy\LocalState\EBWebView\Default\Cache\Cache_Data`,
		},
	},
	{
		name: "discord",
		cachePaths: []string{
			// Discord ships its renderer inside app.asar (Electron), so the HTTP
			// cache mostly contains avatars and CDN attachments, not JS bundles.
			// We still scan it for the rare cached worker scripts.
			`%APPDATA%\discord\Cache\Cache_Data`,
		},
		asarGlobs: []string{
			`%LOCALAPPDATA%\Discord\app-*\resources\app.asar`,
		},
	},
	{
		name: "claude",
		cachePaths: []string{
			`%APPDATA%\Claude\Cache\Cache_Data`,
		},
		asarGlobs: []string{
			`%LOCALAPPDATA%\Programs\Claude\resources\app.asar`,
			`%LOCALAPPDATA%\Programs\claude\resources\app.asar`,
		},
	},
	{
		name:       "slack",
		cachePaths: []string{},
		asarGlobs: []string{
			// Slack also ships an Electron desktop build (separate from the MS
			// Store WebView2 variant captured above under cachePaths). Both can
			// coexist on the same machine.
			`%LOCALAPPDATA%\slack\app-*\resources\app.asar`,
		},
	},
	{
		// New Outlook for Windows (the MSIX/WebView2 rewrite shipping
		// alongside classic Win32 Outlook). The renderer is HTML/JS, so
		// the EBWebView cache yields recoverable JS modules in the same
		// shape as Teams above.
		name: "outlook",
		cachePaths: []string{
			`%LOCALAPPDATA%\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache\Microsoft\Outlook\EBWebView\Default\Cache\Cache_Data`,
			`%LOCALAPPDATA%\Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache\EBWebView\Default\Cache\Cache_Data`,
			`%LOCALAPPDATA%\Microsoft\Olk\EBWebView\Default\Cache\Cache_Data`,
		},
	},
	{
		// Telegram Desktop is a native Qt/C++ app — no Electron renderer,
		// no JS bundles. Listed here so `unravel knowledge sources` can
		// still record an epoch for capture-time tracking even though the
		// JS sweep produces 0 modules. Future work could harvest strings
		// from the binary instead.
		name:       "telegram",
		cachePaths: []string{},
		asarGlobs:  []string{},
	},
}

func runKBSweep(_ *cobra.Command, _ []string) error {
	if err := os.MkdirAll(sweepRoot, 0o755); err != nil {
		return fmt.Errorf("mkdir root: %w", err)
	}
	// sweepDB is now a DSN override (PG cutover v3.0). Empty falls through
	// to config.yaml + keychain via kbdb.Open. The legacy file-path default
	// (<root>/knowledge.db) was removed because it would be misinterpreted
	// as a Postgres DSN by pgxpool.ParseConfig.
	// Cascade the sweep-level --batch into the index path that runKBIndex
	// uses internally. runKBIndex also honours UNRAVEL_KB_BATCH directly
	// so users can override without redeploying.
	kbIndexBatch = sweepBatch

	wanted := map[string]bool{}
	if sweepApps != "" {
		for _, a := range strings.Split(sweepApps, ",") {
			wanted[strings.TrimSpace(strings.ToLower(a))] = true
		}
	}

	type result struct {
		app, cache, dst string
		err             error
	}
	var done []result

	for _, app := range sweepRegistry {
		if len(wanted) > 0 && !wanted[app.name] {
			continue
		}
		// Reset shared knobs to the documented defaults each iteration so a
		// previous app's --max-bytes etc don't bleed across.
		if kbIndexExcerpt == 0 {
			kbIndexExcerpt = 32768
		}
		if kbIndexMinBytes == 0 {
			kbIndexMinBytes = 200
		}
		kbIndexDB = sweepDB

		ranAnything := false
		// One epoch per app: the first runKBIndex allocates it; subsequent
		// dirs (extra caches + asar) reuse it so the build is one epoch.
		kbIndexReuseEpoch = 0

		// 1) HTTP cache extraction (WebView2 / Electron HTTP cache).
		// Iterate ALL existing candidates so co-located caches like
		// Slack's Cache/Cache_Data + Code Cache/js are both swept; the DB
		// dedups by (app, body_sha256) so re-running on overlapping caches
		// is idempotent. Each candidate writes to a stable per-index dir.
		for idx, cacheCand := range app.cachePaths {
			cache := pickFirstExisting([]string{cacheCand})
			if cache == "" {
				continue
			}
			suffix := "08-extracted-modules"
			if idx > 0 {
				suffix = fmt.Sprintf("08-extracted-modules-%d", idx)
			}
			dst := filepath.Join(sweepRoot, capitalise(app.name), suffix)
			fmt.Fprintf(os.Stderr, "→ %-9s  cache=%s\n", app.name, cache)
			kbExtractSrc, kbExtractDst = cache, dst
			if err := runKBExtract(nil, nil); err != nil {
				done = append(done, result{app.name, cache, dst, err})
				continue
			}
			kbIndexApp, kbIndexSrc = app.name, dst
			if err := runKBIndex(nil, nil); err != nil {
				done = append(done, result{app.name, cache, dst, err})
				continue
			}
			kbIndexReuseEpoch = kbIndexLastEpoch
			ranAnything = true
		}

		// 2) Electron asar archive — primary source for Discord/Slack-Electron/
		// Claude. Skip if the app has no asar entry.
		if asarPath := pickFirstAsar(app.asarGlobs); asarPath != "" {
			dst := filepath.Join(sweepRoot, capitalise(app.name), "asar")
			fmt.Fprintf(os.Stderr, "→ %-9s  asar=%s\n", app.name, asarPath)
			if err := extractAsarJS(asarPath, dst); err != nil {
				done = append(done, result{app.name, asarPath, dst, err})
				continue
			}
			kbIndexApp, kbIndexSrc = app.name, dst
			if err := runKBIndex(nil, nil); err != nil {
				done = append(done, result{app.name, asarPath, dst, err})
				continue
			}
			kbIndexReuseEpoch = kbIndexLastEpoch
			ranAnything = true
		}

		if !ranAnything {
			fmt.Fprintf(os.Stderr, "skip %-9s — no cache or asar found\n", app.name)
			continue
		}
		done = append(done, result{app.name, "", "", nil})
	}

	fmt.Println("\n=== sweep summary ===")
	for _, r := range done {
		status := "ok"
		if r.err != nil {
			status = "fail: " + r.err.Error()
		}
		fmt.Printf("  %-9s %s\n", r.app, status)
	}
	return nil
}

// pickFirstAsar resolves env vars + globs in each candidate and returns the
// first matching app.asar (lexicographically last match wins for app-* dirs
// so we land on the newest version).
func pickFirstAsar(candidates []string) string {
	for _, c := range candidates {
		expanded := expandWindowsEnv(c)
		matches, err := filepath.Glob(expanded)
		if err != nil || len(matches) == 0 {
			continue
		}
		sort.Strings(matches)
		return matches[len(matches)-1]
	}
	return ""
}

// extractAsarJS unpacks an Electron app.asar to outDir but only writes files
// whose extension looks like JS source (.js/.mjs/.cjs). Skips images, JSON
// configs, fonts — keeps the on-disk dump small and focused on what
// runKBIndex actually consumes.
func extractAsarJS(asarPath, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	f, hdr, dataOff, _, err := asar.OpenAndParse(asarPath)
	if err != nil {
		return fmt.Errorf("asar open: %w", err)
	}
	defer func() { _ = f.Close() }()

	files := asar.CollectFiles(hdr.Files, "")
	count := 0
	for _, fe := range files {
		if fe.IsDir {
			continue
		}
		ext := strings.ToLower(filepath.Ext(fe.Path))
		if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
			continue
		}
		body, rerr := asar.ReadFileContent(f, int64(dataOff), fe.Offset, fe.Size)
		if rerr != nil {
			continue
		}
		// Flat layout under outDir keeps source_file readable in module_sightings;
		// preserve relative path with `/` → `_` so it stays a single file.
		safe := strings.ReplaceAll(strings.TrimPrefix(fe.Path, "/"), "/", "_")
		if err := os.WriteFile(filepath.Join(outDir, safe), body, 0o644); err != nil {
			continue
		}
		count++
	}
	fmt.Fprintf(os.Stderr, "  asar extracted %d .js files -> %s\n", count, outDir)
	return nil
}

// pickFirstExisting expands env vars in each candidate and returns the first
// path that exists as a directory.
func pickFirstExisting(candidates []string) string {
	for _, c := range candidates {
		expanded := expandWindowsEnv(c)
		if info, err := os.Stat(expanded); err == nil && info.IsDir() {
			return expanded
		}
	}
	return ""
}

// expandWindowsEnv replaces %VAR% segments with their os.Getenv value. We
// don't use os.ExpandEnv because that uses $VAR / ${VAR} only.
func expandWindowsEnv(s string) string {
	out := s
	for {
		i := strings.Index(out, "%")
		if i < 0 {
			break
		}
		j := strings.Index(out[i+1:], "%")
		if j < 0 {
			break
		}
		j += i + 1
		key := out[i+1 : j]
		val := os.Getenv(key)
		out = out[:i] + val + out[j+1:]
	}
	return out
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
