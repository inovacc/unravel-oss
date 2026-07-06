/*
Copyright (c) 2026 Security Research
*/

// Package tauri implements an inject.Scanner for Tauri desktop applications.
//
// It enumerates four seam kinds defined in phase 16 D-02:
//
//   - tauri-devtools           — devtools enabled via tauri.conf.json or Cargo feature
//   - tauri-allowlist          — one seam per enabled allowlist API key
//   - tauri-custom-protocol    — custom protocol scope / asset protocol
//   - tauri-bundle-identifier  — informational identity (low confidence)
//
// All evidence comes from filesystem reads — no execution of the target.
package tauri

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// scanner is the Tauri implementation of inject.Scanner.
type scanner struct{}

func init() { inject.RegisterScanner(scanner{}) }

// Framework returns inject.FrameworkTauri.
func (scanner) Framework() inject.Framework { return inject.FrameworkTauri }

// confPaths returns candidate locations for tauri.conf.json relative to appDir.
func confPaths(appDir string) []string {
	return []string{
		filepath.Join(appDir, "tauri.conf.json"),
		filepath.Join(appDir, "src-tauri", "tauri.conf.json"),
	}
}

// cargoPaths returns candidate locations for Cargo.toml relative to appDir.
func cargoPaths(appDir string) []string {
	return []string{
		filepath.Join(appDir, "Cargo.toml"),
		filepath.Join(appDir, "src-tauri", "Cargo.toml"),
	}
}

// Detect returns true when appDir looks like a Tauri project.
//
// Signals (any one is sufficient):
//   - tauri.conf.json at root or in src-tauri/
//   - Cargo.toml that mentions a tauri dependency
func (scanner) Detect(appDir string) bool {
	if slices.ContainsFunc(confPaths(appDir), fileExists) {
		return true
	}
	for _, p := range cargoPaths(appDir) {
		if !fileExists(p) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if cargoHasTauriDep(string(data)) {
			return true
		}
	}
	return false
}

// Scan walks tauri.conf.json and Cargo.toml under appDir, emitting one Seam
// per discovered surface.
func (s scanner) Scan(ctx context.Context, appDir string) ([]inject.Seam, error) {
	var seams []inject.Seam

	// tauri.conf.json — first existing wins.
	for _, p := range confPaths(appDir) {
		if !fileExists(p) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		var cfg tauriConf
		if err := json.Unmarshal(data, &cfg); err != nil {
			// Tolerate malformed conf — record nothing rather than fail the dissect.
			break
		}
		seams = append(seams, scanConf(p, &cfg)...)
		break
	}

	// Cargo.toml — first existing wins.
	for _, p := range cargoPaths(appDir) {
		if !fileExists(p) {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		seams = append(seams, scanCargo(p, string(data))...)
		break
	}

	return seams, nil
}

// ---------------------------------------------------------------------------
// tauri.conf.json shape — only the subset we use is decoded.
// ---------------------------------------------------------------------------

type tauriConf struct {
	Build *struct {
		DevPath string `json:"devPath,omitempty"`
	} `json:"build,omitempty"`
	Tauri *struct {
		Windows   []map[string]any           `json:"windows,omitempty"`
		Allowlist map[string]json.RawMessage `json:"allowlist,omitempty"`
		Protocol  map[string]any             `json:"protocol,omitempty"`
		Bundle    *struct {
			Identifier string `json:"identifier,omitempty"`
		} `json:"bundle,omitempty"`
	} `json:"tauri,omitempty"`
}

// scanConf returns seams discovered in a parsed tauri.conf.json.
func scanConf(path string, cfg *tauriConf) []inject.Seam {
	var out []inject.Seam

	// devtools — build.devPath OR any window.devTools=true
	devtoolsHit := false
	devtoolsSnippet := ""
	if cfg.Build != nil && cfg.Build.DevPath != "" {
		devtoolsHit = true
		devtoolsSnippet = "build.devPath=" + cfg.Build.DevPath
	}
	if cfg.Tauri != nil {
		for _, w := range cfg.Tauri.Windows {
			if v, ok := w["devTools"]; ok {
				if b, ok := v.(bool); ok && b {
					devtoolsHit = true
					if devtoolsSnippet == "" {
						devtoolsSnippet = "tauri.windows[].devTools=true"
					}
				}
			}
		}
	}
	if devtoolsHit {
		out = append(out, inject.Seam{
			Kind:       "tauri-devtools",
			Confidence: inject.ConfidenceHigh,
			Framework:  inject.FrameworkTauri,
			Evidence: []inject.Evidence{{
				Type:    inject.EvidenceConfigKey,
				Path:    path,
				Snippet: devtoolsSnippet,
			}},
			ReachableRuntime: true,
			Notes:            "Tauri devtools enabled via configuration",
		})
	}

	// allowlist — one seam per enabled api.key
	if cfg.Tauri != nil && len(cfg.Tauri.Allowlist) > 0 {
		// Sort api names for deterministic output.
		apis := make([]string, 0, len(cfg.Tauri.Allowlist))
		for k := range cfg.Tauri.Allowlist {
			apis = append(apis, k)
		}
		sort.Strings(apis)
		for _, api := range apis {
			raw := cfg.Tauri.Allowlist[api]
			var node map[string]any
			if err := json.Unmarshal(raw, &node); err != nil {
				continue
			}
			keys := make([]string, 0, len(node))
			for k := range node {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := node[k]
				if !allowlistEnabled(v) {
					continue
				}
				snip := fmt.Sprintf("tauri.allowlist.%s.%s=%v", api, k, v)
				out = append(out, inject.Seam{
					Kind:       "tauri-allowlist",
					Confidence: inject.ConfidenceHigh,
					Framework:  inject.FrameworkTauri,
					Evidence: []inject.Evidence{{
						Type:    inject.EvidenceConfigKey,
						Path:    path,
						Snippet: snip,
					}},
					ReachableRuntime: true,
					Notes:            fmt.Sprintf("Allowlist API surface enabled: %s.%s", api, k),
				})
			}
		}
	}

	// custom-protocol — any non-empty value under tauri.protocol
	if cfg.Tauri != nil && len(cfg.Tauri.Protocol) > 0 {
		hit := false
		var snippets []string
		keys := make([]string, 0, len(cfg.Tauri.Protocol))
		for k := range cfg.Tauri.Protocol {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := cfg.Tauri.Protocol[k]
			if isNonEmpty(v) {
				hit = true
				snippets = append(snippets, fmt.Sprintf("tauri.protocol.%s=%v", k, v))
			}
		}
		if hit {
			out = append(out, inject.Seam{
				Kind:       "tauri-custom-protocol",
				Confidence: inject.ConfidenceHigh,
				Framework:  inject.FrameworkTauri,
				Evidence: []inject.Evidence{{
					Type:    inject.EvidenceConfigKey,
					Path:    path,
					Snippet: strings.Join(snippets, "; "),
				}},
				ReachableRuntime: true,
				Notes:            "Custom protocol handler configured",
			})
		}
	}

	// bundle identifier — informational
	if cfg.Tauri != nil && cfg.Tauri.Bundle != nil && cfg.Tauri.Bundle.Identifier != "" {
		out = append(out, inject.Seam{
			Kind:       "tauri-bundle-identifier",
			Confidence: inject.ConfidenceLow,
			Framework:  inject.FrameworkTauri,
			Evidence: []inject.Evidence{{
				Type:    inject.EvidenceConfigKey,
				Path:    path,
				Snippet: "tauri.bundle.identifier=" + cfg.Tauri.Bundle.Identifier,
			}},
			ReachableRuntime: false,
			Notes:            "Bundle identifier is declarative metadata, not a runtime injection seam",
		})
	}

	return out
}

// allowlistEnabled returns true for explicit-true booleans, non-empty strings,
// non-empty arrays, or non-empty maps. (Tauri's allowlist accepts both
// `"all": true` and `"scope": ["..."]` forms.)
func allowlistEnabled(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	case float64, int, int64:
		return true
	default:
		return false
	}
}

// isNonEmpty reports whether v is a meaningful (non-zero) JSON value.
func isNonEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

// ---------------------------------------------------------------------------
// Cargo.toml — minimal hand-rolled parser. We only need:
//   - whether any tauri dependency is declared (Detect)
//   - whether [features] enables `devtools` directly or via default = [...]
// ---------------------------------------------------------------------------

// cargoHasTauriDep returns true when Cargo.toml content references a tauri dep.
//
// We accept any of these forms (sufficient for Detect):
//
//	[dependencies]
//	tauri = "1"
//	[dependencies.tauri]
//	[build-dependencies]
//	tauri-build = "1"
func cargoHasTauriDep(content string) bool {
	for _, line := range splitLines(content) {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		if strings.HasPrefix(l, "[dependencies.tauri") ||
			strings.HasPrefix(l, "[build-dependencies.tauri") ||
			strings.HasPrefix(l, "[target.") && strings.Contains(l, ".tauri") {
			return true
		}
		// `tauri = "..."` or `tauri-build = "..."` style key lines
		key := leadingKey(l)
		if key == "tauri" || key == "tauri-build" || strings.HasPrefix(key, "tauri-") {
			return true
		}
	}
	return false
}

// scanCargo emits a tauri-devtools seam when Cargo.toml's [features] section
// enables the `devtools` feature directly or via the default list.
func scanCargo(path, content string) []inject.Seam {
	section := ""
	devtoolsDirect := false
	devtoolsViaDefault := false
	snippet := ""
	for _, raw := range splitLines(content) {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.TrimSpace(strings.Trim(l, "[]"))
			continue
		}
		if section != "features" {
			continue
		}
		key := leadingKey(l)
		val := afterEquals(l)
		switch key {
		case "devtools":
			devtoolsDirect = true
			if snippet == "" {
				snippet = "[features] devtools = " + val
			}
		case "default":
			if containsListItem(val, "devtools") {
				devtoolsViaDefault = true
				if snippet == "" {
					snippet = "[features] default = " + val
				}
			}
		}
	}
	if !devtoolsDirect && !devtoolsViaDefault {
		return nil
	}
	return []inject.Seam{{
		Kind:       "tauri-devtools",
		Confidence: inject.ConfidenceHigh,
		Framework:  inject.FrameworkTauri,
		Evidence: []inject.Evidence{{
			Type:    inject.EvidenceManifest,
			Path:    path,
			Snippet: snippet,
		}},
		ReachableRuntime: true,
		Notes:            "Tauri devtools feature enabled in Cargo.toml",
	}}
}

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}

// leadingKey returns the bare TOML key at the start of a line (before `=`),
// stripped of quotes/whitespace. Returns "" if the line has no `=`.
func leadingKey(line string) string {
	before, _, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	k := strings.TrimSpace(before)
	k = strings.Trim(k, `"'`)
	return k
}

// afterEquals returns the trimmed RHS of a TOML key=value line.
func afterEquals(line string) string {
	_, after, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(after)
}

// containsListItem reports whether a TOML inline list (e.g. `["a", "b"]`) on
// the RHS of a `=` contains the given item.
func containsListItem(rhs, item string) bool {
	rhs = strings.TrimSpace(rhs)
	if !strings.HasPrefix(rhs, "[") {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(rhs, "["), "]")
	for part := range strings.SplitSeq(inner, ",") {
		p := strings.TrimSpace(part)
		p = strings.Trim(p, `"'`)
		if p == item {
			return true
		}
	}
	return false
}
