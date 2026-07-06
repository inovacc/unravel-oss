/*
Copyright (c) 2026 Security Research
*/

// Package framework implements pattern-based JavaScript framework
// detection on bundle-output (post-bundler) source. Returns
// []FrameworkInfo mirroring the Phase 4 (pkg/electron/framework,
// pkg/winui) FrameworkInfo shape exactly so detection results compose
// with the dissect Frameworks slice.
//
// Detection runs per recovered module (D-08): the bundle reconstruction
// step splits a webpack/Vite/esbuild/Rollup bundle and Detect is invoked
// on each module body. A "primary framework" is recorded for the bundle
// in manifest.json but does not override per-module context.
//
// 9 frameworks recognised: React, Preact, Vue, Angular, Svelte, Solid,
// Next.js, Nuxt, Remix.
package framework

import (
	"fmt"
	"sort"
)

// FrameworkInfo mirrors Phase 4 (pkg/electron/framework,
// pkg/winui.FrameworkInfo) shape exactly.
type FrameworkInfo struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

// Detect runs all 9 framework matchers against src and returns the
// matching FrameworkInfo slice. Empty slice (not nil) when no matcher
// fires. Order: more-specific frameworks first (Next.js / Nuxt / Remix
// outrank React / Vue), then by confidence descending.
//
// defer/recover at the function boundary (D-22): on panic Detect returns
// an empty slice so a poisoned input cannot abort the calling pipeline.
func Detect(src []byte) (out []FrameworkInfo) {
	defer func() {
		if r := recover(); r != nil {
			out = []FrameworkInfo{}
			_ = fmt.Sprintf("framework.Detect panic: %v", r) // sink
		}
	}()

	// Pre-compute version literals once (O(n) over src). Avoids quadratic
	// behaviour when 9 matchers each invoke FindAllSubmatch over multi-MB
	// input.
	versionBySlug := scanVersions(src)

	out = make([]FrameworkInfo, 0, 2)
	for _, m := range matchers {
		matched, evidence, version, uniqueHits := runMatcher(src, m, versionBySlug)
		if !matched {
			continue
		}
		conf := confidenceFor(len(evidence), uniqueHits)
		_ = m // keep for potential future per-matcher metadata
		out = append(out, FrameworkInfo{
			Name:       m.name,
			Version:    version,
			Confidence: conf,
			Evidence:   evidence,
		})
	}

	// Sort: specificity desc, then confidence desc, then name asc for
	// determinism.
	sort.SliceStable(out, func(i, j int) bool {
		si := specificityFor(out[i].Name)
		sj := specificityFor(out[j].Name)
		if si != sj {
			return si > sj
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Name < out[j].Name
	})

	return out
}

// DetectPrimary returns the first FrameworkInfo from Detect, ok=false
// when no framework matched.
func DetectPrimary(src []byte) (FrameworkInfo, bool) {
	all := Detect(src)
	if len(all) == 0 {
		return FrameworkInfo{}, false
	}
	return all[0], true
}

// confidenceFor maps pattern-hit count to a confidence score:
//   - >=2 distinct patterns or one uniquely identifying pattern → 0.85
//   - 1 multi-framework pattern → 0.7
//   - explicit name+version literal hit → 1.0 (callers bump separately)
func confidenceFor(hits int, uniqueHits int) float64 {
	switch {
	case uniqueHits >= 1:
		return 0.85
	case hits >= 2:
		return 0.85
	case hits == 1:
		return 0.7
	}
	return 0.0
}

// specificityFor returns the specificity rank for a framework name; used
// to break ties so Next.js outranks React when both fire (D-08).
func specificityFor(name string) int {
	switch name {
	case "Next.js", "Nuxt", "Remix":
		return 10
	case "Angular":
		return 8
	case "Vue", "Svelte":
		return 7
	case "React", "Preact", "Solid":
		return 5
	}
	return 0
}
