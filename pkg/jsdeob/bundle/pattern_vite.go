/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"fmt"
	"regexp"
)

var (
	reViteFingerprint = regexp.MustCompile(`__vite__mapDeps|__vitePreload|__VITE_PRELOAD__`)
	// IIFE module-factory wrappers: `(()=>{ ... })()` (lazy fallback;
	// brace-balanced extraction below tightens boundaries).
	reViteFactoryStart = regexp.MustCompile(`\(\s*\(\s*\)\s*=>\s*\{`)
)

// ViteRecogniser implements Recogniser for Vite-produced bundles.
type ViteRecogniser struct{}

// Name returns the kind identifier.
func (ViteRecogniser) Name() Kind { return KindVite }

// Match scans for Vite fingerprints and carves IIFE module-factory
// wrappers as proposals.
func (ViteRecogniser) Match(src []byte) (set ModuleSet, matched bool) {
	defer func() {
		if r := recover(); r != nil {
			set = ModuleSet{Kind: KindVite, Evidence: []string{fmt.Sprintf("panic: %v", r)}}
			matched = true
		}
	}()

	if !reViteFingerprint.Match(src) {
		return ModuleSet{Kind: KindUnknown}, false
	}
	set.Kind = KindVite
	set.Evidence = append(set.Evidence, "vite preload markers")
	matched = true

	starts := reViteFactoryStart.FindAllIndex(src, -1)
	for _, m := range starts {
		openIdx := m[1] - 1
		if openIdx < 0 || openIdx >= len(src) || src[openIdx] != '{' {
			continue
		}
		closeIdx := matchBalancedBrace(src, openIdx)
		if closeIdx < 0 {
			continue
		}
		set.Modules = append(set.Modules, ModuleProposal{
			Start:  m[0],
			End:    closeIdx + 1,
			Source: "pattern",
		})
	}

	for _, dm := range reDefineProp.FindAllSubmatch(src, -1) {
		if len(dm) < 2 {
			continue
		}
		attachIfUnambiguous(&set.Modules, string(dm[1]), src)
	}

	set.Modules = sortAndDedupe(set.Modules)
	return set, true
}
