/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"fmt"
	"regexp"
)

var (
	reRollupAMD       = regexp.MustCompile(`typeof\s+define\s*===?\s*['"]function['"]\s*&&\s*define\.amd`)
	reRollupCJSCheck  = regexp.MustCompile(`typeof\s+exports\s*===?\s*['"]object['"]\s*&&\s*typeof\s+module`)
	reRollupIIFEStart = regexp.MustCompile(`\(\s*function\s*\(\s*[A-Za-z_$,\s]*\)\s*\{`)
)

// RollupRecogniser implements Recogniser for Rollup standalone output.
type RollupRecogniser struct{}

// Name returns the kind identifier.
func (RollupRecogniser) Name() Kind { return KindRollup }

// Match scans for Rollup UMD/IIFE preamble fingerprints.
func (RollupRecogniser) Match(src []byte) (set ModuleSet, matched bool) {
	defer func() {
		if r := recover(); r != nil {
			set = ModuleSet{Kind: KindRollup, Evidence: []string{fmt.Sprintf("panic: %v", r)}}
			matched = true
		}
	}()

	hasAMD := reRollupAMD.Match(src)
	hasCJS := reRollupCJSCheck.Match(src)
	if !hasAMD && !hasCJS {
		return ModuleSet{Kind: KindUnknown}, false
	}
	set.Kind = KindRollup
	if hasAMD {
		set.Evidence = append(set.Evidence, "define.amd")
	}
	if hasCJS {
		set.Evidence = append(set.Evidence, "typeof exports & module")
	}
	matched = true

	if loc := reRollupIIFEStart.FindIndex(src); loc != nil {
		openIdx := loc[1] - 1
		if openIdx >= 0 && openIdx < len(src) && src[openIdx] == '{' {
			closeIdx := matchBalancedBrace(src, openIdx)
			if closeIdx > openIdx {
				set.Modules = append(set.Modules, ModuleProposal{
					Start:  loc[0],
					End:    closeIdx + 1,
					Source: "pattern",
				})
			}
		}
	}

	set.Evidence = append(set.Evidence, "rollup-single-iife")
	return set, true
}
