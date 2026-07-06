/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"fmt"
	"regexp"
)

var (
	reEsbuildDefProp  = regexp.MustCompile(`var\s+__defProp\s*=\s*Object\.defineProperty`)
	reEsbuildCommonJS = regexp.MustCompile(`var\s+__commonJS\s*=`)
	reEsbuildEsm      = regexp.MustCompile(`var\s+__esm\s*=`)
	reEsbuildToESM    = regexp.MustCompile(`var\s+__toESM\s*=`)

	// Module boundary: `var <name>_exports = {};`
	reEsbuildExportsDecl = regexp.MustCompile(`var\s+([A-Za-z_$][\w$]*)_exports\s*=\s*\{\s*\}\s*;`)
)

// EsbuildRecogniser implements Recogniser for esbuild bundles.
type EsbuildRecogniser struct{}

// Name returns the kind identifier.
func (EsbuildRecogniser) Name() Kind { return KindEsbuild }

// Match scans for esbuild's stable runtime markers — requires at least
// 2 of 4 markers — and emits one proposal per `<name>_exports = {};`
// declaration, ranging from that decl to the next decl (or EOF).
func (EsbuildRecogniser) Match(src []byte) (set ModuleSet, matched bool) {
	defer func() {
		if r := recover(); r != nil {
			set = ModuleSet{Kind: KindEsbuild, Evidence: []string{fmt.Sprintf("panic: %v", r)}}
			matched = true
		}
	}()

	hits := 0
	if reEsbuildDefProp.Match(src) {
		hits++
		set.Evidence = append(set.Evidence, "__defProp")
	}
	if reEsbuildCommonJS.Match(src) {
		hits++
		set.Evidence = append(set.Evidence, "__commonJS")
	}
	if reEsbuildEsm.Match(src) {
		hits++
		set.Evidence = append(set.Evidence, "__esm")
	}
	if reEsbuildToESM.Match(src) {
		hits++
		set.Evidence = append(set.Evidence, "__toESM")
	}
	if hits < 2 {
		return ModuleSet{Kind: KindUnknown}, false
	}
	set.Kind = KindEsbuild
	matched = true

	matches := reEsbuildExportsDecl.FindAllSubmatchIndex(src, -1)
	for i, m := range matches {
		name := string(src[m[2]:m[3]])
		start := m[0]
		end := len(src)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		set.Modules = append(set.Modules, ModuleProposal{
			Start:         start,
			End:           end,
			CandidateName: name,
			Source:        "pattern",
		})
	}
	set.Modules = sortAndDedupe(set.Modules)
	return set, true
}
