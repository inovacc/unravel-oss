package langs

import (
	"encoding/json"
	"sort"
)

// symbolCap mirrors the per-category cap used inside regexExtract.
const symbolCap = 200

// minifiedScanBytes / minifiedMaxLine / minifiedNLRatio: source is "minified"
// when its longest early line is very long AND newline density is low — the
// shape that defeats the (?m)^-anchored symbol regexes.
const (
	minifiedScanBytes = 1 << 16 // inspect first 64 KiB
	minifiedMaxLine   = 2000
	minifiedNLRatio   = 0.002 // < 1 newline per 500 bytes
)

// looksMinified reports whether body is minified/bundled JS that the
// ^-anchored regex extractor cannot read without a beautify pre-pass.
func looksMinified(body []byte) bool {
	n := len(body)
	if n < 512 {
		return false
	}
	scan := body
	if n > minifiedScanBytes {
		scan = body[:minifiedScanBytes]
	}
	nl, cur, maxLine := 0, 0, 0
	for _, c := range scan {
		if c == '\n' {
			nl++
			if cur > maxLine {
				maxLine = cur
			}
			cur = 0
			continue
		}
		cur++
	}
	if cur > maxLine {
		maxLine = cur
	}
	ratio := float64(nl) / float64(len(scan))
	return maxLine >= minifiedMaxLine && ratio < minifiedNLRatio
}

// jsonUnmarshalSym unmarshals a symbols_json string into v.
func jsonUnmarshalSym(s string, v any) error {
	if s == "" {
		s = "{}"
	}
	return json.Unmarshal([]byte(s), v)
}

// mergeSymbolModules unions the symbol sets of two extraction results
// (dedup, sorted/deterministic) and unions Imports. Other Module fields are
// taken from primary (a). symbolCap is re-applied per category.
func mergeSymbolModules(a, b Module) Module {
	am := map[string][]string{}
	bm := map[string][]string{}
	_ = jsonUnmarshalSym(a.SymbolsJSON, &am)
	_ = jsonUnmarshalSym(b.SymbolsJSON, &bm)
	out := map[string][]string{}
	keys := map[string]bool{}
	for k := range am {
		keys[k] = true
	}
	for k := range bm {
		keys[k] = true
	}
	for k := range keys {
		seen := map[string]bool{}
		var u []string
		for _, v := range append(append([]string{}, am[k]...), bm[k]...) {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			u = append(u, v)
		}
		sort.Strings(u)
		if symbolCap > 0 && len(u) > symbolCap {
			u = u[:symbolCap]
		}
		out[k] = u
	}
	res := a
	if j, err := json.Marshal(out); err == nil {
		res.SymbolsJSON = string(j)
	}
	// union Imports slice (dedupe, stable)
	seen := map[string]bool{}
	var imp []string
	for _, v := range append(append([]string{}, a.Imports...), b.Imports...) {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		imp = append(imp, v)
	}
	sort.Strings(imp)
	res.Imports = imp
	return res
}
