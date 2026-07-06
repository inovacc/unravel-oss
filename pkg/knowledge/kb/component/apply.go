/*
Copyright (c) 2026 Security Research
*/

package component

import (
	"fmt"
	"sort"
	"strings"
)

// Apply runs the full classification pipeline on a single Module. Pure: no DB,
// no global state besides the registry. Algorithm per D-31-MULTI-MATCH:
//
//  1. Negative preflight: collect set of suppressed components.
//  2. Positive matching: collect (component, confidence, evidence) tuples.
//  3. Filter out suppressed.
//  4. If empty -> Result{"other", 1.0, "rule", "no rule matched"}.
//  5. Else pick max-confidence; tiebreak by Priorities map.
//  6. Equal confidence + equal priority across distinct components -> Result{"other", ..., "ambiguous: a, b"}.
func Apply(module Module) Result {
	all := All()
	symLower := strings.ToLower(module.SymbolsJSON)
	if len(symLower) > 64*1024 {
		symLower = symLower[:64*1024] // bound DoS via huge symbols_json
	}

	// Pass 1: negative preflight
	suppressed := map[string]bool{}
	for _, r := range all {
		if !r.Suppress {
			continue
		}
		if ruleMatches(r, module, symLower) {
			suppressed[r.Component] = true
		}
	}

	// Pass 2: positive matches
	type cand struct {
		rule Rule
	}
	var cands []cand
	for _, r := range all {
		if r.Suppress {
			continue
		}
		if suppressed[r.Component] {
			continue
		}
		if ruleMatches(r, module, symLower) {
			cands = append(cands, cand{r})
		}
	}

	if len(cands) == 0 {
		return Result{Component: "other", Confidence: 1.0, Classifier: "rule", Evidence: "no rule matched"}
	}

	// Pick max confidence then highest Priorities[component]
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].rule.Confidence != cands[j].rule.Confidence {
			return cands[i].rule.Confidence > cands[j].rule.Confidence
		}
		return Priorities[cands[i].rule.Component] > Priorities[cands[j].rule.Component]
	})

	top := cands[0]
	if len(cands) > 1 {
		nxt := cands[1]
		if top.rule.Confidence == nxt.rule.Confidence &&
			Priorities[top.rule.Component] == Priorities[nxt.rule.Component] &&
			top.rule.Component != nxt.rule.Component {
			names := make([]string, 0, len(cands))
			for _, c := range cands {
				names = append(names, c.rule.Component+"["+c.rule.Name+"]")
			}
			return Result{
				Component:  "other",
				Confidence: 1.0,
				Classifier: "rule",
				Evidence:   "ambiguous: " + strings.Join(names, ", "),
			}
		}
	}
	return Result{
		Component:  top.rule.Component,
		Confidence: top.rule.Confidence,
		Classifier: "rule",
		Evidence:   fmt.Sprintf("matched %s", top.rule.Name),
	}
}

func ruleMatches(r Rule, m Module, symLower string) bool {
	matchedAny := false
	if r.PathRegex != nil {
		if !r.PathRegex.MatchString(m.Path) {
			return false
		}
		matchedAny = true
	}
	if r.NameRegex != nil {
		if !r.NameRegex.MatchString(m.Name) {
			return false
		}
		matchedAny = true
	}
	if len(r.SymbolKeywords) > 0 {
		anyKW := false
		for _, kw := range r.SymbolKeywords {
			if strings.Contains(symLower, strings.ToLower(kw)) {
				anyKW = true
				break
			}
		}
		if !anyKW {
			return false
		}
		matchedAny = true
	}
	return matchedAny
}
