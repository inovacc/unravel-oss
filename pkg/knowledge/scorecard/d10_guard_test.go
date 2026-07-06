/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"reflect"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// TestScorecardNeverFieldOfDissectResult is the D-10 invariant guard.
// It walks every field of dissect.DissectResult (recursively, including
// embedded structs, slice/map element types, pointer dereferences) and
// fails if any field's type comes from this scorecard package.
//
// D-10 mandates that knowledge.json byte shape stays unchanged: Scorecard
// is strictly a return value of Rubric.Score, never persisted on
// DissectResult. A future PR that adds `Scorecard *scorecard.Scorecard`
// to DissectResult would break every cached knowledge.json round-trip and
// be caught here.
//
// P58 (Task 58-06): the additive Citation type and DimScore.MissingCitations
// counter live ENTIRELY in this scorecard package; they must not leak into
// dissect.DissectResult. The reflection walk below already catches any
// field whose type comes from `scorecardPkg`, so Citation/MissingCitations
// are covered automatically by the same guard. Belt-and-braces assertions
// for the named types are added below as named tripwires for future
// reviewers.
func TestScorecardNeverFieldOfDissectResult(t *testing.T) {
	// no-float CI hint: this package mandates RUBR-04 (integer scores
	// only). CI grep `float[36][24]` over scorer_*.go and rubric.go must
	// return zero hits. Tests may use float for comparisons but production
	// source must not.

	scorecardPkg := reflect.TypeOf(Scorecard{}).PkgPath()
	root := reflect.TypeOf(dissect.DissectResult{})

	seen := map[reflect.Type]bool{}
	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		if rt == nil || seen[rt] {
			return
		}
		seen[rt] = true
		switch rt.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Chan:
			walk(rt.Elem(), path+"[]")
			return
		case reflect.Map:
			walk(rt.Key(), path+"<key>")
			walk(rt.Elem(), path+"<val>")
			return
		case reflect.Struct:
			if rt.PkgPath() == scorecardPkg {
				t.Errorf("D-10 breach: %s carries scorecard-package type %s.%s", path, rt.PkgPath(), rt.Name())
			}
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				// P58 named tripwire — fail if a future commit adds a field
				// literally named Citation/MissingCitations/CitationsOK on
				// any DissectResult subtree, regardless of its package.
				if name := f.Name; name == "Citation" || name == "MissingCitations" || name == "CitationsOK" {
					t.Errorf("D-10 breach (P58 named tripwire): field %s.%s introduces P58 citation surface on DissectResult subtree", path, name)
				}
				// P59-05 named tripwire (EMIT-01) — fail if a future commit
				// adds a field literally named EmitHeader on any DissectResult
				// subtree. EmitHeader is INPUT-ONLY to scorecard.EmitScorecardMD
				// and must never be persisted on the dissect result (would
				// mutate knowledge.json byte shape, breaking D-10).
				if name := f.Name; name == "EmitHeader" {
					t.Errorf("D-10 breach (P59 named tripwire): field %s.%s introduces P59 emitter surface on DissectResult subtree", path, name)
				}
				walk(f.Type, path+"."+f.Name)
			}
		}
	}
	walk(root, "DissectResult")
}
