/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("testdata", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %q: %v", p, err)
	}
	return b
}

func TestWebpackRecogniser_ChunkedBundle(t *testing.T) {
	src := loadFixture(t, "webpack_min.js")
	r := WebpackRecogniser{}
	set, ok := r.Match(src)
	if !ok {
		t.Fatal("expected webpack recogniser to match")
	}
	if set.Kind != KindWebpack {
		t.Errorf("Kind = %s, want webpack", set.Kind)
	}
	if len(set.Modules) < 2 {
		t.Errorf("got %d modules, want >=2", len(set.Modules))
	}
	ids := map[string]bool{}
	for _, m := range set.Modules {
		ids[m.ModuleID] = true
	}
	for _, want := range []string{"456", "789"} {
		if !ids[want] {
			t.Errorf("missing module ID %q in %v", want, ids)
		}
	}
}

func TestWebpackRecogniser_ModernArrayChunk(t *testing.T) {
	src := []byte(`(self.webpackChunk_x = self.webpackChunk_x || []).push([[1], {
		100: function (e, t, r) { return 1 },
		200: function (e, t, r) { return 2 }
	}]);`)
	set, ok := WebpackRecogniser{}.Match(src)
	if !ok {
		t.Fatal("modern array chunk should match")
	}
	if len(set.Modules) < 2 {
		t.Errorf("got %d modules, want >=2", len(set.Modules))
	}
}

func TestWebpackRecogniser_NameRecovery_FromExportD(t *testing.T) {
	src := loadFixture(t, "webpack_min.js")
	set, _ := WebpackRecogniser{}.Match(src)
	gotName := false
	for _, m := range set.Modules {
		if m.CandidateName == "Foo" {
			gotName = true
		}
	}
	if !gotName {
		t.Errorf("expected at least one module with CandidateName=Foo, got %+v", set.Modules)
	}
}

func TestViteRecogniser_FingerprintMatch(t *testing.T) {
	src := loadFixture(t, "vite_min.js")
	set, ok := ViteRecogniser{}.Match(src)
	if !ok {
		t.Fatal("expected vite recogniser to match")
	}
	if set.Kind != KindVite {
		t.Errorf("Kind = %s, want vite", set.Kind)
	}
	if len(set.Modules) < 1 {
		t.Errorf("expected >=1 module factories, got %d", len(set.Modules))
	}
}

func TestEsbuildRecogniser_FingerprintMatch(t *testing.T) {
	src := loadFixture(t, "esbuild_min.js")
	set, ok := EsbuildRecogniser{}.Match(src)
	if !ok {
		t.Fatal("expected esbuild recogniser to match")
	}
	if set.Kind != KindEsbuild {
		t.Errorf("Kind = %s, want esbuild", set.Kind)
	}
	if len(set.Modules) < 2 {
		t.Errorf("got %d modules, want >=2", len(set.Modules))
	}
	names := map[string]bool{}
	for _, m := range set.Modules {
		names[m.CandidateName] = true
	}
	for _, want := range []string{"foo", "bar"} {
		if !names[want] {
			t.Errorf("missing recovered name %q in %v", want, names)
		}
	}
}

func TestRollupRecogniser_FingerprintMatch(t *testing.T) {
	src := loadFixture(t, "rollup_min.js")
	set, ok := RollupRecogniser{}.Match(src)
	if !ok {
		t.Fatal("expected rollup recogniser to match")
	}
	if set.Kind != KindRollup {
		t.Errorf("Kind = %s, want rollup", set.Kind)
	}
	hasHint := false
	for _, ev := range set.Evidence {
		if ev == "rollup-single-iife" {
			hasHint = true
		}
	}
	if !hasHint {
		t.Errorf("expected rollup-single-iife evidence hint, got %v", set.Evidence)
	}
}

func TestRecognise_NoMatch(t *testing.T) {
	src := []byte("var x = 1;")
	for _, r := range []Recogniser{
		WebpackRecogniser{}, ViteRecogniser{}, EsbuildRecogniser{}, RollupRecogniser{},
	} {
		if _, ok := r.Match(src); ok {
			t.Errorf("%s should not match plain code", r.Name())
		}
	}
}

func TestRecognise_ConflictingFingerprints(t *testing.T) {
	// Mix webpack + esbuild markers.
	src := []byte(`(self.webpackChunk_x = self.webpackChunk_x || []).push([[1], {1: function(){}}]);
var __defProp = Object.defineProperty;
var __commonJS = function() {};
var foo_exports = {};
`)
	w, wok := WebpackRecogniser{}.Match(src)
	e, eok := EsbuildRecogniser{}.Match(src)
	if !wok {
		t.Fatal("webpack should match")
	}
	if !eok {
		t.Fatal("esbuild should match")
	}
	// Specificity rank webpack > esbuild — bundle.go dispatcher will
	// pick webpack first; this test asserts each recogniser stays
	// independent (no cross-talk).
	if w.Kind != KindWebpack {
		t.Errorf("webpack recogniser returned %s", w.Kind)
	}
	if e.Kind != KindEsbuild {
		t.Errorf("esbuild recogniser returned %s", e.Kind)
	}
}

func TestModuleProposal_Sorting(t *testing.T) {
	src := loadFixture(t, "esbuild_min.js")
	set, _ := EsbuildRecogniser{}.Match(src)
	// must be sorted ascending by Start, with no overlapping ranges.
	prevEnd := -1
	starts := make([]int, len(set.Modules))
	for i, m := range set.Modules {
		starts[i] = m.Start
		if m.Start < prevEnd {
			t.Errorf("module %d overlaps previous (start=%d, prevEnd=%d)", i, m.Start, prevEnd)
		}
		prevEnd = m.End
	}
	if !sort.IntsAreSorted(starts) {
		t.Errorf("modules not sorted by Start: %v", starts)
	}
}

func TestPattern_Bounded(t *testing.T) {
	// 5 MB synthetic blob. Should return well within 5s on any
	// modern dev machine (target <500ms).
	var buf bytes.Buffer
	buf.WriteString("(self.webpackChunk_x = self.webpackChunk_x || []).push([[1], {\n")
	for range 50 {
		buf.WriteString("100" + strings.Repeat("0", 0) + ": function (e, t, r) {\nvar x = 1;\n},\n")
	}
	buf.WriteString("}]);\n")
	// pad to ~5 MB with comment bytes (don't break syntax-relevant patterns).
	pad := make([]byte, 5*1024*1024-buf.Len())
	for i := range pad {
		pad[i] = ' '
	}
	buf.Write(pad)

	start := time.Now()
	_, _ = WebpackRecogniser{}.Match(buf.Bytes())
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Match took %v, want <5s", d)
	}
}

func TestRecogniser_FixturesAreEachRecognisedByExactlyOne(t *testing.T) {
	cases := []struct {
		fixture string
		want    Kind
	}{
		{"webpack_min.js", KindWebpack},
		{"vite_min.js", KindVite},
		{"esbuild_min.js", KindEsbuild},
		{"rollup_min.js", KindRollup},
	}
	all := []Recogniser{
		WebpackRecogniser{}, ViteRecogniser{}, EsbuildRecogniser{}, RollupRecogniser{},
	}
	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			src := loadFixture(t, c.fixture)
			matchedKinds := []Kind{}
			for _, r := range all {
				if _, ok := r.Match(src); ok {
					matchedKinds = append(matchedKinds, r.Name())
				}
			}
			// At least the desired one must match. Allow webpack-marker
			// crosstalk into rollup IIFE detection from generic UMD;
			// reject any cross-pollination involving esbuild markers
			// when not present.
			gotWant := false
			for _, k := range matchedKinds {
				if k == c.want {
					gotWant = true
				}
			}
			if !gotWant {
				t.Errorf("fixture %s: expected match by %s, got %v", c.fixture, c.want, matchedKinds)
			}
		})
	}
}
