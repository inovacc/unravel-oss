/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestEmitScorecardMD_StructuralParity is the P59 golden test (W2).
//
// IMPORTANT: ground-truth `out/whatsapp-kb/SCORECARD.md` is a HAND-CURATED
// archival snapshot. The emitter parity asserted here is STRUCTURAL parity
// (sections present, column counts, bar-glyph algorithm, integer mean math,
// locked literals from §6, PascalCase booleans), NOT literal-string parity
// to that archival file. The expected fixture
// `testdata/whatsapp_expected.md` is hand-written to match THIS emitter's
// output and is the byte-equality target.
//
// The header `**Generated:**` line is the only allowed delta — but the test
// pins a fixed time so even that is byte-equal in CI.
func TestEmitScorecardMD_StructuralParity(t *testing.T) {
	sc := loadScorecardFixture(t, "testdata/whatsapp_scorecard.json")
	log := loadIterLogFixture(t, "testdata/whatsapp_iteration_log.json")

	header := EmitHeader{
		KbID:      "270943e5bc622a72",
		Title:     "WhatsApp",
		PackageID: "5319275A.WhatsAppDesktop",
		Generated: time.Date(2026, 5, 6, 21, 58, 57, 960854700, time.FixedZone("-03:00", -3*3600)),
		Threshold: canonicalThreshold,
	}

	got := renderScorecardMD(sc, log, header)

	expectPath := "testdata/whatsapp_expected.md"
	want, err := os.ReadFile(expectPath)
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}
	if !bytes.Equal([]byte(got), want) {
		// Helpful diff: write produced output to a sibling file for inspection.
		_ = os.WriteFile("testdata/whatsapp_actual.md", []byte(got), 0o644)
		t.Fatalf("emitter output differs from testdata/whatsapp_expected.md\n--- got (first 800 chars) ---\n%s\n--- want (first 800 chars) ---\n%s",
			head(got, 800), head(string(want), 800))
	}
}

// TestEmitScorecardMD_WritesFile asserts the on-disk path + 0o644 mode.
func TestEmitScorecardMD_WritesFile(t *testing.T) {
	dir := t.TempDir()
	sc := &Scorecard{
		KbID: "deadbeef",
		Dimensions: []DimScore{
			{ID: "identity", Name: "Identity", Score: 100},
		},
		CitationsOK: true,
	}
	if err := EmitScorecardMD(dir, sc, nil, EmitHeader{KbID: "deadbeef", Title: "X", Generated: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "SCORECARD.md"))
	if err != nil {
		t.Fatalf("read SCORECARD.md: %v", err)
	}
	if !strings.Contains(string(body), "## Coverage summary") {
		t.Errorf("missing §2 heading in output")
	}
	if !strings.Contains(string(body), "## Per-dimension") {
		t.Errorf("missing §3 heading in output")
	}
}

// TestBarGlyph asserts the bar algorithm: 10 cells per row, U+2588 fills,
// U+00B7 dots, edge cases.
func TestBarGlyph(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "··········"},
		{10, "█·········"},
		{50, "█████·····"},
		{85, "████████··"},
		{100, "██████████"},
		{-5, "··········"},
		{150, "██████████"},
	}
	for _, c := range cases {
		got := barGlyph(c.score)
		if got != c.want {
			t.Errorf("barGlyph(%d) = %q, want %q", c.score, got, c.want)
		}
		if runeCount(got) != 10 {
			t.Errorf("barGlyph(%d) is %d cells, want 10", c.score, runeCount(got))
		}
	}
}

// TestMeanIntegerMath asserts no floats: with sum=1030, mean10 = 858 → "85.8%".
func TestMeanIntegerMath(t *testing.T) {
	sc := loadScorecardFixture(t, "testdata/whatsapp_scorecard.json")
	out := renderScorecardMD(sc, nil, EmitHeader{Title: "X"})
	if !strings.Contains(out, "Mean score: 85.8%") {
		t.Errorf("expected 'Mean score: 85.8%%' in output, got:\n%s", out)
	}
}

// TestNoFloatsInEmit is a static check that emit.go uses no float types.
// Belt-and-braces alongside CI grep `float[36][24]`.
func TestNoFloatsInEmit(t *testing.T) {
	src, err := os.ReadFile("emit.go")
	if err != nil {
		t.Fatalf("read emit.go: %v", err)
	}
	re := regexp.MustCompile(`\bfloat(32|64)\b`)
	if re.Match(src) {
		t.Errorf("emit.go contains float type — B2 violation")
	}
}

// helpers ----------------------------------------------------------------

func loadScorecardFixture(t *testing.T, path string) *Scorecard {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var sc Scorecard
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return &sc
}

func loadIterLogFixture(t *testing.T, path string) *IterationLog {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var log IterationLog
	if err := json.Unmarshal(b, &log); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return &log
}

func runeCount(s string) int {
	return len([]rune(s))
}

func head(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// _ keeps reflect import used if test grows.
var _ = reflect.TypeOf
