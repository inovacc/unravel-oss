/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

var updateGolden = flag.Bool("update", false, "update golden file fixtures")

func loadSampleReport(t *testing.T) *Report {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "sample_report.json"))
	if err != nil {
		t.Fatalf("read sample_report.json: %v", err)
	}
	var r Report
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("unmarshal sample_report.json: %v", err)
	}
	return &r
}

func TestRenderHTML_Golden(t *testing.T) {
	r := loadSampleReport(t)
	out, err := renderHTML(r, HTMLOptions{IncludeImages: false})
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	goldenPath := filepath.Join("testdata", "sample_report.golden.html")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, out, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated golden file %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v (run `go test -update` to create it)", err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("HTML output differs from golden.\n--- got len=%d ---\n%s\n--- want len=%d ---\n%s",
			len(out), string(out), len(want), string(want))
	}
}

// isEmoji checks for emoji code points in common ranges (D-04, D-24).
func isEmoji(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FFFF:
		return true
	case r >= 0x2600 && r <= 0x27BF:
		return true
	}
	return false
}

func TestRenderHTML_NoEmojis(t *testing.T) {
	r := loadSampleReport(t)
	out, err := renderHTML(r, HTMLOptions{})
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	s := string(out)
	for i, w := 0, 0; i < len(s); i += w {
		ru, sz := utf8.DecodeRuneInString(s[i:])
		w = sz
		if isEmoji(ru) {
			t.Fatalf("emoji rune %U found at byte %d", ru, i)
		}
	}
}

func TestRenderHTML_SelfContained(t *testing.T) {
	r := loadSampleReport(t)
	out, err := renderHTML(r, HTMLOptions{})
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	if bytes.Contains(out, []byte("<script src=")) {
		t.Error("rendered HTML must not include external <script src=>")
	}
	if bytes.Contains(out, []byte(`<link rel="stylesheet" href=`)) {
		t.Error("rendered HTML must not include external stylesheet link")
	}
}

func TestRenderHTML_BadgeClasses(t *testing.T) {
	r := loadSampleReport(t)
	out, err := renderHTML(r, HTMLOptions{})
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	for _, want := range []string{"badge-block", "badge-flag", "badge-pass"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("expected %q in output", want)
		}
	}
}

func TestBadgeClass_Mapping(t *testing.T) {
	tests := []struct{ in, want string }{
		{"BLOCK", "badge-block"},
		{"FLAG", "badge-flag"},
		{"PASS", "badge-pass"},
		{"unknown", "badge-info"},
		{"", "badge-info"},
	}
	for _, tt := range tests {
		if got := badgeClass(tt.in); got != tt.want {
			t.Errorf("badgeClass(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}

func TestBase64Image_MissingFile(t *testing.T) {
	if got := base64Image("/does/not/exist.png"); got != "" {
		t.Errorf("base64Image missing file = %q; want empty", got)
	}
	if got := base64Image(""); got != "" {
		t.Errorf("base64Image empty path = %q; want empty", got)
	}
}

func TestBase64Image_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.png")
	payload := []byte{0x89, 0x50, 0x4E, 0x47}
	if err := os.WriteFile(p, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	got := base64Image(p)
	if !bytes.HasPrefix([]byte(got), []byte("data:image/png;base64,")) {
		t.Errorf("expected data:image/png;base64, prefix; got %q", got)
	}
}

func TestCweN_Helper(t *testing.T) {
	if got := cweN("hardcoded_credential"); got != 798 {
		t.Errorf("cweN(hardcoded_credential) = %d; want 798", got)
	}
	if got := cweN("nonexistent"); got != 0 {
		t.Errorf("cweN(nonexistent) = %d; want 0", got)
	}
}
