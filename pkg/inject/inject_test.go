/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// stubScanner is a configurable test double for Scanner.
type stubScanner struct {
	fw       Framework
	detect   bool
	seams    []Seam
	scanErr  error
	scanCall int
}

func (s *stubScanner) Framework() Framework      { return s.fw }
func (s *stubScanner) Detect(appDir string) bool { return s.detect }
func (s *stubScanner) Scan(ctx context.Context, appDir string) ([]Seam, error) {
	s.scanCall++
	return s.seams, s.scanErr
}

func TestScan_NoScannersRegistered_EmptyResult(t *testing.T) {
	resetScannersForTest()
	t.Cleanup(resetScannersForTest)

	got, err := Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if len(got.Seams) != 0 {
		t.Errorf("want 0 seams, got %d", len(got.Seams))
	}
	if got.Framework != "" {
		t.Errorf("want empty framework, got %q", got.Framework)
	}
	if got.Summary.TotalSeams != 0 {
		t.Errorf("want total 0, got %d", got.Summary.TotalSeams)
	}
}

func TestScan_OneScanner_PopulatesFramework(t *testing.T) {
	resetScannersForTest()
	t.Cleanup(resetScannersForTest)

	RegisterScanner(&stubScanner{
		fw:     FrameworkElectron,
		detect: true,
		seams: []Seam{
			{Kind: "preload-script", Confidence: ConfidenceHigh, Framework: FrameworkElectron},
			{Kind: "node-integration", Confidence: ConfidenceMedium, Framework: FrameworkElectron},
		},
	})

	got, err := Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if got.Framework != FrameworkElectron {
		t.Errorf("want electron, got %q", got.Framework)
	}
	if len(got.Seams) != 2 {
		t.Errorf("want 2 seams, got %d", len(got.Seams))
	}
}

func TestScan_TwoScanners_HybridFramework(t *testing.T) {
	resetScannersForTest()
	t.Cleanup(resetScannersForTest)

	RegisterScanner(&stubScanner{fw: FrameworkElectron, detect: true, seams: []Seam{{Kind: "k1"}}})
	RegisterScanner(&stubScanner{fw: FrameworkWebView2, detect: true, seams: []Seam{{Kind: "k2"}}})

	got, err := Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if got.Framework != FrameworkHybrid {
		t.Errorf("want hybrid, got %q", got.Framework)
	}
	if len(got.Seams) != 2 {
		t.Errorf("want 2 seams, got %d", len(got.Seams))
	}
}

func TestScan_ScannerError_DoesNotFail(t *testing.T) {
	resetScannersForTest()
	t.Cleanup(resetScannersForTest)

	bad := &stubScanner{fw: FrameworkElectron, detect: true, scanErr: errors.New("boom")}
	good := &stubScanner{fw: FrameworkTauri, detect: true, seams: []Seam{{Kind: "tauri-allowlist"}}}
	RegisterScanner(bad)
	RegisterScanner(good)

	got, err := Scan(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	// Both detected → hybrid, even though one errored.
	if got.Framework != FrameworkHybrid {
		t.Errorf("want hybrid (both detected), got %q", got.Framework)
	}
	if len(got.Seams) != 1 {
		t.Errorf("want 1 seam (only good scanner contributes), got %d", len(got.Seams))
	}
	if bad.scanCall != 1 || good.scanCall != 1 {
		t.Errorf("both scanners must be invoked: bad=%d good=%d", bad.scanCall, good.scanCall)
	}
}

func TestRankConfidence_Order(t *testing.T) {
	cases := []struct {
		name string
		in   []Confidence
		want Confidence
	}{
		{"empty", nil, ConfidenceLow},
		{"high-only", []Confidence{ConfidenceHigh}, ConfidenceHigh},
		{"medium-only", []Confidence{ConfidenceMedium}, ConfidenceMedium},
		{"low-only", []Confidence{ConfidenceLow}, ConfidenceLow},
		{"mixed-low-high-medium", []Confidence{ConfidenceLow, ConfidenceHigh, ConfidenceMedium}, ConfidenceHigh},
		{"low-medium", []Confidence{ConfidenceLow, ConfidenceMedium}, ConfidenceMedium},
		{"medium-low", []Confidence{ConfidenceMedium, ConfidenceLow}, ConfidenceMedium},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := RankConfidence(tt.in...); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteSeamsJSON_AtomicAndGuarded(t *testing.T) {
	dir := t.TempDir()
	res := &ScanResult{
		GeneratedAt: "2026-05-01T00:00:00Z",
		Framework:   FrameworkElectron,
		Seams: []Seam{
			{Kind: "preload-script", Confidence: ConfidenceHigh, Framework: FrameworkElectron},
		},
		Summary: Summary{TotalSeams: 1, ByKind: map[string]int{"preload-script": 1}, ByConfidence: map[string]int{"high": 1}},
	}
	if err := WriteSeamsJSON(dir, res); err != nil {
		t.Fatalf("WriteSeamsJSON: %v", err)
	}
	target := filepath.Join(dir, "security", "injection_seams.json")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	var rt ScanResult
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rt.Framework != FrameworkElectron || len(rt.Seams) != 1 {
		t.Errorf("round-trip mismatch: %+v", rt)
	}

	// Path-traversal guard: raw `..` segment in outDir must be rejected.
	// Use string concatenation so filepath.Join's Clean does not collapse it.
	if err := WriteSeamsJSON(dir+"/../escape", res); !errors.Is(err, ErrPathTraversal) {
		t.Errorf("want ErrPathTraversal for `..` outDir, got %v", err)
	}
}

func TestComputeSummary_AggregatesByKindAndConfidence(t *testing.T) {
	seams := []Seam{
		{Kind: "preload-script", Confidence: ConfidenceHigh},
		{Kind: "preload-script", Confidence: ConfidenceMedium},
		{Kind: "node-integration", Confidence: ConfidenceHigh},
		{Kind: "tauri-allowlist", Confidence: ConfidenceLow},
	}
	got := computeSummary(seams)
	if got.TotalSeams != 4 {
		t.Errorf("total: got %d want 4", got.TotalSeams)
	}
	if got.ByKind["preload-script"] != 2 || got.ByKind["node-integration"] != 1 || got.ByKind["tauri-allowlist"] != 1 {
		t.Errorf("by_kind wrong: %+v", got.ByKind)
	}
	if got.ByConfidence["high"] != 2 || got.ByConfidence["medium"] != 1 || got.ByConfidence["low"] != 1 {
		t.Errorf("by_confidence wrong: %+v", got.ByConfidence)
	}
}
