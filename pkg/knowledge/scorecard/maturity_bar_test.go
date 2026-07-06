/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// maturityBar mirrors the RESEARCH §C schema of testdata/maturity_bar_v1.json.
// It is a SEPARATE artifact from the byte-sacred VALD-02 fixture
// expected_score_w13_final.json (D-01).
type maturityBar struct {
	Version      int    `json:"version"`
	RationaleDoc string `json:"rationale_doc"`
	PerDim       []struct {
		ID            string `json:"id"`
		Floor         int    `json:"floor"`
		Justification string `json:"justification"`
		EvidenceRef   string `json:"evidence_ref"`
	} `json:"per_dim"`
	CorpusGate struct {
		MinPassApps int    `json:"min_pass_apps"`
		Of          int    `json:"of"`
		Metric      string `json:"metric"`
	} `json:"corpus_gate"`
}

const maturityBarPath = "testdata/maturity_bar_v1.json"

func loadMaturityBar(t *testing.T) *maturityBar {
	t.Helper()
	raw, err := os.ReadFile(maturityBarPath)
	if err != nil {
		t.Fatalf("read %s: %v", maturityBarPath, err)
	}
	var bar maturityBar
	if err := json.Unmarshal(raw, &bar); err != nil {
		t.Fatalf("unmarshal %s: %v", maturityBarPath, err)
	}
	return &bar
}

// TestKBMaturityBar is the well-formedness unit gate (no build tag → runs in
// the quick suite). It asserts the bar loads, version==1, the 5 under-scoring
// dims are present, every per_dim entry carries a positive floor + non-empty
// justification + evidence_ref, and corpus_gate is 7 of 10 (D-06).
func TestKBMaturityBar(t *testing.T) {
	bar := loadMaturityBar(t)

	if bar.Version != 1 {
		t.Errorf("version = %d, want 1", bar.Version)
	}
	if bar.RationaleDoc == "" {
		t.Error("rationale_doc is empty; the bar must be auditable (D-02)")
	}

	want := map[string]bool{
		"crypto": false, "source_layer": false, "storage": false,
		"binary_surface": false, "api": false,
	}
	for _, p := range bar.PerDim {
		if _, ok := want[p.ID]; ok {
			want[p.ID] = true
		}
		if p.Floor <= 0 || p.Floor > 100 {
			t.Errorf("dim %q floor = %d, want 1..100", p.ID, p.Floor)
		}
		if p.Justification == "" {
			t.Errorf("dim %q has empty justification (fabrication-by-baseline guard, D-02)", p.ID)
		}
		if p.EvidenceRef == "" {
			t.Errorf("dim %q has empty evidence_ref (T-84-03 auditability)", p.ID)
		}
	}
	for id, present := range want {
		if !present {
			t.Errorf("required dim %q missing from per_dim", id)
		}
	}

	if bar.CorpusGate.MinPassApps != 7 || bar.CorpusGate.Of != 10 {
		t.Errorf("corpus_gate = %d of %d, want 7 of 10 (D-06)",
			bar.CorpusGate.MinPassApps, bar.CorpusGate.Of)
	}
	if bar.CorpusGate.Metric == "" {
		t.Error("corpus_gate.metric is empty")
	}
}

// TestKBMaturityBar_NoFabricationFloors asserts each floor is a deliberate
// target (>0, <=100), every floor is strictly above the current SHALLOW
// WhatsApp sidecar score for that dim (no fabrication-by-baseline, D-02 /
// threat T-84-01), and that the bar is the SEPARATE artifact — its path is
// testdata/maturity_bar_v1.json, never expected_score_w13_final.json (D-01).
func TestKBMaturityBar_NoFabricationFloors(t *testing.T) {
	bar := loadMaturityBar(t)

	// Current shallow real-signal WhatsApp scores (84-CONTEXT evidence
	// baseline). A floor equal to any of these would be
	// fabrication-by-baseline (D-02, T-84-01).
	currentShallow := map[string]int{
		"crypto": 0, "source_layer": 30, "storage": 25,
		"binary_surface": 73, "api": 75,
	}
	for _, p := range bar.PerDim {
		if p.Floor <= 0 || p.Floor > 100 {
			t.Errorf("dim %q floor = %d not a deliberate 1..100 target", p.ID, p.Floor)
		}
		if cur, ok := currentShallow[p.ID]; ok && p.Floor <= cur {
			t.Errorf("dim %q floor = %d <= current shallow score %d: fabrication-by-baseline (D-02)",
				p.ID, p.Floor, cur)
		}
	}

	if filepath.Base(maturityBarPath) != "maturity_bar_v1.json" {
		t.Fatalf("maturity bar path = %q, must be the separate artifact (D-01)", maturityBarPath)
	}
	if _, err := os.Stat("testdata/expected_score_w13_final.json"); err != nil {
		t.Fatalf("VALD-02 fixture must still exist untouched: %v", err)
	}
}
