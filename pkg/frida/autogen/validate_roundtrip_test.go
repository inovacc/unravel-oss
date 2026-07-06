/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/frida"
)

// TestValidateRoundtrip generates from the combined report, picks one
// criteria.json, synthesizes a tiny capture file, and runs frida.Validate
// to confirm the criteria schema round-trips through the canonical
// validator (ROADMAP Phase 26 success criterion #4).
func TestValidateRoundtrip(t *testing.T) {
	report := loadReport(t, filepath.Join("testdata", "combined-seamreport.json"))
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "scripts")
	res, err := Generate(report, outDir, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.Scripts) == 0 {
		t.Fatal("no scripts produced")
	}
	first := res.Scripts[0]
	// Fabricate a capture file matching the RunResult-shape that validate
	// auto-detects. Output must be a list of strings; one starts with the
	// canonical [FRIDA-EVENT] prefix and contains seam_id matching the hook.
	capture := map[string]any{
		"script_name": filepath.Base(first.ScriptPath),
		"output": []string{
			"[FRIDA-EVENT] {\"type\":\"hook_loaded\",\"seam_id\":\"" + first.SeamID + "\"}",
		},
	}
	capBytes, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(tmp, "capture.json")
	if err := os.WriteFile(capPath, capBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	report2, err := frida.Validate(first.CriteriaPath, capPath)
	if err != nil {
		t.Fatalf("frida.Validate failed to load criteria — round-trip broken: %v", err)
	}
	if report2 == nil {
		t.Fatal("nil ValidationReport")
	}
	if report2.Summary.Total < 1 {
		t.Errorf("summary.total = %d; want >= 1 (at least one criterion evaluated)", report2.Summary.Total)
	}
}
