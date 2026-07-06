/*
Copyright (c) 2026 Security Research

Unit-level tests for ingest.Run helpers that don't need a real
*sql.DB. Integration coverage (full 9-step transaction, idempotency,
two-epoch diff, concurrent allocation, module_components boundary)
lives in ingest_integration_test.go under //go:build integration.
*/

package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResultJSONRoundtrip(t *testing.T) {
	score := 72
	in := Result{
		KBID:           "abc123",
		KSID:           "abc123:1.0:42",
		Epoch:          int64(2),
		RiskScore:      &score,
		RiskLevel:      "high",
		Framework:      "uwp",
		DepthScore:     58,
		DepthCovered:   []string{"identity", "framework"},
		DepthMissing:   []string{"webview"},
		ModulesIndexed: 100,
		BodiesIndexed:  87,
		DiffsWritten:   3,
		BinarySHA256:   "deadbeef",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"epoch":2`) {
		t.Errorf("epoch json key missing or wrong: got=%s", string(b))
	}

	var out Result
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Epoch != int64(2) {
		t.Errorf("epoch: got=%d want=2", out.Epoch)
	}
	if out.RiskScore == nil || *out.RiskScore != 72 {
		t.Errorf("risk score: got=%v want=72", out.RiskScore)
	}
}

func TestReadBinarySHA256_PicksTopLevelExe(t *testing.T) {
	tmp := t.TempDir()
	content := []byte("MZ-fake-binary")
	if err := os.WriteFile(filepath.Join(tmp, "binary.exe"), content, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	sha, err := readBinarySHA256(tmp)
	if err != nil {
		t.Fatalf("readBinarySHA256: %v", err)
	}
	expected := sha256.Sum256(content)
	want := hex.EncodeToString(expected[:])
	if sha != want {
		t.Errorf("sha: got=%s want=%s", sha, want)
	}
}

func TestReadBinarySHA256_NoBinaryReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "data.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	sha, err := readBinarySHA256(tmp)
	if err != nil {
		t.Fatalf("readBinarySHA256: %v", err)
	}
	if sha != "" {
		t.Errorf("sha: got=%q want=empty", sha)
	}
}

func TestLoadKnowledgeJSON_AbsentReturnsEmptyMap(t *testing.T) {
	tmp := t.TempDir()
	m := loadKnowledgeJSON(tmp)
	if m == nil {
		t.Fatal("expected non-nil map")
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got=%v", m)
	}
}

func TestLoadKnowledgeJSON_ParsesValidJSON(t *testing.T) {
	tmp := t.TempDir()
	body := []byte(`{"framework":"electron","security":{"risk_score":45}}`)
	if err := os.WriteFile(filepath.Join(tmp, "knowledge.json"), body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	m := loadKnowledgeJSON(tmp)
	if m["framework"] != "electron" {
		t.Errorf("framework: got=%v want=electron", m["framework"])
	}
}
