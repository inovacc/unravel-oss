/*
Copyright (c) 2026 Security Research

Wave 0 test for P40-01 --review-mode flag.
*/

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// minimalV1Corpus mirrors eval.Corpus shape but stays in cmd package to avoid
// import cycles for the in-process drive of runReviewMode.
type minimalV1Corpus struct {
	Version int                   `json:"version"`
	Modules []minimalV1LabeledMod `json:"modules"`
}
type minimalV1LabeledMod struct {
	Name              string `json:"name"`
	Path              string `json:"path"`
	SymbolsJSON       string `json:"symbols_json"`
	ExpectedComponent string `json:"expected_component"`
	Notes             string `json:"notes,omitempty"`
}

type minimalV2Out struct {
	SchemaVersion int                 `json:"schema_version"`
	Entries       []minimalV2OutEntry `json:"entries"`
}
type minimalV2OutEntry struct {
	ID                string  `json:"id"`
	Name              string  `json:"name"`
	ExpectedComponent string  `json:"expected_component"`
	HumanLabel        string  `json:"human_label"`
	PredictedLabel    string  `json:"predicted_label"`
	ReviewStatus      string  `json:"review_status"`
	Confidence        float64 `json:"confidence"`
}

func TestReviewMode_ArchivesAndMigrates(t *testing.T) {
	dir := t.TempDir()
	corpusPath := filepath.Join(dir, "corpus.json")
	archivePath := filepath.Join(dir, "corpus.v1.json.archive")

	v1 := minimalV1Corpus{
		Version: 1,
		Modules: []minimalV1LabeledMod{
			{Name: "T.Auth.Login", Path: "src/auth/login.cs", SymbolsJSON: "[\"jwt\",\"oauth\"]", ExpectedComponent: "auth"},
			{Name: "T.Crypto.Aes", Path: "src/crypto/aes.cs", SymbolsJSON: "[\"AES\",\"sha256\"]", ExpectedComponent: "crypto"},
		},
	}
	raw, _ := json.MarshalIndent(v1, "", "  ")
	originalBytes := append([]byte(nil), raw...)
	if err := os.WriteFile(corpusPath, raw, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Drive runReviewMode by setting the package-level vars + invoking via cobra cmd.
	classifyReviewMode = true
	classifyOut = corpusPath
	defer func() {
		classifyReviewMode = false
		classifyOut = ""
	}()

	if err := runReviewMode(classifyCmd); err != nil {
		t.Fatalf("runReviewMode: %v", err)
	}

	// 1) archive exists with original bytes
	got, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if string(got) != string(originalBytes) {
		t.Errorf("archive content drift")
	}

	// 2) corpus.json is now schema_version 2 with all pending
	out, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read migrated: %v", err)
	}
	var v2 minimalV2Out
	if err := json.Unmarshal(out, &v2); err != nil {
		t.Fatalf("unmarshal v2: %v", err)
	}
	if v2.SchemaVersion != 2 {
		t.Errorf("schema_version: got %d want 2", v2.SchemaVersion)
	}
	if len(v2.Entries) != 2 {
		t.Fatalf("entries: got %d want 2", len(v2.Entries))
	}
	for _, e := range v2.Entries {
		if e.ReviewStatus != "pending" {
			t.Errorf("review_status %q: want pending", e.ReviewStatus)
		}
		if e.HumanLabel != e.ExpectedComponent {
			t.Errorf("HumanLabel %q != ExpectedComponent %q", e.HumanLabel, e.ExpectedComponent)
		}
		if e.ID == "" {
			t.Errorf("ID empty for %q", e.Name)
		}
	}
}
