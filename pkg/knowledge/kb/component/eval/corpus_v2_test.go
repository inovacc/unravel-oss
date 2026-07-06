/*
Copyright (c) 2026 Security Research
*/

package eval_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/eval"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate registry for migration apply
)

func writeFixture(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func validV2() *eval.CorpusV2 {
	return &eval.CorpusV2{
		SchemaVersion: 2,
		GeneratedAt:   time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
		Source:        "test",
		Entries: []eval.CorpusEntryV2{
			{
				ID:             "bbbbbbbbbbbbbbbb",
				Name:           "B.Mod",
				Path:           "src/b.go",
				HumanLabel:     "auth",
				PredictedLabel: "auth",
				Confidence:     0.8,
				ReviewStatus:   "accepted",
			},
			{
				ID:             "aaaaaaaaaaaaaaaa",
				Name:           "A.Mod",
				Path:           "src/a.go",
				HumanLabel:     "crypto",
				PredictedLabel: "crypto",
				Confidence:     0.95,
				ReviewStatus:   "accepted",
			},
		},
	}
}

func TestLoadCorpusV2_RejectsMissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	writeFixture(t, path, `{"schema_version":2,"entries":[{"id":"x","predicted_label":"auth","confidence":0.5,"review_status":"pending"}]}`)
	if _, err := eval.LoadCorpusV2(path); err == nil {
		t.Fatalf("expected error for missing name/human_label")
	}
}

func TestLoadCorpusV2_RejectsSchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	writeFixture(t, path, `{"schema_version":1,"entries":[]}`)
	_, err := eval.LoadCorpusV2(path)
	if err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("expected schema mismatch error, got %v", err)
	}
}

func TestLoadCorpusV2_RejectsConfidenceOutOfRange(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
	}{
		{"negative", `{"schema_version":2,"entries":[{"id":"x","name":"n","path":"p","human_label":"auth","predicted_label":"auth","confidence":-0.5,"review_status":"pending"}]}`},
		{"over_one", `{"schema_version":2,"entries":[{"id":"x","name":"n","path":"p","human_label":"auth","predicted_label":"auth","confidence":1.5,"review_status":"pending"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			writeFixture(t, path, tc.body)
			if _, err := eval.LoadCorpusV2(path); err == nil {
				t.Fatalf("expected confidence error")
			}
		})
	}
}

func TestWriteCorpusV2_Canonicalizes(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "1.json")
	p2 := filepath.Join(dir, "2.json")

	c := validV2()
	if err := eval.WriteCorpusV2(p1, c); err != nil {
		t.Fatalf("write1: %v", err)
	}
	if err := eval.WriteCorpusV2(p2, c); err != nil {
		t.Fatalf("write2: %v", err)
	}
	b1, _ := os.ReadFile(p1)
	b2, _ := os.ReadFile(p2)
	if string(b1) != string(b2) {
		t.Fatalf("non-canonical: outputs differ")
	}
}

func TestWriteCorpusV2_SortsEntriesByID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	c := validV2() // entries: B then A
	if err := eval.WriteCorpusV2(p, c); err != nil {
		t.Fatalf("write: %v", err)
	}
	loaded, err := eval.LoadCorpusV2(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Entries[0].ID >= loaded.Entries[1].ID {
		t.Fatalf("entries not sorted: %s >= %s", loaded.Entries[0].ID, loaded.Entries[1].ID)
	}
}

func TestRoundtrip_WriteThenLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	in := validV2()
	if err := eval.WriteCorpusV2(p, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := eval.LoadCorpusV2(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if out.SchemaVersion != 2 || len(out.Entries) != 2 {
		t.Fatalf("roundtrip mismatch: %+v", out)
	}
	for _, e := range out.Entries {
		if e.HumanLabel == "" || e.PredictedLabel == "" {
			t.Fatalf("field lost: %+v", e)
		}
	}
}

func TestRoundtrip_StableTimestamps(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	in := validV2()
	in.GeneratedAt = time.Date(2026, 5, 4, 12, 34, 56, 999999999, time.UTC)
	if err := eval.WriteCorpusV2(p, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := eval.LoadCorpusV2(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := in.GeneratedAt.UTC().Round(time.Second)
	if !out.GeneratedAt.Equal(want) {
		t.Fatalf("timestamp drift: got %v want %v", out.GeneratedAt, want)
	}
}

func TestMigrateCorpusV1ToV2(t *testing.T) {
	dir := t.TempDir()
	v1Path := filepath.Join(dir, "v1.json")
	v2Path := filepath.Join(dir, "v2.json")
	v1 := eval.Corpus{
		Version: 1,
		Modules: []eval.LabeledModule{
			{Name: "A.Auth", Path: "src/auth/a.cs", SymbolsJSON: "[\"jwt\",\"oauth\"]", ExpectedComponent: "auth", Notes: "test"},
			{Name: "B.Crypto", Path: "src/crypto/b.cs", SymbolsJSON: "[\"AES\",\"sha256\"]", ExpectedComponent: "crypto"},
		},
	}
	raw, _ := json.Marshal(v1)
	if err := os.WriteFile(v1Path, raw, 0o644); err != nil {
		t.Fatalf("write v1: %v", err)
	}
	if err := eval.MigrateCorpusV1ToV2(v1Path, v2Path); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	out, err := eval.LoadCorpusV2(v2Path)
	if err != nil {
		t.Fatalf("load v2: %v", err)
	}
	if len(out.Entries) != 2 {
		t.Fatalf("entries: got %d want 2", len(out.Entries))
	}
	for _, e := range out.Entries {
		if e.ReviewStatus != "pending" {
			t.Errorf("review_status: got %q want pending", e.ReviewStatus)
		}
		if e.HumanLabel != e.ExpectedComponent {
			t.Errorf("HumanLabel != ExpectedComponent: %q vs %q", e.HumanLabel, e.ExpectedComponent)
		}
		if e.ID == "" || len(e.ID) != 16 {
			t.Errorf("ID malformed: %q", e.ID)
		}
		if e.PredictedLabel == "" {
			t.Errorf("PredictedLabel empty")
		}
	}
}
