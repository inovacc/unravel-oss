/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestProvenanceHeader_Format(t *testing.T) {
	var buf bytes.Buffer
	ts, _ := time.Parse(time.RFC3339, "2026-04-26T14:30:00Z")
	h := HeaderInput{
		ILSpyVersion:  "8.2.0.7535",
		Model:         "claude-sonnet-4",
		PromptName:    "csharp",
		PromptHash:    "a1b2c3d4abcdef00",
		RawRel:        "raw/MyApp.dll/Ns/MyClass.cs",
		BeautifiedRel: "beautified/MyApp.dll/Ns/MyClass.cs",
		Timestamp:     ts,
	}
	if err := WriteHeader(&buf, h); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	lines := strings.SplitN(buf.String(), "\n", 3)
	if len(lines) < 2 {
		t.Fatalf("expected 2+ lines, got %d", len(lines))
	}
	re1 := regexp.MustCompile(`^// unravel: ilspycmd \S+ \| \S+ \| csharp\.md@[0-9a-f]{8,} \| \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	if !re1.MatchString(lines[0]) {
		t.Errorf("line 1 mismatch: %q", lines[0])
	}
	re2 := regexp.MustCompile(`^// raw: \S+\s+beautified: \S+$`)
	if !re2.MatchString(lines[1]) {
		t.Errorf("line 2 mismatch: %q", lines[1])
	}
}

func TestProvenanceHeader_Parseable(t *testing.T) {
	var buf bytes.Buffer
	ts, _ := time.Parse(time.RFC3339, "2026-04-26T14:30:00Z")
	in := HeaderInput{
		ILSpyVersion:  "8.2.0",
		Model:         "claude-sonnet",
		PromptName:    "csharp",
		PromptHash:    "deadbeefcafe1234",
		RawRel:        "raw/A.dll/X.cs",
		BeautifiedRel: "beautified/A.dll/X.cs",
		Timestamp:     ts,
	}
	if err := WriteHeader(&buf, in); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	got, err := ParseHeader(buf.String())
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got.ILSpyVersion != in.ILSpyVersion || got.Model != in.Model {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.RawRel != in.RawRel || got.BeautifiedRel != in.BeautifiedRel {
		t.Errorf("rel paths mismatch: %+v", got)
	}
	if !got.Timestamp.Equal(in.Timestamp) {
		t.Errorf("timestamp mismatch: %v vs %v", got.Timestamp, in.Timestamp)
	}
}

func TestAssemblyMeta_Schema(t *testing.T) {
	dir := t.TempDir()
	m := AssemblyMeta{
		Assembly:           "MyApp.dll",
		SHA256:             "abc",
		ILSpyCmdVersion:    "8.2.0",
		DecompileStartedAt: time.Now().UTC(),
		DecompileEndedAt:   time.Now().UTC(),
		Files: []FileMeta{
			{Path: "Ns/X.cs", SizeRaw: 100, SizeBeautified: 120, Beautified: true, ChunkCount: 1, NameQuality: "beautified"},
		},
	}
	if err := WriteAssemblyMeta(dir, m); err != nil {
		t.Fatalf("WriteAssemblyMeta: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "_meta.json"))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var gen map[string]any
	if err := json.Unmarshal(data, &gen); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"assembly", "sha256", "ilspycmd_version", "decompile_started_at", "decompile_ended_at", "files"} {
		if _, ok := gen[key]; !ok {
			t.Errorf("missing key %q in _meta.json", key)
		}
	}
	files := gen["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("want 1 file entry, got %d", len(files))
	}
	fe := files[0].(map[string]any)
	for _, key := range []string{"path", "size_raw", "size_beautified", "beautified", "chunk_count", "name_quality"} {
		if _, ok := fe[key]; !ok {
			t.Errorf("missing file key %q", key)
		}
	}
}

func TestRunManifest_Schema(t *testing.T) {
	dir := t.TempDir()
	rm := RunManifest{
		RunID:           NewRunID(),
		StartedAt:       time.Now().UTC(),
		EndedAt:         time.Now().UTC(),
		ILSpyCmdVersion: "8.2.0",
		AIModel:         "claude-sonnet",
		PromptHash:      "hash123",
		PromptPath:      "pkg/ai/prompts/csharp.md",
		AIEnabled:       true,
		Input:           "MyApp.dll",
		InputMode:       "single",
		Concurrency:     4,
		Assemblies:      []AssemblyManifestEntry{{Name: "MyApp.dll", Decompiled: true}},
	}
	if err := WriteRunManifest(dir, rm); err != nil {
		t.Fatalf("WriteRunManifest: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	var gen map[string]any
	if err := json.Unmarshal(data, &gen); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"run_id", "started_at", "ended_at", "ilspycmd_version", "ai_model", "prompt_hash", "prompt_path", "ai_enabled", "input", "input_mode", "include_framework", "concurrency", "assemblies"} {
		if _, ok := gen[key]; !ok {
			t.Errorf("missing key %q in manifest.json", key)
		}
	}
	// run_id is UUIDv4-shaped.
	rid := gen["run_id"].(string)
	uuRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuRE.MatchString(rid) {
		t.Errorf("run_id %q not UUIDv4", rid)
	}
}

func TestProvenanceHeader_Malformed(t *testing.T) {
	if _, err := ParseHeader("not a header"); err == nil {
		t.Error("expected error on malformed header")
	}
	if _, err := ParseHeader("// unravel: garbage\n// raw: a  beautified: b"); err == nil {
		t.Error("expected error on malformed line 1")
	}
}

func TestAtomicWriteJSON_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	_ = os.WriteFile(target, []byte("{}"), 0o644)
	link := filepath.Join(dir, "_meta.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	if err := atomicWriteJSON(link, map[string]string{"x": "y"}); err == nil {
		t.Error("expected symlink rejection")
	}
}
