/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/internal/ai/prompts"
)

// buildFakeRunDir creates a fake decompiler-output directory tree at
// <out>/raw/<asm>/ with the given relPath written as the file body.
// Returns the *Result fixture.
func buildFakeRunDir(t *testing.T, out, asmName, relPath, body string) *Result {
	t.Helper()
	rawAsmDir := filepath.Join(out, "raw", asmName)
	full := filepath.Join(rawAsmDir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return &Result{
		ILSpyVersion: "mock-1.0",
		StartedAt:    time.Now().UTC(),
		EndedAt:      time.Now().UTC(),
		Assemblies: []AssemblyResult{
			{
				Name:       asmName,
				Path:       asmName,
				OutDir:     rawAsmDir,
				Decompiled: true,
				FileCount:  1,
				SHA256:     "deadbeef",
			},
		},
	}
}

func TestOrchestrator_WritesParallelTrees(t *testing.T) {
	out := t.TempDir()
	dr := buildFakeRunDir(t, out, "MyApp.dll", filepath.Join("Ns", "MyClass.cs"), sampleClassesForGuard)

	o := NewOrchestrator(&fakeBeautifier{}, BeautifyOptions{AIEnabled: true, Model: "claude-sonnet"})
	rep, err := o.Run(context.Background(), dr, RunOptions{Output: out, Input: "MyApp.dll", Mode: "single", Concurrency: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.RunID == "" {
		t.Error("missing RunID")
	}

	rawFile := filepath.Join(out, "raw", "MyApp.dll", "Ns", "MyClass.cs")
	beautFile := filepath.Join(out, "beautified", "MyApp.dll", "Ns", "MyClass.cs")
	if _, err := os.Stat(rawFile); err != nil {
		t.Errorf("missing raw file: %v", err)
	}
	if _, err := os.Stat(beautFile); err != nil {
		t.Errorf("missing beautified mirror: %v", err)
	}
	t.Logf("raw=%s beautified=%s (mirrored relative path: Ns/MyClass.cs)", rawFile, beautFile)
}

func TestOrchestrator_PerAssemblyMeta(t *testing.T) {
	out := t.TempDir()
	dr := buildFakeRunDir(t, out, "MyApp.dll", "X.cs", sampleClassesForGuard)
	o := NewOrchestrator(&fakeBeautifier{}, BeautifyOptions{AIEnabled: true, Model: "m"})
	if _, err := o.Run(context.Background(), dr, RunOptions{Output: out, Concurrency: 1}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, p := range []string{
		filepath.Join(out, "raw", "MyApp.dll", "_meta.json"),
		filepath.Join(out, "beautified", "MyApp.dll", "_meta.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
}

func TestOrchestrator_RunManifest(t *testing.T) {
	out := t.TempDir()
	dr := buildFakeRunDir(t, out, "MyApp.dll", "X.cs", sampleClassesForGuard)
	o := NewOrchestrator(&fakeBeautifier{}, BeautifyOptions{AIEnabled: true, Model: "claude-sonnet"})
	if _, err := o.Run(context.Background(), dr, RunOptions{Output: out, Input: "MyApp.dll", Mode: "single"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mf := filepath.Join(out, "manifest.json")
	data, err := os.ReadFile(mf)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var gen map[string]any
	if err := json.Unmarshal(data, &gen); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if gen["ai_enabled"] != true {
		t.Error("expected ai_enabled=true")
	}
}

func TestOrchestrator_PromptHashRecorded(t *testing.T) {
	out := t.TempDir()
	dr := buildFakeRunDir(t, out, "A.dll", "X.cs", sampleClassesForGuard)
	o := NewOrchestrator(&fakeBeautifier{}, BeautifyOptions{AIEnabled: true})
	if _, err := o.Run(context.Background(), dr, RunOptions{Output: out}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(out, "manifest.json"))
	var gen map[string]any
	_ = json.Unmarshal(data, &gen)
	got := gen["prompt_hash"].(string)
	want := prompts.PromptHash("csharp")
	if got != want {
		t.Errorf("prompt_hash mismatch: got %q want %q", got, want)
	}
}

func TestOrchestrator_NoAIMode(t *testing.T) {
	out := t.TempDir()
	dr := buildFakeRunDir(t, out, "A.dll", "X.cs", sampleClassesForGuard)
	o := NewOrchestrator(nil, BeautifyOptions{AIEnabled: false})
	rep, err := o.Run(context.Background(), dr, RunOptions{Output: out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.BeautifiedTree != "" {
		t.Error("expected empty BeautifiedTree when AIEnabled=false")
	}
	if _, err := os.Stat(filepath.Join(out, "raw", "A.dll", "_meta.json")); err != nil {
		t.Errorf("missing raw _meta.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "beautified")); err == nil {
		t.Error("expected no beautified tree when AIEnabled=false")
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Errorf("manifest.json missing: %v", err)
	}
	// Verify manifest has ai_enabled=false.
	data, _ := os.ReadFile(filepath.Join(out, "manifest.json"))
	var gen map[string]any
	_ = json.Unmarshal(data, &gen)
	if gen["ai_enabled"] != false {
		t.Error("expected ai_enabled=false in manifest")
	}
}

func TestOrchestrator_PerFileError_NotFatal(t *testing.T) {
	out := t.TempDir()
	// Simple file; AI errors out.
	dr := buildFakeRunDir(t, out, "A.dll", "X.cs", "namespace N { public class A { void M() { } } }\n")

	// Beautifier that always errors.
	b := &fakeBeautifier{transform: func(in string) (string, error) {
		return "", errSentinel
	}}
	o := NewOrchestrator(b, BeautifyOptions{AIEnabled: true})
	rep, err := o.Run(context.Background(), dr, RunOptions{Output: out})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep == nil {
		t.Fatal("nil report")
	}
	// run completes — no fatal; per-file error recorded in beautified
	// tree's _meta.json.
}

var errSentinel = stubError("ai unavailable")

type stubError string

func (s stubError) Error() string { return string(s) }
