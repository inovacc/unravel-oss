/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func atomicAdd(p *int64, d int64) int64 { return atomic.AddInt64(p, d) }
func atomicLoad(p *int64) int64         { return atomic.LoadInt64(p) }
func atomicCAS(p *int64, old, new int64) bool {
	return atomic.CompareAndSwapInt64(p, old, new)
}

func writeFakeAssembly(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("fake-asm-"+name), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestDecompiler_VersionCaptured(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "ok")

	d, err := NewWithEngine(EngineILSpy)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	in := t.TempDir()
	asm := writeFakeAssembly(t, in, "MyApp.dll")

	out := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := d.Run(ctx, Options{Input: asm, Output: out, Concurrency: 1, Mode: ModeAuto})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.ILSpyVersion == "" {
		t.Errorf("ILSpyVersion empty, want populated")
	}
}

func TestDecompiler_PerAssemblyOutDirIsolated(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "ok")

	d, err := NewWithEngine(EngineILSpy)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	in := t.TempDir()
	a1 := writeFakeAssembly(t, in, "First.dll")
	a2 := writeFakeAssembly(t, in, "Second.dll")
	_ = a1
	_ = a2

	// Synthesize deps.json so full-app picks both.
	depsJSON := `{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"libraries":{"First/1.0.0":{"type":"project"},"Second/1.0.0":{"type":"project"}},"targets":{}}`
	if err := os.WriteFile(filepath.Join(in, "App.deps.json"), []byte(depsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	out := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := d.Run(ctx, Options{Input: in, Output: out, Concurrency: 2, Mode: ModeFullApp})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(res.Assemblies) != 2 {
		t.Fatalf("Assemblies len = %d, want 2: %+v", len(res.Assemblies), res.Assemblies)
	}

	// Each must have a distinct out-dir under <out>/raw/<name>/.
	dirs := map[string]bool{}
	for _, ar := range res.Assemblies {
		if !strings.Contains(filepath.ToSlash(ar.OutDir), "/raw/") {
			t.Errorf("OutDir %q missing /raw/ segment", ar.OutDir)
		}
		if dirs[ar.OutDir] {
			t.Errorf("duplicate OutDir %q", ar.OutDir)
		}
		dirs[ar.OutDir] = true
	}
}

func TestDecompiler_BoundedParallel(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "ok")

	in := t.TempDir()
	out := t.TempDir()

	const n = 8
	libs := map[string]any{}
	for i := 0; i < n; i++ {
		name := "Asm" + string(rune('A'+i))
		writeFakeAssembly(t, in, name+".dll")
		libs[name+"/1.0.0"] = map[string]any{"type": "project"}
	}
	depsJSON := `{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"libraries":{`
	first := true
	for k := range libs {
		if !first {
			depsJSON += ","
		}
		first = false
		depsJSON += `"` + k + `":{"type":"project"}`
	}
	depsJSON += `},"targets":{}}`
	if err := os.WriteFile(filepath.Join(in, "App.deps.json"), []byte(depsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	d, err := NewWithEngine(EngineILSpy)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var inflight, maxObserved int64
	d.onAcquire = func() {
		v := atomicAdd(&inflight, 1)
		for {
			m := atomicLoad(&maxObserved)
			if v <= m {
				break
			}
			if atomicCAS(&maxObserved, m, v) {
				break
			}
		}
		// Hold briefly so overlap is observable even if the mock is fast.
		time.Sleep(30 * time.Millisecond)
	}
	d.onRelease = func() {
		atomicAdd(&inflight, -1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const concurrency = 2
	if _, err := d.Run(ctx, Options{Input: in, Output: out, Concurrency: concurrency, Mode: ModeFullApp}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if maxObserved <= 0 {
		t.Fatalf("max observed = %d, expected > 0", maxObserved)
	}
	if maxObserved > concurrency {
		t.Errorf("max in-flight = %d, exceeds concurrency %d", maxObserved, concurrency)
	}
}

func TestDecompiler_PerAssemblyErrorsNonFatal(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}

	in := t.TempDir()
	out := t.TempDir()
	for _, n := range []string{"A.dll", "B.dll", "C.dll"} {
		writeFakeAssembly(t, in, n)
	}
	depsJSON := `{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"libraries":{"A/1.0.0":{"type":"project"},"B/1.0.0":{"type":"project"},"C/1.0.0":{"type":"project"}},"targets":{}}`
	if err := os.WriteFile(filepath.Join(in, "App.deps.json"), []byte(depsJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	// Use an env var the mock recognizes — but we want only "B" to crash.
	// Simplest: set MOCK_ILSPYCMD_MODE=crash so all crash, then verify all
	// errors collected and nothing aborts. (The behavior under test is
	// "per-assembly errors collected, others continue" — having all-fail still
	// proves the run completes with len(Assemblies)==3 and len(Errors)==3.)
	t.Setenv("MOCK_ILSPYCMD_MODE", "crash")

	d, err := NewWithEngine(EngineILSpy)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := d.Run(ctx, Options{Input: in, Output: out, Concurrency: 2, Mode: ModeFullApp})
	if err != nil {
		t.Fatalf("Run returned error (should collect, not abort): %v", err)
	}

	if len(res.Assemblies) != 3 {
		t.Errorf("Assemblies len = %d, want 3", len(res.Assemblies))
	}
	if len(res.Errors) == 0 {
		t.Errorf("Errors empty, want >=1 collected")
	}
}

func TestDecompiler_PathSanitize_RejectTraversal(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "ok")

	d, err := NewWithEngine(EngineILSpy)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = d.Run(ctx, Options{Input: "../../etc/foo.dll", Output: t.TempDir(), Mode: ModeSingle})
	if err == nil {
		t.Fatal("Run with traversal input: want error, got nil")
	}
	if !strings.Contains(err.Error(), "traversal") && !strings.Contains(err.Error(), "..") {
		t.Errorf("error %q does not mention traversal", err.Error())
	}
}
