/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRun_NativeEngine_FillsResult(t *testing.T) {
	// synthManagedAssembly writes a minimal managed PE; the clr group's
	// ExtractModules tolerates the tiny-but-valid metadata fixture (see
	// clrgen). Here we only assert wiring: native Run produces a Result with
	// the ilspy version field empty and an AssemblyResult per input, Decompiled
	// set without touching any ilspy subprocess.
	dir := t.TempDir()
	asm := filepath.Join(dir, "Sample.dll")
	synthManagedAssembly(t, asm) // clrgen helper — emits 1 type, 1 method

	d, err := NewWithEngine(EngineNative)
	if err != nil {
		t.Fatalf("NewWithEngine(native): %v", err)
	}

	res, err := d.Run(context.Background(), Options{
		Input:  asm,
		Output: filepath.Join(dir, "out"),
		Mode:   ModeSingle,
	})
	if err != nil {
		t.Fatalf("Run native: %v", err)
	}
	if res.ILSpyVersion != "" {
		t.Errorf("native ILSpyVersion = %q, want empty", res.ILSpyVersion)
	}
	if len(res.Assemblies) != 1 {
		t.Fatalf("Assemblies = %d, want 1", len(res.Assemblies))
	}
	ar := res.Assemblies[0]
	if !ar.Decompiled {
		t.Errorf("AssemblyResult.Decompiled = false, want true")
	}
	if ar.Name == "" || ar.SHA256 == "" {
		t.Errorf("AssemblyResult name/sha not filled: %+v", ar)
	}
	if ar.ModuleCount < 1 {
		t.Errorf("ModuleCount = %d, want >=1", ar.ModuleCount)
	}
}
