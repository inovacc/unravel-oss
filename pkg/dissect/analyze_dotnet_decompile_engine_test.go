package dissect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/decompile"
)

// TestDotNetCapture_NativeNonEmpty proves the native capture path can never
// silently produce a zero-module KB epoch from a managed PE: a synthesized
// one-type assembly must yield >=1 module via the native engine.
func TestDotNetCapture_NativeNonEmpty(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "Sample.dll")
	synthManagedAssemblyForDissect(t, asm) // clrgen-backed; >=1 type

	d, err := decompile.NewWithEngine(decompile.EngineNative)
	if err != nil {
		t.Fatalf("native New: %v", err)
	}
	res, err := d.Run(context.Background(), decompile.Options{
		Input: asm, Output: filepath.Join(dir, "out"), Mode: decompile.ModeSingle,
	})
	if err != nil {
		t.Fatalf("native run: %v", err)
	}
	total := 0
	for _, ar := range res.Assemblies {
		total += ar.ModuleCount
	}
	if total == 0 {
		t.Fatal("native capture produced zero modules — silent-empty regression")
	}
}

// The supplemental must construct its decompiler via NewWithEngine(EngineILSpy),
// not the engine-default New(). Guard against a silent native swap that would
// starve the AI-beautify supplemental of raw .cs.
func TestDotNetSupplemental_UsesILSpyEngine(t *testing.T) {
	src := readSource(t, "analyze_dotnet_decompile.go")
	if strings.Contains(src, "decompile.New()") {
		t.Fatal("supplemental must call NewWithEngine(EngineILSpy), not New()")
	}
	if !strings.Contains(src, "decompile.NewWithEngine(decompile.EngineILSpy)") {
		t.Fatal("supplemental must pin EngineILSpy for the beautify path")
	}
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
