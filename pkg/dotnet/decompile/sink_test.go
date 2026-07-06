/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr"
)

type capSink struct{ got []clr.TypeModule }

func (s *capSink) EmitModule(m clr.TypeModule) error { s.got = append(s.got, m); return nil }

func TestRun_FullApp_RequiresSink(t *testing.T) {
	dir := t.TempDir()
	synthManagedAssembly(t, filepath.Join(dir, "A.dll"))
	d, _ := NewWithEngine(EngineNative)

	_, err := d.Run(context.Background(), Options{
		Input: dir, Output: filepath.Join(dir, "out"), Mode: ModeFullApp,
	})
	if !errors.Is(err, ErrSinkRequired) {
		t.Fatalf("FullApp without Sink err = %v, want ErrSinkRequired", err)
	}
}

func TestRun_FullApp_StreamsToSink(t *testing.T) {
	dir := t.TempDir()
	synthManagedAssembly(t, filepath.Join(dir, "A.dll"))
	d, _ := NewWithEngine(EngineNative)
	sink := &capSink{}

	res, err := d.Run(context.Background(), Options{
		Input: dir, Output: filepath.Join(dir, "out"), Mode: ModeFullApp, Sink: sink,
	})
	if err != nil {
		t.Fatalf("Run FullApp w/ sink: %v", err)
	}
	if len(sink.got) == 0 {
		t.Fatal("sink received no modules")
	}
	// FullApp must NOT buffer modules in-memory.
	for _, ar := range res.Assemblies {
		if ar.Modules != nil {
			t.Errorf("FullApp buffered %d modules in AssemblyResult; must stream", len(ar.Modules))
		}
	}
}

func TestRun_Single_BuffersUnderCap(t *testing.T) {
	dir := t.TempDir()
	synthManagedAssembly(t, filepath.Join(dir, "A.dll"))
	d, _ := NewWithEngine(EngineNative)

	res, err := d.Run(context.Background(), Options{
		Input: filepath.Join(dir, "A.dll"), Output: filepath.Join(dir, "out"), Mode: ModeSingle,
	})
	if err != nil {
		t.Fatalf("Run single: %v", err)
	}
	if res.Assemblies[0].Modules == nil {
		t.Error("ModeSingle should buffer modules for CLI callers")
	}
}

func TestRun_Single_OverCap_Errors(t *testing.T) {
	// A synthetic assembly whose type count exceeds MaxSingleBufferModules
	// must fail loudly rather than OOM-buffer.
	dir := t.TempDir()
	synthManyTypeAssembly(t, filepath.Join(dir, "Big.dll"), MaxSingleBufferModules+1)
	d, _ := NewWithEngine(EngineNative)

	_, err := d.Run(context.Background(), Options{
		Input: filepath.Join(dir, "Big.dll"), Output: filepath.Join(dir, "out"), Mode: ModeSingle,
	})
	if !errors.Is(err, ErrSingleBufferCap) {
		t.Fatalf("over-cap single err = %v, want ErrSingleBufferCap", err)
	}
}
