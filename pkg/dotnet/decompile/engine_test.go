/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"errors"
	"testing"
)

func TestNew_DefaultsToNativeEngine(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("New() native must never fail on a clean box: %v", err)
	}
	if d.Engine() != EngineNative {
		t.Fatalf("New() engine = %v, want EngineNative", d.Engine())
	}
}

func TestNewWithEngine(t *testing.T) {
	tests := []struct {
		name      string
		engine    Engine
		wantEng   Engine
		wantErrIs error // nil = no assertion (ilspy may or may not be installed)
	}{
		{"native", EngineNative, EngineNative, nil},
		{"ilspy", EngineILSpy, EngineILSpy, nil},
		{"unknown", Engine(99), 0, ErrUnknownEngine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewWithEngine(tt.engine)
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("err = %v, want errors.Is %v", err, tt.wantErrIs)
				}
				return
			}
			if tt.engine == EngineILSpy && err != nil {
				t.Skipf("ilspycmd absent (expected install-hint): %v", err)
			}
			if err != nil {
				t.Fatalf("NewWithEngine(%v): %v", tt.engine, err)
			}
			if d.Engine() != tt.wantEng {
				t.Fatalf("engine = %v, want %v", d.Engine(), tt.wantEng)
			}
		})
	}
}
