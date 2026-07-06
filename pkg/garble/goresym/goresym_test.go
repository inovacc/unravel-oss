package goresym_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
)

// ---------------------------------------------------------------------------
// Recover — error-path table tests
// ---------------------------------------------------------------------------

func TestRecover_EmptyPath(t *testing.T) {
	_, err := goresym.Recover(context.Background(), "", goresym.Options{})
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
}

func TestRecover_EmptyPath_ErrorMessage(t *testing.T) {
	_, err := goresym.Recover(context.Background(), "", goresym.Options{})
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	const want = "goresym: path is required"
	if err.Error() != want {
		t.Errorf("error message = %q, want %q", err.Error(), want)
	}
}

// ---------------------------------------------------------------------------
// ErrNotImplemented sentinel identity
// ---------------------------------------------------------------------------

func TestErrNotImplemented_Identity(t *testing.T) {
	if goresym.ErrNotImplemented == nil {
		t.Fatal("ErrNotImplemented must not be nil")
	}
	// Must satisfy errors.Is with itself (standard sentinel behaviour).
	if !errors.Is(goresym.ErrNotImplemented, goresym.ErrNotImplemented) {
		t.Error("errors.Is(ErrNotImplemented, ErrNotImplemented) should be true")
	}
}

func TestErrNotImplemented_Message(t *testing.T) {
	msg := goresym.ErrNotImplemented.Error()
	if msg == "" {
		t.Error("ErrNotImplemented.Error() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// Type construction and JSON round-trip
// ---------------------------------------------------------------------------

func TestSymbol_ZeroValue(t *testing.T) {
	var s goresym.Symbol
	if s.Name != "" || s.Address != 0 || s.Type != "" {
		t.Errorf("unexpected zero value: %+v", s)
	}
}

func TestSymbol_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		symbol goresym.Symbol
	}{
		{
			name:   "full symbol",
			symbol: goresym.Symbol{Name: "main.main", Address: 0x401000, Type: "func()"},
		},
		{
			name:   "symbol without type (omitempty)",
			symbol: goresym.Symbol{Name: "runtime.goexit", Address: 0x402000},
		},
		{
			name:   "zero-address symbol",
			symbol: goresym.Symbol{Name: "init", Address: 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.symbol)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			var got goresym.Symbol
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if got.Name != tc.symbol.Name {
				t.Errorf("Name: got %q, want %q", got.Name, tc.symbol.Name)
			}
			if got.Address != tc.symbol.Address {
				t.Errorf("Address: got %d, want %d", got.Address, tc.symbol.Address)
			}
			if got.Type != tc.symbol.Type {
				t.Errorf("Type: got %q, want %q", got.Type, tc.symbol.Type)
			}
		})
	}
}

func TestSymbol_TypeOmitEmpty(t *testing.T) {
	s := goresym.Symbol{Name: "foo", Address: 1}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	// "type" field must be absent when empty.
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := m["type"]; ok {
		t.Error("expected 'type' key to be omitted when empty")
	}
}

func TestResult_ZeroValue(t *testing.T) {
	var r goresym.Result
	if r.BuildID != "" || r.GoVersion != "" || r.ModulePath != "" {
		t.Errorf("unexpected non-empty string fields: %+v", r)
	}
	if r.Symbols != nil {
		t.Error("expected Symbols to be nil in zero value")
	}
	if r.Types != nil {
		t.Error("expected Types to be nil in zero value")
	}
}

func TestResult_JSONRoundTrip(t *testing.T) {
	original := goresym.Result{
		BuildID:    "abc123",
		GoVersion:  "go1.21.0",
		ModulePath: "github.com/example/app",
		Symbols: []goresym.Symbol{
			{Name: "main.run", Address: 0x401000, Type: "func() error"},
		},
		Types: []string{"main.Config", "main.Server"},
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var got goresym.Result
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got.BuildID != original.BuildID {
		t.Errorf("BuildID: got %q, want %q", got.BuildID, original.BuildID)
	}
	if got.GoVersion != original.GoVersion {
		t.Errorf("GoVersion: got %q, want %q", got.GoVersion, original.GoVersion)
	}
	if got.ModulePath != original.ModulePath {
		t.Errorf("ModulePath: got %q, want %q", got.ModulePath, original.ModulePath)
	}
	if len(got.Symbols) != len(original.Symbols) {
		t.Fatalf("Symbols len: got %d, want %d", len(got.Symbols), len(original.Symbols))
	}
	if got.Symbols[0].Name != original.Symbols[0].Name {
		t.Errorf("Symbols[0].Name: got %q, want %q", got.Symbols[0].Name, original.Symbols[0].Name)
	}
	if len(got.Types) != len(original.Types) {
		t.Fatalf("Types len: got %d, want %d", len(got.Types), len(original.Types))
	}
}

func TestResult_OmitEmptyFields(t *testing.T) {
	r := goresym.Result{GoVersion: "go1.20"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"build_id", "module_path", "symbols", "types"} {
		if _, ok := m[key]; ok {
			t.Errorf("expected key %q to be omitted when empty", key)
		}
	}
	if _, ok := m["go_version"]; !ok {
		t.Error("expected 'go_version' key to be present")
	}
}

func TestOptions_Defaults(t *testing.T) {
	var o goresym.Options
	if o.Backend != "" {
		t.Errorf("expected empty Backend default, got %q", o.Backend)
	}
	if o.IncludeStdLib {
		t.Error("expected IncludeStdLib to default to false")
	}
}
