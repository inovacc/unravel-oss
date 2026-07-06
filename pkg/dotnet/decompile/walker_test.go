/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWalker_SingleFile(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "MyApp.dll")
	if err := os.WriteFile(asm, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := WalkSingle(asm)
	if err != nil {
		t.Fatalf("WalkSingle: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}

	if got[0].Name != "MyApp.dll" {
		t.Errorf("Name = %q, want MyApp.dll", got[0].Name)
	}

	if !got[0].FirstParty {
		t.Errorf("FirstParty = false, want true")
	}
}

func TestWalker_FullApp_FiltersFramework(t *testing.T) {
	dir := t.TempDir()

	// Create three fake assemblies.
	for _, name := range []string{"MyApp.dll", "Microsoft.Extensions.Logging.dll", "System.Text.Json.dll"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Synthesize a deps.json referencing all three by library key.
	deps := map[string]any{
		"runtimeTarget": map[string]any{"name": ".NETCoreApp,Version=v8.0"},
		"libraries": map[string]any{
			"MyApp/1.0.0":                        map[string]any{"type": "project"},
			"Microsoft.Extensions.Logging/8.0.0": map[string]any{"type": "package"},
			"System.Text.Json/8.0.0":             map[string]any{"type": "package"},
		},
		"targets": map[string]any{},
	}

	depsBytes, _ := json.Marshal(deps)
	depsPath := filepath.Join(dir, "MyApp.deps.json")
	if err := os.WriteFile(depsPath, depsBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("excludes framework by default", func(t *testing.T) {
		got, err := WalkFullApp(dir, false)
		if err != nil {
			t.Fatalf("WalkFullApp: %v", err)
		}

		names := namesOf(got)
		if !contains(names, "MyApp.dll") {
			t.Errorf("missing MyApp.dll in %v", names)
		}
		if contains(names, "Microsoft.Extensions.Logging.dll") {
			t.Errorf("framework Microsoft.* not filtered out: %v", names)
		}
		if contains(names, "System.Text.Json.dll") {
			t.Errorf("framework System.* not filtered out: %v", names)
		}
	})

	t.Run("includes framework when requested", func(t *testing.T) {
		got, err := WalkFullApp(dir, true)
		if err != nil {
			t.Fatalf("WalkFullApp: %v", err)
		}

		names := namesOf(got)
		want := []string{"MyApp.dll", "Microsoft.Extensions.Logging.dll", "System.Text.Json.dll"}
		for _, w := range want {
			if !contains(names, w) {
				t.Errorf("missing %q in %v", w, names)
			}
		}
	})
}

func TestWalker_AdversarialName_Rejected(t *testing.T) {
	dir := t.TempDir()
	deps := map[string]any{
		"runtimeTarget": map[string]any{"name": ".NETCoreApp,Version=v8.0"},
		"libraries": map[string]any{
			"../../escape/1.0.0": map[string]any{"type": "project"},
		},
		"targets": map[string]any{},
	}
	depsBytes, _ := json.Marshal(deps)
	if err := os.WriteFile(filepath.Join(dir, "X.deps.json"), depsBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := WalkFullApp(dir, false)
	// Either an error is returned, or the malicious entry is silently dropped.
	// We accept both outcomes — but the key invariant is that nothing escapes
	// dir.
	if err != nil {
		if !strings.Contains(err.Error(), "traversal") && !strings.Contains(err.Error(), "..") {
			t.Logf("WalkFullApp returned non-traversal error: %v", err)
		}
		return
	}
	for _, a := range got {
		if strings.Contains(a.Name, "..") || strings.Contains(a.Path, "..") {
			t.Errorf("adversarial name leaked into walker output: %+v", a)
		}
	}
}

func TestPathSanitize_RejectTraversal(t *testing.T) {
	tests := []struct {
		name    string
		root    string
		path    string
		wantErr bool
	}{
		{"reject ..", "", "../../etc", true},
		{"reject embedded ..", "", "foo/../../bar", true},
		{"accept clean", "", "foo/bar", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sanitizeOutPath(tt.root, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeOutPath(%q, %q) err=%v wantErr=%v", tt.root, tt.path, err, tt.wantErr)
			}
		})
	}
}

func namesOf(asms []Assembly) []string {
	out := make([]string, len(asms))
	for i, a := range asms {
		out[i] = a.Name
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
