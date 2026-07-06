package archive

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Test: New + Option functions
// ---------------------------------------------------------------------------

func TestNew_Defaults(t *testing.T) {
	e := New(slog.Default())
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.logger == nil {
		t.Error("logger should not be nil")
	}
	if e.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if e.maxNestedDepth != 2 {
		t.Errorf("maxNestedDepth = %d, want 2", e.maxNestedDepth)
	}
	// native decompiler enabled by default
	if !e.useNativeDecompiler {
		t.Error("useNativeDecompiler should default to true")
	}
}

func TestNew_WithDecompiler(t *testing.T) {
	e := New(slog.Default(), WithDecompiler("/path/to/cfr.jar"))
	if e.decompilerPath != "/path/to/cfr.jar" {
		t.Errorf("decompilerPath = %q, want /path/to/cfr.jar", e.decompilerPath)
	}
}

func TestNew_WithNativeDecompiler(t *testing.T) {
	// Start with native disabled, then enable
	e := &Extractor{useNativeDecompiler: false}
	WithNativeDecompiler()(e)
	if !e.useNativeDecompiler {
		t.Error("WithNativeDecompiler should set useNativeDecompiler=true")
	}
}

func TestNew_MultipleOptions(t *testing.T) {
	e := New(slog.Default(),
		WithDecompiler("/tools/cfr.jar"),
		WithNativeDecompiler(),
	)
	if e.decompilerPath != "/tools/cfr.jar" {
		t.Errorf("decompilerPath = %q, want /tools/cfr.jar", e.decompilerPath)
	}
	if !e.useNativeDecompiler {
		t.Error("useNativeDecompiler should be true")
	}
}

// ---------------------------------------------------------------------------
// Test: ArchiveInfo.Cleanup
// ---------------------------------------------------------------------------

func TestArchiveInfo_Cleanup_RemovesDir(t *testing.T) {
	dir := t.TempDir()
	// Create a sub-file to ensure the dir isn't already empty
	f := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	info := &ArchiveInfo{ExtractDir: dir}
	if err := info.Cleanup(); err != nil {
		t.Fatalf("Cleanup error: %v", err)
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("expected ExtractDir to be removed after Cleanup")
	}
}

func TestArchiveInfo_Cleanup_EmptyExtractDir(t *testing.T) {
	info := &ArchiveInfo{ExtractDir: ""}
	// Should return nil without error
	if err := info.Cleanup(); err != nil {
		t.Errorf("Cleanup with empty ExtractDir returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: splitClassPath
// ---------------------------------------------------------------------------

func TestSplitClassPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "space separated",
			input: "lib/a.jar lib/b.jar lib/c.jar",
			want:  []string{"lib/a.jar", "lib/b.jar", "lib/c.jar"},
		},
		{
			name:  "single entry",
			input: "lib/only.jar",
			want:  []string{"lib/only.jar"},
		},
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "extra spaces",
			input: "  lib/a.jar   lib/b.jar  ",
			want:  []string{"lib/a.jar", "lib/b.jar"},
		},
		{
			name:  "tabs and spaces",
			input: "lib/a.jar\tlib/b.jar",
			want:  []string{"lib/a.jar", "lib/b.jar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitClassPath(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("splitClassPath(%q) = %v (len %d), want %v (len %d)",
					tt.input, got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitClassPath[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: FindDecompiler — no decompiler configured returns ""
// ---------------------------------------------------------------------------

func TestFindDecompiler_NoneConfigured(t *testing.T) {
	// Use a fresh extractor with no decompiler path set.
	// Neither tools/cfr.jar nor cache entries exist in test environment.
	e := New(slog.Default())
	// We cannot assert empty (CI might have cfr.jar), but we can call without panic.
	_ = e.FindDecompiler()
}

func TestFindDecompiler_WithExplicitPath(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "cfr.jar")
	if err := os.WriteFile(jar, []byte("fake jar"), 0o644); err != nil {
		t.Fatalf("write fake jar: %v", err)
	}

	e := New(slog.Default(), WithDecompiler(jar))
	got := e.FindDecompiler()
	if got != jar {
		t.Errorf("FindDecompiler = %q, want %q", got, jar)
	}
}

func TestFindDecompiler_NonexistentExplicitPath(t *testing.T) {
	e := New(slog.Default(), WithDecompiler("/no/such/cfr.jar"))
	got := e.FindDecompiler()
	// Should fall through to next strategies; exact result doesn't matter
	// but we want to confirm no panic and that the explicit path is NOT returned
	// since it doesn't exist on disk.
	if got == "/no/such/cfr.jar" {
		t.Error("FindDecompiler should not return non-existent explicit path")
	}
}
