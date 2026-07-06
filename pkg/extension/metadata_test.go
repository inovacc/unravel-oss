/* Copyright (c) 2026 Security Research */
package extension

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNormalizeOptionalPermissions(t *testing.T) {
	tests := []struct {
		name string
		cm   ChromeManifest
		want []string
	}{
		{
			name: "returns sorted unique permissions",
			cm: ChromeManifest{
				OptPermissions: []any{"tabs", "storage", "tabs"},
			},
			want: []string{"storage", "tabs"},
		},
		{
			name: "nil optional permissions returns nil",
			cm:   ChromeManifest{},
			want: nil,
		},
		{
			name: "trims whitespace",
			cm: ChromeManifest{
				OptPermissions: []any{" bookmarks ", "  history "},
			},
			want: []string{"bookmarks", "history"},
		},
		{
			name: "skips empty strings",
			cm: ChromeManifest{
				OptPermissions: []any{"tabs", "", "  "},
			},
			want: []string{"tabs"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeOptionalPermissions(tt.cm)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("normalizeOptionalPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractBackgroundScripts(t *testing.T) {
	tests := []struct {
		name string
		cm   ChromeManifest
		want []string
	}{
		{
			name: "extracts scripts from background",
			cm: ChromeManifest{
				Background: map[string]any{
					"scripts": []any{"bg.js", "utils.js"},
				},
			},
			want: []string{"bg.js", "utils.js"},
		},
		{
			name: "nil background returns nil",
			cm:   ChromeManifest{},
			want: nil,
		},
		{
			name: "no scripts key returns nil",
			cm: ChromeManifest{
				Background: map[string]any{
					"persistent": false,
				},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBackgroundScripts(tt.cm)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractBackgroundScripts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractBackgroundServiceWorker(t *testing.T) {
	tests := []struct {
		name string
		cm   ChromeManifest
		want string
	}{
		{
			name: "extracts service worker",
			cm: ChromeManifest{
				Background: map[string]any{
					"service_worker": "sw.js",
				},
			},
			want: "sw.js",
		},
		{
			name: "nil background returns empty",
			cm:   ChromeManifest{},
			want: "",
		},
		{
			name: "no service_worker key returns empty",
			cm: ChromeManifest{
				Background: map[string]any{
					"scripts": []any{"bg.js"},
				},
			},
			want: "",
		},
		{
			name: "trims whitespace",
			cm: ChromeManifest{
				Background: map[string]any{
					"service_worker": "  worker.js  ",
				},
			},
			want: "worker.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBackgroundServiceWorker(tt.cm)
			if got != tt.want {
				t.Errorf("extractBackgroundServiceWorker() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeWebAccessibleResources(t *testing.T) {
	tests := []struct {
		name string
		raw  any
		want []string
	}{
		{
			name: "nil returns nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "V2 string list",
			raw:  []any{"page.html", "script.js"},
			want: []string{"page.html", "script.js"},
		},
		{
			name: "V3 object with resources",
			raw: []any{
				map[string]any{
					"resources": []any{"img/*.png", "styles.css"},
					"matches":   []any{"<all_urls>"},
				},
			},
			want: []string{"img/*.png", "styles.css"},
		},
		{
			name: "single string",
			raw:  "resource.js",
			want: []string{"resource.js"},
		},
		{
			name: "deduplicates and sorts",
			raw:  []any{"z.js", "a.js", "z.js"},
			want: []string{"a.js", "z.js"},
		},
		{
			name: "skips empty strings",
			raw:  []any{"valid.js", "", "  "},
			want: []string{"valid.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeWebAccessibleResources(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("normalizeWebAccessibleResources() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeExternallyConnectable(t *testing.T) {
	tests := []struct {
		name string
		raw  any
		want []string
	}{
		{
			name: "nil returns nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "non-map returns nil",
			raw:  "not a map",
			want: nil,
		},
		{
			name: "ids and matches",
			raw: map[string]any{
				"ids":     []any{"ext1", "ext2"},
				"matches": []any{"https://example.com/*"},
			},
			want: []string{"id:ext1", "id:ext2", "match:https://example.com/*"},
		},
		{
			name: "with accepts_tls_channel_id",
			raw: map[string]any{
				"accepts_tls_channel_id": true,
			},
			want: []string{"accepts_tls_channel_id:true"},
		},
		{
			name: "empty object",
			raw:  map[string]any{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeExternallyConnectable(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("normalizeExternallyConnectable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSortedKeys(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]bool
		want []string
	}{
		{"nil map", nil, nil},
		{"empty map", map[string]bool{}, nil},
		{"single key", map[string]bool{"a": true}, []string{"a"}},
		{"multiple sorted", map[string]bool{"c": true, "a": true, "b": true}, []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedKeys(tt.m)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sortedKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveLocaleMessage(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "plain string returned as-is",
			raw:  "My Extension",
			want: "My Extension",
		},
		{
			name: "non-matching token returned as-is",
			raw:  "not__MSG__format",
			want: "not__MSG__format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveLocaleMessage(tt.raw, t.TempDir(), "")
			if got != tt.want {
				t.Errorf("resolveLocaleMessage(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestResolveLocaleMessageWithLocales(t *testing.T) {
	dir := t.TempDir()

	// Create _locales/en/messages.json
	localeDir := filepath.Join(dir, "_locales", "en")
	if err := os.MkdirAll(localeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	messages := `{"appName":{"message":"My App"}}`
	if err := os.WriteFile(filepath.Join(localeDir, "messages.json"), []byte(messages), 0o644); err != nil {
		t.Fatal(err)
	}

	got := resolveLocaleMessage("__MSG_appName__", dir, "en")
	if got != "My App" {
		t.Errorf("resolveLocaleMessage() = %q, want %q", got, "My App")
	}
}

func TestLookupMessage(t *testing.T) {
	dir := t.TempDir()

	// Create _locales/fr/messages.json
	localeDir := filepath.Join(dir, "_locales", "fr")
	if err := os.MkdirAll(localeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	messages := `{"extName":{"message":"Mon Extension"}}`
	if err := os.WriteFile(filepath.Join(localeDir, "messages.json"), []byte(messages), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("finds in default locale", func(t *testing.T) {
		got := lookupMessage(dir, "extName", "fr")
		if got != "Mon Extension" {
			t.Errorf("lookupMessage() = %q, want %q", got, "Mon Extension")
		}
	})

	t.Run("falls back to scanning locales", func(t *testing.T) {
		got := lookupMessage(dir, "extName", "")
		if got != "Mon Extension" {
			t.Errorf("lookupMessage() = %q, want %q", got, "Mon Extension")
		}
	})

	t.Run("returns empty for missing key", func(t *testing.T) {
		got := lookupMessage(dir, "nonExistent", "fr")
		if got != "" {
			t.Errorf("lookupMessage() = %q, want empty", got)
		}
	})
}

func TestReadMessage(t *testing.T) {
	dir := t.TempDir()

	localeDir := filepath.Join(dir, "_locales", "en")
	if err := os.MkdirAll(localeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	messages := `{"appName":{"message":"Test App"},"lowkey":{"message":"Lower"}}`
	if err := os.WriteFile(filepath.Join(localeDir, "messages.json"), []byte(messages), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("finds exact key", func(t *testing.T) {
		got := readMessage(dir, "en", "appName")
		if got != "Test App" {
			t.Errorf("readMessage() = %q, want %q", got, "Test App")
		}
	})

	t.Run("falls back to lowercase key", func(t *testing.T) {
		got := readMessage(dir, "en", "LOWKEY")
		if got != "Lower" {
			t.Errorf("readMessage() = %q, want %q", got, "Lower")
		}
	})

	t.Run("missing locale returns empty", func(t *testing.T) {
		got := readMessage(dir, "de", "appName")
		if got != "" {
			t.Errorf("readMessage() = %q, want empty", got)
		}
	})

	t.Run("invalid JSON returns empty", func(t *testing.T) {
		badDir := filepath.Join(dir, "_locales", "bad")
		if err := os.MkdirAll(badDir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(badDir, "messages.json"), []byte("{invalid}"), 0o644); err != nil {
			t.Fatal(err)
		}

		got := readMessage(dir, "bad", "appName")
		if got != "" {
			t.Errorf("readMessage() = %q, want empty", got)
		}
	})
}

func TestFindManifestDir(t *testing.T) {
	t.Run("finds manifest in root", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, err := findManifestDir(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != dir {
			t.Errorf("findManifestDir() = %q, want %q", got, dir)
		}
	})

	t.Run("finds manifest in nested dir", func(t *testing.T) {
		dir := t.TempDir()
		nested := filepath.Join(dir, "sub")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(nested, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, err := findManifestDir(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != nested {
			t.Errorf("findManifestDir() = %q, want %q", got, nested)
		}
	})

	t.Run("skips _metadata", func(t *testing.T) {
		dir := t.TempDir()
		metaDir := filepath.Join(dir, "_metadata")
		if err := os.MkdirAll(metaDir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(metaDir, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := findManifestDir(dir)
		if err == nil {
			t.Fatal("expected error when only manifest is in _metadata")
		}
	})

	t.Run("empty dir errors", func(t *testing.T) {
		_, err := findManifestDir(t.TempDir())
		if err == nil {
			t.Fatal("expected error for empty dir")
		}
	})
}

func TestToUniqueSortedStrings(t *testing.T) {
	tests := []struct {
		name string
		raw  any
		want []string
	}{
		{
			name: "nil returns nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "single string",
			raw:  "hello",
			want: []string{"hello"},
		},
		{
			name: "string slice",
			raw:  []string{"c", "a", "b", "a"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "any slice",
			raw:  []any{"z", "a", "m"},
			want: []string{"a", "m", "z"},
		},
		{
			name: "empty string returns nil",
			raw:  "",
			want: nil,
		},
		{
			name: "whitespace-only string returns nil",
			raw:  "   ",
			want: nil,
		},
		{
			name: "trims whitespace in slice",
			raw:  []any{" foo ", " bar "},
			want: []string{"bar", "foo"},
		},
		{
			name: "skips empty entries in string slice",
			raw:  []string{"a", "", "  ", "b"},
			want: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toUniqueSortedStrings(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toUniqueSortedStrings(%v) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
