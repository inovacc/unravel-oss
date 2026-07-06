/* Copyright (c) 2026 Security Research */
package gather

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrichElectron_Binary(t *testing.T) {
	root := t.TempDir()

	// Create a fake binary with version strings embedded
	content := []byte("some prefix Chrome/120.0.6099.109 Electron/28.1.3 more data node/v20.9.0 trailing")
	if err := os.WriteFile(filepath.Join(root, "myapp"), content, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create resources dir so it looks like an electron app
	if err := os.MkdirAll(filepath.Join(root, "resources"), 0o755); err != nil {
		t.Fatal(err)
	}

	entry := &AppEntry{Path: root, Type: "electron"}
	enrichEntry(entry)

	if entry.ChromiumVersion != "120.0.6099.109" {
		t.Errorf("ChromiumVersion = %q, want %q", entry.ChromiumVersion, "120.0.6099.109")
	}
	if entry.ElectronVersion != "28.1.3" {
		t.Errorf("ElectronVersion = %q, want %q", entry.ElectronVersion, "28.1.3")
	}
	if entry.NodeVersion != "20.9.0" {
		t.Errorf("NodeVersion = %q, want %q", entry.NodeVersion, "20.9.0")
	}
}

func TestEnrichElectron_ASAR(t *testing.T) {
	root := t.TempDir()
	resDir := filepath.Join(root, "resources")
	if err := os.MkdirAll(resDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Build a minimal ASAR with package.json containing React dependency
	pkgJSON := `{"dependencies":{"react":"^18.2.0","react-dom":"^18.2.0"}}`
	asarPath := filepath.Join(resDir, "app.asar")
	if err := writeMinimalASAR(asarPath, "package.json", []byte(pkgJSON)); err != nil {
		t.Fatal(err)
	}

	entry := &AppEntry{Path: root, Type: "electron"}
	enrichEntry(entry)

	if len(entry.Frameworks) == 0 {
		t.Fatal("expected frameworks to be detected from ASAR")
	}
	found := false
	for _, fw := range entry.Frameworks {
		if fw == "React" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected React in frameworks, got %v", entry.Frameworks)
	}
}

func TestEnrichElectron_PackageJSON(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "resources", "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	pkg := map[string]any{
		"dependencies": map[string]any{
			"vue":  "^3.3.0",
			"nuxt": "^3.8.0",
		},
	}
	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	entry := &AppEntry{Path: root, Type: "electron"}
	enrichEntry(entry)

	if len(entry.Frameworks) != 2 {
		t.Fatalf("expected 2 frameworks, got %v", entry.Frameworks)
	}
	// Sorted: Nuxt, Vue
	if entry.Frameworks[0] != "Nuxt" || entry.Frameworks[1] != "Vue" {
		t.Errorf("expected [Nuxt Vue], got %v", entry.Frameworks)
	}
}

func TestEnrichTauri_Binary(t *testing.T) {
	root := t.TempDir()

	content := []byte("some binary data tauri@2.8.2 more stuff")
	if err := os.WriteFile(filepath.Join(root, "pluely"), content, 0o755); err != nil {
		t.Fatal(err)
	}

	entry := &AppEntry{Path: root, Type: "tauri"}
	enrichEntry(entry)

	if entry.TauriVersion != "2.8.2" {
		t.Errorf("TauriVersion = %q, want %q", entry.TauriVersion, "2.8.2")
	}
}

func TestEnrichTauri_Config(t *testing.T) {
	root := t.TempDir()

	conf := map[string]any{
		"package": map[string]any{
			"version":     "1.5.0",
			"productName": "MyTauriApp",
		},
	}
	data, _ := json.Marshal(conf)
	if err := os.WriteFile(filepath.Join(root, "tauri.conf.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	entry := &AppEntry{Path: root, Type: "tauri", Version: ""}
	enrichEntry(entry)

	if entry.Version != "1.5.0" {
		t.Errorf("Version = %q, want %q", entry.Version, "1.5.0")
	}
}

func TestEnrichEntry_NoData(t *testing.T) {
	root := t.TempDir()

	entry := &AppEntry{Path: root, Type: "electron"}
	enrichEntry(entry) // should not panic

	if entry.ElectronVersion != "" || entry.ChromiumVersion != "" || entry.NodeVersion != "" {
		t.Error("expected empty version fields for empty dir")
	}
	if entry.Frameworks != nil {
		t.Error("expected nil frameworks for empty dir")
	}
}

func TestEnrichEntry_UnknownType(t *testing.T) {
	entry := &AppEntry{Path: t.TempDir(), Type: "unknown"}
	enrichEntry(entry) // should not panic, no enrichment
}

func TestDetectFrameworks(t *testing.T) {
	tests := []struct {
		name string
		deps map[string]any
		want []string
	}{
		{
			name: "react",
			deps: map[string]any{"react": "^18", "react-dom": "^18"},
			want: []string{"React"},
		},
		{
			name: "vue+nuxt",
			deps: map[string]any{"vue": "^3", "nuxt": "^3"},
			want: []string{"Nuxt", "Vue"},
		},
		{
			name: "angular",
			deps: map[string]any{"@angular/core": "^17"},
			want: []string{"Angular"},
		},
		{
			name: "svelte",
			deps: map[string]any{"svelte": "^4"},
			want: []string{"Svelte"},
		},
		{
			name: "solid",
			deps: map[string]any{"solid-js": "^1"},
			want: []string{"Solid"},
		},
		{
			name: "next",
			deps: map[string]any{"next": "^14", "react": "^18"},
			want: []string{"Next.js", "React"},
		},
		{
			name: "no frameworks",
			deps: map[string]any{"lodash": "^4", "axios": "^1"},
			want: nil,
		},
		{
			name: "empty",
			deps: map[string]any{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFrameworks(tt.deps)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestFindMainBinary(t *testing.T) {
	root := t.TempDir()

	// Create files of different sizes
	_ = os.WriteFile(filepath.Join(root, "small.txt"), []byte("hi"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "app"), make([]byte, 1000), 0o755)
	_ = os.WriteFile(filepath.Join(root, "helper"), make([]byte, 500), 0o755)
	_ = os.WriteFile(filepath.Join(root, "icon.png"), make([]byte, 2000), 0o644)
	_ = os.WriteFile(filepath.Join(root, "config.json"), []byte("{}"), 0o644)

	got := findMainBinary(root)
	if filepath.Base(got) != "app" {
		t.Errorf("findMainBinary = %q, want app", got)
	}
}

func TestFindMainBinary_EmptyDir(t *testing.T) {
	got := findMainBinary(t.TempDir())
	if got != "" {
		t.Errorf("expected empty string for empty dir, got %q", got)
	}
}

func TestReadFileCapped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big")
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	_ = os.WriteFile(f, data, 0o644)

	got, err := readFileCapped(f, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 100 {
		t.Errorf("got %d bytes, want 100", len(got))
	}
}

func TestParseDepsFromJSON(t *testing.T) {
	data := []byte(`{"dependencies":{"react":"^18"},"devDependencies":{"jest":"^29"}}`)
	deps := parseDepsFromJSON(data)
	if deps == nil {
		t.Fatal("expected non-nil deps")
	}
	if _, ok := deps["react"]; !ok {
		t.Error("expected react in deps")
	}
	if _, ok := deps["jest"]; !ok {
		t.Error("expected jest in deps")
	}
}

func TestParseDepsFromJSON_Invalid(t *testing.T) {
	deps := parseDepsFromJSON([]byte("not json"))
	if deps != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestParseDepsFromJSON_Empty(t *testing.T) {
	deps := parseDepsFromJSON([]byte(`{}`))
	if deps != nil {
		t.Error("expected nil for empty deps")
	}
}

// writeMinimalASAR creates a minimal valid ASAR archive containing a single file.
// The ASAR format uses Chromium's binary serialization for headers.
func writeMinimalASAR(path, fileName string, content []byte) error {
	header := map[string]any{
		"files": map[string]any{
			fileName: map[string]any{
				"offset": "0",
				"size":   len(content),
			},
		},
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return err
	}

	headerJSONSize := uint32(len(headerJSON))
	headerDataSize := headerJSONSize + 4
	totalSize := headerDataSize + 4

	// Calculate data offset with alignment (matches asar.OpenAndParse logic)
	dataOffset := int(8 + totalSize)
	if dataOffset%4 != 0 {
		dataOffset += 4 - (dataOffset % 4)
	}

	buf := make([]byte, dataOffset+len(content))
	binary.LittleEndian.PutUint32(buf[0:4], 4)
	binary.LittleEndian.PutUint32(buf[4:8], totalSize)
	binary.LittleEndian.PutUint32(buf[8:12], 4)
	binary.LittleEndian.PutUint32(buf[12:16], headerJSONSize)
	copy(buf[16:], headerJSON)
	// Padding bytes between header and data are zero-filled by make()
	copy(buf[dataOffset:], content)

	return os.WriteFile(path, buf, 0o644)
}
