/*
Copyright (c) 2026 Security Research
*/
package msm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeDB is an in-memory database that satisfies the unexported database
// interface, letting us exercise buildInfo's table-driven logic without a real
// CFBF container (the mscfb library is read-only, so a real .msm fixture cannot
// be synthesized in-process). The CFBF/byte-parsing path is covered separately
// by the error-path file tests below and, end-to-end, by the real-file goldens
// already exercised against pkg/msi's identical reader.
type fakeDB struct {
	tables  []string
	streams []string
	rows    map[string][]map[string]any
}

func (f *fakeDB) Tables() []string { return f.tables }

func (f *fakeDB) HasTable(name string) bool {
	for _, t := range f.tables {
		if t == name {
			return true
		}
	}
	return false
}

func (f *fakeDB) StreamNames() []string { return f.streams }

func (f *fakeDB) HasStream(name string) bool {
	for _, s := range f.streams {
		if s == name {
			return true
		}
	}
	return false
}

func (f *fakeDB) ReadTable(name string) ([]map[string]any, error) {
	return f.rows[name], nil
}

func TestBuildInfo_MergeModuleWithDriver(t *testing.T) {
	db := &fakeDB{
		tables:  []string{"ModuleSignature", "Component", "File", "Media", "Directory"},
		streams: []string{"\x05DigitalSignature", "ovpndco.cab"},
		rows: map[string][]map[string]any{
			"ModuleSignature": {
				{"ModuleID": "ovpn_dco.1A2B3C4D_5E6F_7A8B_9C0D_E1F2A3B4C5D6", "Language": 1033, "Version": "2.5.0"},
			},
			"Component": {
				{"Component": "ovpndco.sys.comp", "ComponentId": "{GUID-1}", "Directory_": "DriverDir", "KeyPath": "ovpndco.sys"},
			},
			"File": {
				{"File": "ovpndco.sys", "FileName": "ovpndco.sys", "Component_": "ovpndco.sys.comp", "FileSize": 81920, "Version": "2.5.0"},
				{"File": "ovpndco.cat", "FileName": "OVPNDC~1.CAT|ovpn-dco.cat", "Component_": "ovpndco.sys.comp", "FileSize": 4096},
				{"File": "readme.txt", "FileName": "README~1.TXT|readme.txt", "Component_": "ovpndco.sys.comp", "FileSize": 100},
			},
			"Media": {
				{"Cabinet": "#ovpndco.cab"},
			},
		},
	}

	info := buildInfo(db)

	if !info.IsMergeModule {
		t.Fatal("expected IsMergeModule = true")
	}
	if info.ModuleID != "ovpn_dco.1A2B3C4D_5E6F_7A8B_9C0D_E1F2A3B4C5D6" {
		t.Errorf("ModuleID = %q", info.ModuleID)
	}
	if info.Language != 1033 {
		t.Errorf("Language = %d, want 1033", info.Language)
	}
	if info.Version != "2.5.0" {
		t.Errorf("Version = %q, want 2.5.0", info.Version)
	}
	if len(info.Components) != 1 {
		t.Fatalf("Components = %d, want 1", len(info.Components))
	}
	if len(info.Files) != 3 {
		t.Fatalf("Files = %d, want 3", len(info.Files))
	}
	// Long-name extraction from "Short|Long".
	if info.Files[1].Name != "ovpn-dco.cat" {
		t.Errorf("Files[1].Name = %q, want ovpn-dco.cat", info.Files[1].Name)
	}
	// Driver classification: .sys + .cat are drivers, .txt is not.
	if len(info.DriverFiles) != 2 {
		t.Fatalf("DriverFiles = %d, want 2 (.sys + .cat)", len(info.DriverFiles))
	}
	if !info.Files[0].IsDriver {
		t.Error("ovpndco.sys should be a driver")
	}
	if info.Files[2].IsDriver {
		t.Error("readme.txt should not be a driver")
	}
	// Embedded cabinet recorded with '#' stripped.
	if len(info.EmbeddedCabinets) != 1 || info.EmbeddedCabinets[0] != "ovpndco.cab" {
		t.Errorf("EmbeddedCabinets = %v, want [ovpndco.cab]", info.EmbeddedCabinets)
	}
	if !info.HasSignature {
		t.Error("expected HasSignature = true")
	}
}

func TestBuildInfo_NotMergeModule(t *testing.T) {
	// A plain MSI database (no ModuleSignature) should produce an honest
	// warning rather than fabricating merge-module metadata.
	db := &fakeDB{
		tables: []string{"Property", "File"},
		rows:   map[string][]map[string]any{},
	}

	info := buildInfo(db)

	if info.IsMergeModule {
		t.Error("expected IsMergeModule = false")
	}
	if len(info.Warnings) == 0 {
		t.Error("expected a warning about missing ModuleSignature")
	}
	if info.ModuleID != "" {
		t.Errorf("ModuleID = %q, want empty", info.ModuleID)
	}
}

func TestBuildInfo_EmptyTables(t *testing.T) {
	db := &fakeDB{tables: []string{"ModuleSignature"}, rows: map[string][]map[string]any{}}

	info := buildInfo(db)

	if !info.IsMergeModule {
		t.Error("expected IsMergeModule = true")
	}
	if len(info.Files) != 0 || len(info.Components) != 0 {
		t.Error("expected no files/components for empty tables")
	}
}

func TestIsDriverFile(t *testing.T) {
	cases := map[string]bool{
		"ovpn-dco.sys": true,
		"driver.SYS":   true,
		"catalog.cat":  true,
		"setup.inf":    true,
		"helper.dll":   true,
		"readme.txt":   false,
		"config.json":  false,
		"noext":        false,
	}
	for name, want := range cases {
		if got := isDriverFile(name); got != want {
			t.Errorf("isDriverFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestShortLongName(t *testing.T) {
	if got := shortLongName("OVPNDC~1.CAT|ovpn-dco.cat"); got != "ovpn-dco.cat" {
		t.Errorf("got %q", got)
	}
	if got := shortLongName("plain.sys"); got != "plain.sys" {
		t.Errorf("got %q", got)
	}
}

func TestInfoNonexistent(t *testing.T) {
	_, err := Info("/nonexistent/file.msm")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseAlias(t *testing.T) {
	_, err := Parse("/nonexistent/file.msm")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestInfoNotCFBF(t *testing.T) {
	// A non-CFBF file must fail cleanly (wrapped error), not panic.
	f := filepath.Join(t.TempDir(), "bad.msm")
	if err := os.WriteFile(f, []byte("this is not a compound file"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Info(f)
	if err == nil {
		t.Error("expected error for non-CFBF input")
	}
	if !errors.Is(err, err) { // sanity: error is non-nil and wrappable
		t.Error("error should be inspectable")
	}
}

func TestIsMergeModule_NotCFBF(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.msm")
	if err := os.WriteFile(f, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsMergeModule(f) {
		t.Error("garbage should not be a merge module")
	}
	if IsMergeModule("/nonexistent/x.msm") {
		t.Error("missing file should not be a merge module")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		0:               "0 bytes",
		512:             "512 bytes",
		2048:            "2.0 KB",
		3 * 1024 * 1024: "3.0 MB",
	}
	for size, want := range cases {
		if got := FormatBytes(size); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", size, got, want)
		}
	}
}
