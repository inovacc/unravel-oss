package gather

import (
	"io/fs"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/extension"
	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// fakeDirEntry implements fs.DirEntry for testing.
type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f fakeDirEntry) Name() string      { return f.name }
func (f fakeDirEntry) IsDir() bool       { return f.isDir }
func (f fakeDirEntry) Type() fs.FileMode { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) {
	return fakeFileInfo{name: f.name, isDir: f.isDir}, nil
}

type fakeFileInfo struct {
	name  string
	isDir bool
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.isDir }
func (f fakeFileInfo) Sys() any           { return nil }

func testManifest() *manifest.Manifest {
	m := manifest.Default()
	return m
}

// saveAndRestore saves original function vars and returns a cleanup function.
func saveAndRestore(t *testing.T) {
	t.Helper()
	origDiscover := discoverBrowsers
	origParse := parseExtension
	origAnalyze := analyzePermissions
	origRisk := calculateRiskScore
	origRead := readDir
	t.Cleanup(func() {
		discoverBrowsers = origDiscover
		parseExtension = origParse
		analyzePermissions = origAnalyze
		calculateRiskScore = origRisk
		readDir = origRead
	})
}

func TestGather_BasicDiscovery(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtDir: "/fake/chrome/extensions"},
		}
	}
	readDir = func(name string) ([]fs.DirEntry, error) {
		return []fs.DirEntry{
			fakeDirEntry{name: "ext-abc", isDir: true},
			fakeDirEntry{name: "ext-xyz", isDir: true},
		}, nil
	}
	parseExtension = func(_, extID, browser, profile string) (*extension.ExtensionInfo, error) {
		info := &extension.ExtensionInfo{
			ID:          extID,
			Name:        "Ext " + extID,
			Version:     "1.0.0",
			ManifestVer: 3,
			Browser:     browser,
			Profile:     profile,
			Path:        "/fake/chrome/extensions/" + extID,
		}
		if extID == "ext-abc" {
			info.Permissions.All = []string{"tabs", "storage"}
		}
		return info, nil
	}
	analyzePermissions = func(info *extension.ExtensionInfo, _ []manifest.ExtPermissionRule) {}
	calculateRiskScore = func(info *extension.ExtensionInfo, _ map[string]int) {
		if info.ID == "ext-abc" {
			info.RiskScore = 50
			info.RiskLevel = "HIGH"
		} else {
			info.RiskScore = 10
			info.RiskLevel = "LOW"
		}
	}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Should be sorted by risk score descending
	if entries[0].ID != "ext-abc" {
		t.Errorf("expected ext-abc first (highest risk), got %s", entries[0].ID)
	}
	if entries[0].RiskScore != 50 {
		t.Errorf("expected risk score 50, got %d", entries[0].RiskScore)
	}
	if entries[1].ID != "ext-xyz" {
		t.Errorf("expected ext-xyz second, got %s", entries[1].ID)
	}
}

func TestGather_SkipsFilesAndTemp(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtDir: "/fake/extensions"},
		}
	}
	readDir = func(_ string) ([]fs.DirEntry, error) {
		return []fs.DirEntry{
			fakeDirEntry{name: "real-ext", isDir: true},
			fakeDirEntry{name: "Temp", isDir: true},
			fakeDirEntry{name: "somefile.json", isDir: false},
		}, nil
	}
	parseExtension = func(_, extID, browser, profile string) (*extension.ExtensionInfo, error) {
		return &extension.ExtensionInfo{
			ID: extID, Name: extID, Browser: browser, Profile: profile,
			Path: "/fake/extensions/" + extID,
		}, nil
	}
	analyzePermissions = func(_ *extension.ExtensionInfo, _ []manifest.ExtPermissionRule) {}
	calculateRiskScore = func(_ *extension.ExtensionInfo, _ map[string]int) {}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (Temp and files skipped), got %d", len(entries))
	}
	if entries[0].ID != "real-ext" {
		t.Errorf("expected real-ext, got %s", entries[0].ID)
	}
}

func TestGather_ReadDirError(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtDir: "/nonexistent"},
		}
	}
	readDir = func(_ string) ([]fs.DirEntry, error) {
		return nil, os.ErrNotExist
	}
	parseExtension = func(_, _, _, _ string) (*extension.ExtensionInfo, error) {
		t.Fatal("parseExtension should not be called when readDir fails")
		return nil, nil
	}
	analyzePermissions = func(_ *extension.ExtensionInfo, _ []manifest.ExtPermissionRule) {}
	calculateRiskScore = func(_ *extension.ExtensionInfo, _ map[string]int) {}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 0 {
		t.Errorf("expected 0 entries on readDir error, got %d", len(entries))
	}
}

func TestGather_ParseExtensionError(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtDir: "/fake"},
		}
	}
	readDir = func(_ string) ([]fs.DirEntry, error) {
		return []fs.DirEntry{
			fakeDirEntry{name: "bad-ext", isDir: true},
			fakeDirEntry{name: "good-ext", isDir: true},
		}, nil
	}
	parseExtension = func(_, extID, browser, profile string) (*extension.ExtensionInfo, error) {
		if extID == "bad-ext" {
			return nil, os.ErrNotExist
		}
		return &extension.ExtensionInfo{
			ID: extID, Name: extID, Browser: browser, Profile: profile,
		}, nil
	}
	analyzePermissions = func(_ *extension.ExtensionInfo, _ []manifest.ExtPermissionRule) {}
	calculateRiskScore = func(_ *extension.ExtensionInfo, _ map[string]int) {}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (bad-ext skipped), got %d", len(entries))
	}
	if entries[0].ID != "good-ext" {
		t.Errorf("expected good-ext, got %s", entries[0].ID)
	}
}

func TestGather_MultipleBrowserProfiles(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtDir: "/chrome/default"},
			{Browser: "firefox", Profile: "abc123", ExtDir: "/firefox/abc123"},
		}
	}
	readDir = func(name string) ([]fs.DirEntry, error) {
		if name == "/chrome/default" {
			return []fs.DirEntry{fakeDirEntry{name: "ext-1", isDir: true}}, nil
		}
		return []fs.DirEntry{fakeDirEntry{name: "ext-2", isDir: true}}, nil
	}
	parseExtension = func(_, extID, browser, profile string) (*extension.ExtensionInfo, error) {
		return &extension.ExtensionInfo{
			ID: extID, Name: extID, Browser: browser, Profile: profile,
		}, nil
	}
	analyzePermissions = func(_ *extension.ExtensionInfo, _ []manifest.ExtPermissionRule) {}
	calculateRiskScore = func(_ *extension.ExtensionInfo, _ map[string]int) {}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries from 2 profiles, got %d", len(entries))
	}

	browsers := map[string]bool{}
	for _, e := range entries {
		browsers[e.Browser] = true
	}
	if !browsers["chrome"] || !browsers["firefox"] {
		t.Error("expected entries from both chrome and firefox")
	}
}

func TestGather_CrossBrowserDuplicates(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtDir: "/chrome"},
			{Browser: "edge", Profile: "Default", ExtDir: "/edge"},
			{Browser: "brave", Profile: "Profile 1", ExtDir: "/brave"},
		}
	}
	readDir = func(_ string) ([]fs.DirEntry, error) {
		return []fs.DirEntry{fakeDirEntry{name: "shared-ext", isDir: true}}, nil
	}
	parseExtension = func(_, extID, browser, profile string) (*extension.ExtensionInfo, error) {
		return &extension.ExtensionInfo{
			ID: extID, Name: "Shared", Browser: browser, Profile: profile,
		}, nil
	}
	analyzePermissions = func(_ *extension.ExtensionInfo, _ []manifest.ExtPermissionRule) {}
	calculateRiskScore = func(_ *extension.ExtensionInfo, _ map[string]int) {}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	dupeCount := 0
	for _, e := range entries {
		if e.Duplicate {
			dupeCount++
			if e.DupeOf != "chrome/Default" {
				t.Errorf("expected dupe_of chrome/Default, got %s", e.DupeOf)
			}
		}
	}
	if dupeCount != 2 {
		t.Errorf("expected 2 duplicates, got %d", dupeCount)
	}
}

func TestGather_NoBrowsers(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return nil
	}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 0 {
		t.Errorf("expected 0 entries with no browsers, got %d", len(entries))
	}
}

func TestGather_EmptyExtDir(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtDir: "/empty"},
		}
	}
	readDir = func(_ string) ([]fs.DirEntry, error) {
		return []fs.DirEntry{}, nil
	}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty dir, got %d", len(entries))
	}
}

func TestGather_BrowserFilter(t *testing.T) {
	saveAndRestore(t)

	var capturedFilter string
	discoverBrowsers = func(filter string) []extension.BrowserProfile {
		capturedFilter = filter
		return nil
	}

	Gather(testManifest(), "firefox", false)

	if capturedFilter != "firefox" {
		t.Errorf("expected browser filter 'firefox', got %q", capturedFilter)
	}
}

func TestGather_EntryFields(t *testing.T) {
	saveAndRestore(t)

	discoverBrowsers = func(_ string) []extension.BrowserProfile {
		return []extension.BrowserProfile{
			{Browser: "chrome", Profile: "Work", ExtDir: "/chrome/work"},
		}
	}
	readDir = func(_ string) ([]fs.DirEntry, error) {
		return []fs.DirEntry{fakeDirEntry{name: "ublock", isDir: true}}, nil
	}
	parseExtension = func(_, extID, browser, profile string) (*extension.ExtensionInfo, error) {
		info := &extension.ExtensionInfo{
			ID:          extID,
			Name:        "uBlock Origin",
			Version:     "1.57.2",
			ManifestVer: 3,
			Browser:     browser,
			Profile:     profile,
			Path:        "/chrome/work/ublock/1.57.2",
		}
		info.Permissions.All = []string{"storage", "webRequest", "tabs"}
		return info, nil
	}
	analyzePermissions = func(_ *extension.ExtensionInfo, _ []manifest.ExtPermissionRule) {}
	calculateRiskScore = func(info *extension.ExtensionInfo, _ map[string]int) {
		info.RiskScore = 30
		info.RiskLevel = "MEDIUM"
	}

	entries := Gather(testManifest(), "", false)

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.ID != "ublock" {
		t.Errorf("ID = %q, want ublock", e.ID)
	}
	if e.Name != "uBlock Origin" {
		t.Errorf("Name = %q, want uBlock Origin", e.Name)
	}
	if e.Version != "1.57.2" {
		t.Errorf("Version = %q, want 1.57.2", e.Version)
	}
	if e.ManifestVer != 3 {
		t.Errorf("ManifestVer = %d, want 3", e.ManifestVer)
	}
	if e.Browser != "chrome" {
		t.Errorf("Browser = %q, want chrome", e.Browser)
	}
	if e.Profile != "Work" {
		t.Errorf("Profile = %q, want Work", e.Profile)
	}
	if e.Path != "/chrome/work/ublock/1.57.2" {
		t.Errorf("Path = %q, want /chrome/work/ublock/1.57.2", e.Path)
	}
	if e.RiskScore != 30 {
		t.Errorf("RiskScore = %d, want 30", e.RiskScore)
	}
	if e.RiskLevel != "MEDIUM" {
		t.Errorf("RiskLevel = %q, want MEDIUM", e.RiskLevel)
	}
	if e.Permissions != 3 {
		t.Errorf("Permissions = %d, want 3", e.Permissions)
	}
}

func TestMarkDuplicates(t *testing.T) {
	tests := []struct {
		name    string
		entries []ExtensionEntry
		want    map[int]bool // index -> expected Duplicate value
	}{
		{
			name:    "empty",
			entries: nil,
			want:    map[int]bool{},
		},
		{
			name: "no duplicates",
			entries: []ExtensionEntry{
				{ID: "a", Browser: "chrome", Profile: "Default"},
				{ID: "b", Browser: "chrome", Profile: "Default"},
			},
			want: map[int]bool{0: false, 1: false},
		},
		{
			name: "with duplicates",
			entries: []ExtensionEntry{
				{ID: "a", Browser: "chrome", Profile: "Default"},
				{ID: "a", Browser: "edge", Profile: "Default"},
				{ID: "b", Browser: "chrome", Profile: "Default"},
				{ID: "a", Browser: "brave", Profile: "P1"},
			},
			want: map[int]bool{0: false, 1: true, 2: false, 3: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			markDuplicates(tt.entries)
			for i, wantDupe := range tt.want {
				if tt.entries[i].Duplicate != wantDupe {
					t.Errorf("entries[%d].Duplicate = %v, want %v", i, tt.entries[i].Duplicate, wantDupe)
				}
			}
		})
	}
}

func TestMarkDuplicates_DupeOf(t *testing.T) {
	entries := []ExtensionEntry{
		{ID: "ext-abc", Browser: "chrome", Profile: "Default"},
		{ID: "ext-abc", Browser: "edge", Profile: "Default"},
		{ID: "ext-xyz", Browser: "chrome", Profile: "Default"},
		{ID: "ext-abc", Browser: "brave", Profile: "Profile 1"},
	}

	markDuplicates(entries)

	if entries[0].Duplicate {
		t.Error("first occurrence should not be duplicate")
	}
	if !entries[1].Duplicate || entries[1].DupeOf != "chrome/Default" {
		t.Errorf("entries[1]: Duplicate=%v, DupeOf=%q", entries[1].Duplicate, entries[1].DupeOf)
	}
	if entries[2].Duplicate {
		t.Error("ext-xyz should not be duplicate")
	}
	if !entries[3].Duplicate || entries[3].DupeOf != "chrome/Default" {
		t.Errorf("entries[3]: Duplicate=%v, DupeOf=%q", entries[3].Duplicate, entries[3].DupeOf)
	}
}

func TestSortByRiskScore(t *testing.T) {
	entries := []ExtensionEntry{
		{Name: "low", RiskScore: 5},
		{Name: "high", RiskScore: 80},
		{Name: "medium", RiskScore: 30},
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RiskScore > entries[j].RiskScore
	})

	if entries[0].Name != "high" {
		t.Errorf("expected highest risk first, got %s", entries[0].Name)
	}
	if entries[2].Name != "low" {
		t.Errorf("expected lowest risk last, got %s", entries[2].Name)
	}
}
