package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testStore creates a Store backed by a temp directory and returns it along
// with a cleanup function.
func testStore(t *testing.T) *Store {
	t.Helper()

	dir := t.TempDir()
	baseDir := filepath.Join(dir, "cache")

	return NewWithDir(baseDir)
}

// writeSourceFile creates a temporary file with the given content and returns
// its path.
func writeSourceFile(t *testing.T, content string) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "source-*")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}

	_ = f.Close()

	return f.Name()
}

// --------------------------------------------------------------------------
// Construction
// --------------------------------------------------------------------------

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}

	if s.baseDir == "" {
		t.Error("baseDir is empty")
	}

	if s.indexPath == "" {
		t.Error("indexPath is empty")
	}
}

func TestNewWithDir(t *testing.T) {
	tests := []struct {
		name    string
		baseDir string
	}{
		{name: "simple path", baseDir: "/tmp/test-cache"},
		{name: "nested path", baseDir: "/tmp/a/b/c/cache"},
		{name: "relative path", baseDir: "relative/cache"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewWithDir(tc.baseDir)
			if s.baseDir != tc.baseDir {
				t.Errorf("baseDir = %q, want %q", s.baseDir, tc.baseDir)
			}

			wantIndex := filepath.Join(filepath.Dir(tc.baseDir), "cache.json")
			if s.indexPath != wantIndex {
				t.Errorf("indexPath = %q, want %q", s.indexPath, wantIndex)
			}
		})
	}
}

// --------------------------------------------------------------------------
// CacheDir / IndexPath
// --------------------------------------------------------------------------

func TestCacheDir(t *testing.T) {
	dir := CacheDir()
	if dir == "" {
		t.Fatal("CacheDir() returned empty string")
	}

	if !strings.HasSuffix(dir, filepath.Join("Unravel", "cache")) {
		t.Errorf("CacheDir() = %q, want suffix Unravel/cache", dir)
	}
}

func TestCacheDirFallbacks(t *testing.T) {
	tests := []struct {
		name       string
		setLocal   string
		wantSuffix string
	}{
		{
			name:       "LOCALAPPDATA set",
			setLocal:   t.TempDir(),
			wantSuffix: filepath.Join("Unravel", "cache"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := os.Getenv("LOCALAPPDATA")
			t.Setenv("LOCALAPPDATA", tc.setLocal)

			dir := CacheDir()
			if !strings.HasSuffix(dir, tc.wantSuffix) {
				t.Errorf("CacheDir() = %q, want suffix %q", dir, tc.wantSuffix)
			}

			if tc.setLocal != "" && !strings.HasPrefix(dir, tc.setLocal) {
				t.Errorf("CacheDir() = %q, want prefix %q", dir, tc.setLocal)
			}

			_ = orig // restored by t.Setenv
		})
	}
}

func TestIndexPath(t *testing.T) {
	path := IndexPath()
	if path == "" {
		t.Fatal("IndexPath() returned empty string")
	}

	if !strings.HasSuffix(path, filepath.Join("Unravel", "cache.json")) {
		t.Errorf("IndexPath() = %q, want suffix Unravel/cache.json", path)
	}
}

// --------------------------------------------------------------------------
// Put
// --------------------------------------------------------------------------

func TestPut(t *testing.T) {
	tests := []struct {
		name       string
		sourcePath string // "" means use a real temp file
		entryType  string
		tags       []string
		data       map[string][]byte
		wantErr    bool
	}{
		{
			name:      "basic put",
			entryType: "apk",
			tags:      []string{"android"},
			data:      map[string][]byte{"report.json": []byte(`{"ok":true}`)},
		},
		{
			name:      "put with multiple files",
			entryType: "electron",
			tags:      []string{"windows", "asar"},
			data: map[string][]byte{
				"manifest.json":  []byte(`{"name":"test"}`),
				"sub/nested.txt": []byte("nested content"),
			},
		},
		{
			name:      "put with nil tags",
			entryType: "ipa",
			tags:      nil,
			data:      map[string][]byte{"info.txt": []byte("hello")},
		},
		{
			name:      "put with empty data",
			entryType: "deb",
			tags:      []string{},
			data:      map[string][]byte{},
		},
		{
			name:       "put with nonexistent source",
			sourcePath: "/nonexistent/source/file.bin",
			entryType:  "unknown",
			tags:       nil,
			data:       map[string][]byte{"out.txt": []byte("data")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)

			sourcePath := tc.sourcePath
			if sourcePath == "" {
				sourcePath = writeSourceFile(t, "test content for "+tc.name)
			}

			entry, err := s.Put(sourcePath, tc.entryType, tc.tags, tc.data)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("Put() error: %v", err)
			}

			if entry.ID == "" {
				t.Error("entry ID is empty")
			}

			if entry.SourcePath != sourcePath {
				t.Errorf("SourcePath = %q, want %q", entry.SourcePath, sourcePath)
			}

			if entry.Type != tc.entryType {
				t.Errorf("Type = %q, want %q", entry.Type, tc.entryType)
			}

			if entry.CreatedAt.IsZero() {
				t.Error("CreatedAt is zero")
			}

			// For real source files, verify hash is populated
			if tc.sourcePath == "" && entry.SourceHash == "" {
				t.Error("SourceHash is empty for existing source file")
			}

			// For nonexistent source, hash should be empty
			if tc.sourcePath == "/nonexistent/source/file.bin" && entry.SourceHash != "" {
				t.Error("SourceHash should be empty for nonexistent source")
			}

			// Verify data files were written
			for name, content := range tc.data {
				written, err := os.ReadFile(filepath.Join(entry.CacheDir, name))
				if err != nil {
					t.Errorf("data file %q not found: %v", name, err)

					continue
				}

				if string(written) != string(content) {
					t.Errorf("data file %q content = %q, want %q", name, written, content)
				}
			}
		})
	}
}

// --------------------------------------------------------------------------
// Get
// --------------------------------------------------------------------------

func TestGet(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "get test content")

	entry, err := s.Put(src, "test", nil, map[string][]byte{"f.txt": []byte("data")})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "existing entry", id: entry.ID, wantErr: false},
		{name: "nonexistent entry", id: "00000000-0000-0000-0000-000000000000", wantErr: true},
		{name: "empty id", id: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Get(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("Get() error: %v", err)
			}

			if got.ID != entry.ID {
				t.Errorf("ID = %q, want %q", got.ID, entry.ID)
			}

			if got.Type != "test" {
				t.Errorf("Type = %q, want %q", got.Type, "test")
			}
		})
	}
}

// --------------------------------------------------------------------------
// Find
// --------------------------------------------------------------------------

func TestFind(t *testing.T) {
	s := testStore(t)

	src1 := writeSourceFile(t, "find test content 1")
	src2 := writeSourceFile(t, "find test content 2")

	_, err := s.Put(src1, "type1", nil, map[string][]byte{"a.txt": []byte("a")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Put(src1, "type1-dup", nil, map[string][]byte{"b.txt": []byte("b")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.Put(src2, "type2", nil, map[string][]byte{"c.txt": []byte("c")})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		wantCount int
	}{
		{name: "find by existing path (two entries)", path: src1, wantCount: 2},
		{name: "find by second path", path: src2, wantCount: 1},
		{name: "find nonexistent file", path: "/no/such/file.bin", wantCount: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.Find(tc.path)
			if len(matches) != tc.wantCount {
				t.Errorf("Find(%q) returned %d entries, want %d", tc.path, len(matches), tc.wantCount)
			}
		})
	}
}

// --------------------------------------------------------------------------
// List
// --------------------------------------------------------------------------

func TestList(t *testing.T) {
	tests := []struct {
		name      string
		putCount  int
		wantCount int
	}{
		{name: "empty store", putCount: 0, wantCount: 0},
		{name: "one entry", putCount: 1, wantCount: 1},
		{name: "three entries", putCount: 3, wantCount: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)

			for i := 0; i < tc.putCount; i++ {
				src := writeSourceFile(t, "list test")

				_, err := s.Put(src, "test", nil, map[string][]byte{"f.txt": []byte("d")})
				if err != nil {
					t.Fatal(err)
				}
			}

			entries, err := s.List()
			if err != nil {
				t.Fatalf("List() error: %v", err)
			}

			if len(entries) != tc.wantCount {
				t.Errorf("List() returned %d entries, want %d", len(entries), tc.wantCount)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Delete
// --------------------------------------------------------------------------

func TestDelete(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "delete test content")

	entry, err := s.Put(src, "test", nil, map[string][]byte{"f.txt": []byte("data")})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "delete existing", id: entry.ID, wantErr: false},
		{name: "delete already deleted", id: entry.ID, wantErr: true},
		{name: "delete nonexistent", id: "bogus-id", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Delete(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("Delete() error: %v", err)
			}

			// Verify entry is gone from index
			_, getErr := s.Get(entry.ID)
			if getErr == nil {
				t.Error("entry still retrievable after Delete")
			}

			// Verify cache dir was removed
			if _, statErr := os.Stat(entry.CacheDir); !os.IsNotExist(statErr) {
				t.Error("cache dir still exists after Delete")
			}
		})
	}
}

// --------------------------------------------------------------------------
// Prune
// --------------------------------------------------------------------------

func TestPrune(t *testing.T) {
	tests := []struct {
		name       string
		entryAges  []time.Duration // negative means in the past
		maxAge     time.Duration
		wantPruned int
		wantRemain int
	}{
		{
			name:       "empty store",
			entryAges:  nil,
			maxAge:     24 * time.Hour,
			wantPruned: 0,
			wantRemain: 0,
		},
		{
			name:       "nothing to prune (all recent)",
			entryAges:  []time.Duration{0, 0, 0},
			maxAge:     24 * time.Hour,
			wantPruned: 0,
			wantRemain: 3,
		},
		{
			name:       "prune all",
			entryAges:  []time.Duration{-48 * time.Hour, -72 * time.Hour},
			maxAge:     24 * time.Hour,
			wantPruned: 2,
			wantRemain: 0,
		},
		{
			name:       "prune some",
			entryAges:  []time.Duration{0, -48 * time.Hour, 0},
			maxAge:     24 * time.Hour,
			wantPruned: 1,
			wantRemain: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)

			// Create entries and manually set their CreatedAt
			for _, age := range tc.entryAges {
				src := writeSourceFile(t, "prune test")

				entry, err := s.Put(src, "test", nil, map[string][]byte{"f.txt": []byte("d")})
				if err != nil {
					t.Fatal(err)
				}

				if age != 0 {
					// Directly modify index to set entry time
					s.mu.Lock()

					idx, _ := s.readIndex()
					for i := range idx.Entries {
						if idx.Entries[i].ID == entry.ID {
							idx.Entries[i].CreatedAt = time.Now().UTC().Add(age)
						}
					}

					_ = s.writeIndex(idx)
					s.mu.Unlock()
				}
			}

			pruned, err := s.Prune(tc.maxAge)
			if err != nil {
				t.Fatalf("Prune() error: %v", err)
			}

			if pruned != tc.wantPruned {
				t.Errorf("Prune() pruned %d, want %d", pruned, tc.wantPruned)
			}

			entries, _ := s.List()
			if len(entries) != tc.wantRemain {
				t.Errorf("remaining entries = %d, want %d", len(entries), tc.wantRemain)
			}
		})
	}
}

// --------------------------------------------------------------------------
// ReadFile
// --------------------------------------------------------------------------

func TestReadFile(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "readfile test")

	entry, err := s.Put(src, "test", nil, map[string][]byte{
		"report.json":  []byte(`{"status":"ok"}`),
		"sub/deep.txt": []byte("deep content"),
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		id       string
		filename string
		want     string
		wantErr  bool
	}{
		{name: "read existing file", id: entry.ID, filename: "report.json", want: `{"status":"ok"}`},
		{name: "read nested file", id: entry.ID, filename: "sub/deep.txt", want: "deep content"},
		{name: "read nonexistent file", id: entry.ID, filename: "nope.txt", wantErr: true},
		{name: "read from bad id", id: "bad-id", filename: "report.json", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := s.ReadFile(tc.id, tc.filename)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("ReadFile() error: %v", err)
			}

			if string(data) != tc.want {
				t.Errorf("ReadFile() = %q, want %q", data, tc.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// UUIDv7 generation
// --------------------------------------------------------------------------

func TestNewUUIDv7(t *testing.T) {
	tests := []struct {
		name  string
		check func(id string) bool
		desc  string
	}{
		{
			name:  "non-empty",
			check: func(id string) bool { return id != "" },
			desc:  "UUID should not be empty",
		},
		{
			name: "has correct format",
			check: func(id string) bool {
				parts := strings.Split(id, "-")
				return len(parts) == 5
			},
			desc: "UUID should have 5 hyphen-separated parts",
		},
		{
			name: "version 7",
			check: func(id string) bool {
				parts := strings.Split(id, "-")
				return len(parts) >= 3 && len(parts[2]) >= 1 && parts[2][0] == '7'
			},
			desc: "third segment should start with '7' (version 7)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := newUUIDv7()
			if !tc.check(id) {
				t.Errorf("%s: got %q", tc.desc, id)
			}
		})
	}
}

func TestNewUUIDv7_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 20)

	for range 20 {
		id := newUUIDv7()
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate UUID generated: %s", id)
		}

		seen[id] = struct{}{}
	}
	// No inter-call sleep needed: newUUIDv7 now sources its random suffix from
	// crypto/rand (cross-platform), so ids are distinct even within one ms.
}

// --------------------------------------------------------------------------
// Index persistence
// --------------------------------------------------------------------------

func TestIndexPersistence(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "persistence test")

	entry, err := s.Put(src, "persist", []string{"tag1"}, map[string][]byte{"x.txt": []byte("x")})
	if err != nil {
		t.Fatal(err)
	}

	// Read index file directly and verify structure
	data, err := os.ReadFile(s.indexPath)
	if err != nil {
		t.Fatalf("reading index file: %v", err)
	}

	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		t.Fatalf("unmarshalling index: %v", err)
	}

	if idx.Version != IndexVersionSharded {
		t.Errorf("index version = %d, want %d (Put stamps the sharded layout version)", idx.Version, IndexVersionSharded)
	}

	if len(idx.Entries) != 1 {
		t.Fatalf("index has %d entries, want 1", len(idx.Entries))
	}

	if idx.Entries[0].ID != entry.ID {
		t.Errorf("persisted entry ID = %q, want %q", idx.Entries[0].ID, entry.ID)
	}
}

func TestCorruptIndex(t *testing.T) {
	s := testStore(t)

	// Write corrupt JSON to index
	if err := os.MkdirAll(filepath.Dir(s.indexPath), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(s.indexPath, []byte("{invalid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A corrupt index must surface an ERROR, not be silently treated as empty.
	// Masking corruption as "0 entries" is exactly what would let gcOrphans
	// reclassify every real cache dir as an orphan and delete it.
	if _, err := s.List(); err == nil {
		t.Fatal("List() on a corrupt index returned nil error; want a parse error")
	}
}

func TestMissingIndex(t *testing.T) {
	s := testStore(t)

	// No index file exists yet
	entries, err := s.List()
	if err != nil {
		t.Fatalf("List() on fresh store error: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// --------------------------------------------------------------------------
// Concurrent access
// --------------------------------------------------------------------------

func TestConcurrentPut(t *testing.T) {
	s := testStore(t)

	const goroutines = 10

	var wg sync.WaitGroup

	errs := make(chan error, goroutines)

	for i := range goroutines {
		wg.Add(1)

		go func(n int) {
			defer wg.Done()

			src := writeSourceFile(t, "concurrent test")

			_, err := s.Put(src, "concurrent", nil, map[string][]byte{
				"data.txt": []byte("goroutine data"),
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Put() error: %v", err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	if len(entries) != goroutines {
		t.Errorf("expected %d entries, got %d", goroutines, len(entries))
	}
}

func TestConcurrentGetAndList(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "concurrent read test")

	entry, err := s.Put(src, "test", nil, map[string][]byte{"f.txt": []byte("d")})
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 10

	var wg sync.WaitGroup

	errs := make(chan error, goroutines*2)

	for range goroutines {
		wg.Add(2)

		go func() {
			defer wg.Done()

			_, err := s.Get(entry.ID)
			if err != nil {
				errs <- err
			}
		}()

		go func() {
			defer wg.Done()

			_, err := s.List()
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent read error: %v", err)
	}
}

// --------------------------------------------------------------------------
// Hash computation (via Find matching by hash)
// --------------------------------------------------------------------------

func TestFindByHash(t *testing.T) {
	s := testStore(t)

	// Create a source file and store an entry
	src := writeSourceFile(t, "hash matching content")

	_, err := s.Put(src, "hashed", nil, map[string][]byte{"r.txt": []byte("r")})
	if err != nil {
		t.Fatal(err)
	}

	// Find by the same file path -- should match by hash
	matches := s.Find(src)
	if len(matches) != 1 {
		t.Fatalf("Find() returned %d matches, want 1", len(matches))
	}

	if matches[0].SourceHash == "" {
		t.Error("matched entry has empty hash")
	}

	// Create a copy of the file with same content at a different path
	copyPath := filepath.Join(t.TempDir(), "copy.bin")
	content, _ := os.ReadFile(src)

	if err := os.WriteFile(copyPath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	// DSC-06 / 13-06: Find now requires abs-path equality. A copy of the same
	// content at a DIFFERENT path must NOT collide with the original entry —
	// otherwise dissect cache hits would carry one input's identity into a
	// different input's output dir.
	copyMatches := s.Find(copyPath)
	if len(copyMatches) != 0 {
		t.Errorf("Find() by hash copy at different path returned %d matches, want 0 (DSC-06 path-equality requirement)", len(copyMatches))
	}
}

// --------------------------------------------------------------------------
// Edge cases
// --------------------------------------------------------------------------

func TestPutToReadOnlyDir(t *testing.T) {
	// Windows does not enforce directory read-only permissions the same way
	// as Unix, so this test is only meaningful on Unix-like systems.
	if os.Getenv("CI") != "" {
		t.Skip("skipping on CI (may run as root)")
	}

	if filepath.Separator == '\\' {
		t.Skip("skipping on Windows (read-only dirs not enforced)")
	}

	// Create a read-only directory
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly", "cache")

	if err := os.MkdirAll(roDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Make the cache dir read-only
	if err := os.Chmod(roDir, 0o444); err != nil {
		t.Skip("cannot set read-only permissions")
	}

	t.Cleanup(func() {
		_ = os.Chmod(roDir, 0o755)
	})

	s := NewWithDir(filepath.Join(roDir, "sub"))
	_, err := s.Put("/tmp/fake", "test", nil, map[string][]byte{"f.txt": []byte("d")})

	if err == nil {
		t.Error("expected error writing to read-only dir")
	}
}

func TestDeleteRemovesCacheDir(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "delete dir test")

	entry, err := s.Put(src, "test", nil, map[string][]byte{"f.txt": []byte("data")})
	if err != nil {
		t.Fatal(err)
	}

	// Verify dir exists
	if _, err := os.Stat(entry.CacheDir); err != nil {
		t.Fatalf("cache dir doesn't exist before delete: %v", err)
	}

	if err := s.Delete(entry.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(entry.CacheDir); !os.IsNotExist(err) {
		t.Error("cache dir still exists after Delete")
	}
}

func TestPutSourceSizePopulated(t *testing.T) {
	s := testStore(t)

	content := "this is test content with known size"
	src := writeSourceFile(t, content)

	entry, err := s.Put(src, "test", nil, map[string][]byte{"f.txt": []byte("d")})
	if err != nil {
		t.Fatal(err)
	}

	if entry.SourceSize != int64(len(content)) {
		t.Errorf("SourceSize = %d, want %d", entry.SourceSize, len(content))
	}
}

func TestPutMetadataInitialized(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "meta test")

	entry, err := s.Put(src, "test", nil, map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}

	if entry.Metadata == nil {
		t.Error("Metadata map is nil, should be initialized")
	}
}
