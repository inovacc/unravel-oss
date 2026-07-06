package aihost

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeTree is a minimal TreeWriter for exercising WriteTreeAtomic.
type fakeTree struct {
	walk     map[string][]byte
	manifest map[string][]byte
}

func (f fakeTree) Walk(fn func(path string, data []byte) error) error {
	for p, d := range f.walk {
		if err := fn(p, d); err != nil {
			return err
		}
	}
	return nil
}
func (f fakeTree) ManifestFiles() (map[string][]byte, error) { return f.manifest, nil }

func TestWriteTreeAtomic_WritesAndSweeps(t *testing.T) {
	target := t.TempDir()
	// Pre-existing stale file under a sweep dir — must be removed.
	stale := filepath.Join(target, "skills", "old", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	tree := fakeTree{
		walk:     map[string][]byte{"skills/new/SKILL.md": []byte("new")},
		manifest: map[string][]byte{".mcp.json": []byte("{}")},
	}
	n, err := WriteTreeAtomic(tree, target, []string{"skills"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("wrote %d files, want 2 (1 asset + 1 manifest)", n)
	}
	if _, err := os.Stat(filepath.Join(target, "skills", "new", "SKILL.md")); err != nil {
		t.Errorf("new asset not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, ".mcp.json")); err != nil {
		t.Errorf("manifest not written: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale file under sweep dir was not removed (err=%v)", err)
	}
}
