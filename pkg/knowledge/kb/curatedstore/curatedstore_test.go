package curatedstore

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSafeJoin(t *testing.T) {
	root := t.TempDir()
	if _, err := SafeJoin(root, "../escape"); err == nil {
		t.Fatal("../ escape must be rejected")
	}
	if _, err := SafeJoin(root, "/abs/path"); err == nil {
		t.Fatal("absolute path must be rejected")
	}
	if _, err := SafeJoin(root, "a/../../escape"); err == nil {
		t.Fatal("nested .. escape must be rejected")
	}
	got, err := SafeJoin(root, "sub/file.txt")
	if err != nil || got != filepath.Join(root, "sub", "file.txt") {
		t.Fatalf("in-tree join failed: %q %v", got, err)
	}
	// symlink escaping the root must be refused
	if runtime.GOOS != "windows" {
		outside := t.TempDir()
		link := filepath.Join(root, "evil")
		_ = os.Symlink(outside, link)
		if _, err := SafeJoin(root, "evil/x"); err == nil {
			t.Fatal("symlink-escape must be rejected")
		}
	}
}

func TestListAndRoot(t *testing.T) {
	base := t.TempDir()
	r := Root(base, "kb-abc")
	if r != filepath.Join(base, "apps", "kb-abc") {
		t.Fatalf("Root = %q", r)
	}
	_, _, exists, err := List(filepath.Join(base, "nope"), 10)
	if err != nil || exists {
		t.Fatalf("missing root: exists=%v err=%v (want false,nil)", exists, err)
	}
	vdir := filepath.Join(r, "versions", "v1")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a.js", "b.java", "c.txt"} {
		if err := os.WriteFile(filepath.Join(vdir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	es, trunc, exists, err := List(r, 2)
	if err != nil || !exists {
		t.Fatalf("List err=%v exists=%v", err, exists)
	}
	if len(es) != 2 || !trunc {
		t.Fatalf("bound: got %d entries trunc=%v want 2,true", len(es), trunc)
	}
	es2, trunc2, _, _ := List(r, 100)
	if len(es2) != 3 || trunc2 {
		t.Fatalf("unbounded: got %d trunc=%v want 3,false", len(es2), trunc2)
	}
}
