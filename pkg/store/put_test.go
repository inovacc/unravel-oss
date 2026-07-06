/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPut_ShardedLayoutAndSize(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "hello")
	data := map[string][]byte{"result.json": []byte(`{"a":1}`), "notes.txt": []byte("hi")}

	e, err := s.Put(src, "dissect", []string{"t"}, data)
	if err != nil {
		t.Fatal(err)
	}

	// Size = sum of data byte lengths.
	want := int64(len(`{"a":1}`) + len("hi"))
	if e.Size != want {
		t.Errorf("Size = %d, want %d", e.Size, want)
	}

	// CacheDir is cache/{2hex}/{id}.
	rel, _ := filepath.Rel(s.baseDir, e.CacheDir)
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 2 || len(parts[0]) != 2 || parts[1] != e.ID {
		t.Fatalf("CacheDir rel %q not {2hex}/{id}", rel)
	}
	if parts[0] != shardFor(e.ID) {
		t.Errorf("bucket %q != shardFor(id) %q", parts[0], shardFor(e.ID))
	}

	// Payload round-trips through the sharded path.
	got, err := s.ReadFile(e.ID, "result.json")
	if err != nil || string(got) != `{"a":1}` {
		t.Errorf("ReadFile = %q, %v", got, err)
	}

	// Index is marked sharded.
	idx, _ := s.readIndex()
	if idx.Version != IndexVersionSharded {
		t.Errorf("index version = %d, want %d", idx.Version, IndexVersionSharded)
	}
}
