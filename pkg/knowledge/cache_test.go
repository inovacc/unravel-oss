/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	return store.NewWithDir(filepath.Join(dir, "cache"))
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestCacheLookupNamespaceByType(t *testing.T) {
	s := newTestStore(t)
	payload := []byte("class Bar {}")
	hash := sha(payload)

	if err := beautifyCachePut(s, hash, "beautify-java", "src/Bar.java", payload); err != nil {
		t.Fatalf("put: %v", err)
	}

	if got, hit, err := beautifyCacheLookup(s, hash, "beautify-java"); err != nil || !hit {
		t.Fatalf("same-type lookup: hit=%v err=%v", hit, err)
	} else if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch")
	}
	// Cross-type lookup MUST miss (Pitfall 4 — namespace by Type).
	if _, hit, err := beautifyCacheLookup(s, hash, "beautify-js"); err != nil {
		t.Fatalf("cross-type lookup err: %v", err)
	} else if hit {
		t.Fatal("cross-type cache hit; namespace collision (Pitfall 4)")
	}
}

func TestCachePutAtomicWrite(t *testing.T) {
	s := newTestStore(t)
	payload := []byte("hello-atomic")
	hash := sha(payload)
	if err := beautifyCachePut(s, hash, "beautify-java", "src/X.java", payload); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, hit, err := beautifyCacheLookup(s, hash, "beautify-java")
	if err != nil || !hit {
		t.Fatalf("lookup: hit=%v err=%v", hit, err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("payload mismatch")
	}
}

func TestCacheLargeInputBail(t *testing.T) {
	s := newTestStore(t)
	big := bytes.Repeat([]byte{'x'}, 51*1024*1024) // 51 MiB
	hash := sha(big)
	err := beautifyCachePut(s, hash, "beautify-java", "src/Big.java", big)
	if err == nil {
		t.Fatal("want error for >50 MiB payload, got nil")
	}
	if _, hit, _ := beautifyCacheLookup(s, hash, "beautify-java"); hit {
		t.Error("payload was written despite size cap")
	}
}

func TestCacheMissReturnsFalse(t *testing.T) {
	s := newTestStore(t)
	if _, hit, err := beautifyCacheLookup(s, sha([]byte("nope")), "beautify-java"); err != nil {
		t.Fatalf("err: %v", err)
	} else if hit {
		t.Fatal("unexpected hit on empty store")
	}
}
