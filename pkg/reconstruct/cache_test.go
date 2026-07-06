package reconstruct

import (
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/store"
)

func TestCacheKeyDeterministic(t *testing.T) {
	k1 := CacheKey("content", "v1")
	k2 := CacheKey("content", "v1")
	if k1 != k2 {
		t.Errorf("same inputs should produce same key: %s != %s", k1, k2)
	}
}

func TestCacheKeyDiffersByPromptVersion(t *testing.T) {
	k1 := CacheKey("same content", "v1")
	k2 := CacheKey("same content", "v2")
	if k1 == k2 {
		t.Error("different prompt versions should produce different keys")
	}
}

func TestCacheKeyDiffersByContent(t *testing.T) {
	k1 := CacheKey("content A", "v1")
	k2 := CacheKey("content B", "v1")
	if k1 == k2 {
		t.Error("different content should produce different keys")
	}
}

func TestCacheKeyIsSHA256Hex(t *testing.T) {
	k := CacheKey("test", "v1")
	if len(k) != 64 {
		t.Errorf("expected 64 hex chars (SHA-256), got %d: %s", len(k), k)
	}
}

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := store.NewWithDir(dir)

	result := &Result{
		Content: "public class Foo {}",
		Stage:   "complete",
		Provenance: &Provenance{
			PromptVersion: "v1",
			Model:         "claude-4",
			Timestamp:     time.Now().UTC(),
		},
	}

	key := CacheKey("original content", "v1")

	err := CacheStore(s, key, result)
	if err != nil {
		t.Fatalf("CacheStore failed: %v", err)
	}

	got, err := CacheLookup(s, key)
	if err != nil {
		t.Fatalf("CacheLookup failed: %v", err)
	}
	if got == nil {
		t.Fatal("CacheLookup returned nil for cached entry")
	}
	if got.Content != result.Content {
		t.Errorf("content mismatch: got %q, want %q", got.Content, result.Content)
	}
	if got.Stage != result.Stage {
		t.Errorf("stage mismatch: got %q, want %q", got.Stage, result.Stage)
	}
}

func TestCacheLookupMiss(t *testing.T) {
	dir := t.TempDir()
	s := store.NewWithDir(dir)

	got, err := CacheLookup(s, "nonexistent-key")
	if err != nil {
		t.Fatalf("unexpected error on cache miss: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil on cache miss, got %+v", got)
	}
}
