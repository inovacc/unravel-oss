// Copyright (c) 2026 Security Research
package enrich

import (
	"strings"
	"testing"
)

// TestCacheKeyDistinctOnSourceBundleChange enforces RESEARCH Pitfall 2:
// the 0x00 separator means (script, bundle) and (script', bundle') with
// the same naive concatenation must map to different keys.
func TestCacheKeyDistinctOnSourceBundleChange(t *testing.T) {
	a := computeCacheKey([]byte("ab"), "cd")
	b := computeCacheKey([]byte("a"), "bcd")
	if a == b {
		t.Fatalf("cache key collision: separator missing — keys equal %q", a)
	}
}

func TestCacheKeyStableForSameInputs(t *testing.T) {
	a := computeCacheKey([]byte("script-body"), "bundle-body")
	b := computeCacheKey([]byte("script-body"), "bundle-body")
	if a != b {
		t.Errorf("cache key not stable: %q != %q", a, b)
	}
}

func TestCacheKeyHexShape(t *testing.T) {
	k := computeCacheKey([]byte("x"), "y")
	if len(k) != 64 {
		t.Errorf("expected 64-char sha256 hex, got %d (%q)", len(k), k)
	}
	if strings.ContainsAny(k, "GHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("expected lowercase hex")
	}
}

func TestCacheLookup_MissReturnsFalse(t *testing.T) {
	o := &Orchestrator{CacheDir: t.TempDir()}
	if _, ok := o.cacheLookup("nonexistent-key"); ok {
		t.Errorf("expected miss")
	}
}
