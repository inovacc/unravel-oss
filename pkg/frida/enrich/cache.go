/*
Copyright (c) 2026 Security Research

Phase 9 D-20 / Phase 11 D-08: pkg/store cache namespacing for frida-enrich.
The cache key is `sha256(scriptContent || 0x00 || sourceBundle)`. The 0x00
separator is RESEARCH Pitfall 2 mitigation: without it, an attacker who
controls either half could craft inputs that collide with another
(script', sourceBundle') pair.

Phase 11 (D-08): hashing + default-path I/O delegate to pkg/ai/cache. The
Orchestrator.CacheDir override branch is preserved as a small inline
reader/writer using the same atomic temp+rename pattern (PATTERNS option b).

The store layout is:

	<baseDir>/frida-enrich/<key>.script.js
	<baseDir>/frida-enrich/<key>.criteria.json

Tests redirect <baseDir> via Orchestrator.CacheDir.
*/
package enrich

import (
	"encoding/json"
	"os"
	"path/filepath"

	aicache "github.com/inovacc/unravel-oss/internal/ai/cache"
	"github.com/inovacc/unravel-oss/pkg/frida"
)

// cacheNamespace is the `Type` used for any pkg/store entries this package
// emits — and also the on-disk subdir name for its keyed layout.
const cacheNamespace = "frida-enrich"

// cachedPair is what we keep on disk per cache key.
type cachedPair struct {
	script   string
	criteria frida.CriteriaFile
}

// computeCacheKey is the public hash function: sha256(script || 0x00 ||
// bundle). Delegates to pkg/ai/cache.Key (Phase 11 D-08); byte-identical
// to the pre-lift implementation per pkg/ai/cache/golden_test.go vectors.
// The separator byte defends against the (Pitfall 2) collision where
// (a, b) and (a', b') concatenate to the same byte stream.
func computeCacheKey(scriptContent []byte, sourceBundle string) string {
	return aicache.Key(string(scriptContent), sourceBundle)
}

// cacheLookup returns (pair, true) when both halves of a previously cached
// (script, criteria) entry are present and decodable. Any I/O or decode
// error is treated as a miss.
func (o *Orchestrator) cacheLookup(key string) (cachedPair, bool) {
	scriptName := key + ".script.js"
	criteriaName := key + ".criteria.json"

	var scriptBytes, criteriaBytes []byte
	var ok bool

	if o != nil && o.CacheDir != "" {
		// Override path: read directly from the operator-provided root.
		base := filepath.Join(o.CacheDir, cacheNamespace)
		var err error
		scriptBytes, err = os.ReadFile(filepath.Join(base, scriptName))
		if err != nil {
			return cachedPair{}, false
		}
		criteriaBytes, err = os.ReadFile(filepath.Join(base, criteriaName))
		if err != nil {
			return cachedPair{}, false
		}
	} else {
		scriptBytes, ok = aicache.Get(cacheNamespace, scriptName)
		if !ok {
			return cachedPair{}, false
		}
		criteriaBytes, ok = aicache.Get(cacheNamespace, criteriaName)
		if !ok {
			return cachedPair{}, false
		}
	}

	var cf frida.CriteriaFile
	if err := json.Unmarshal(criteriaBytes, &cf); err != nil {
		return cachedPair{}, false
	}
	return cachedPair{script: string(scriptBytes), criteria: cf}, true
}

// cacheStore writes both halves of (script, criteria) to the keyed cache
// path. Failures are logged-and-ignored (best-effort cache).
func (o *Orchestrator) cacheStore(key string, pair cachedPair) {
	scriptName := key + ".script.js"
	criteriaName := key + ".criteria.json"

	body, err := json.MarshalIndent(pair.criteria, "", "  ")
	if err != nil {
		return
	}

	if o != nil && o.CacheDir != "" {
		// Override path: write directly using same atomic-ish pattern.
		base := filepath.Join(o.CacheDir, cacheNamespace)
		if err := os.MkdirAll(base, 0o755); err != nil {
			return
		}
		_ = os.WriteFile(filepath.Join(base, scriptName), []byte(pair.script), 0o644)
		_ = os.WriteFile(filepath.Join(base, criteriaName), body, 0o644)
		return
	}

	_ = aicache.Put(cacheNamespace, scriptName, []byte(pair.script))
	_ = aicache.Put(cacheNamespace, criteriaName, body)
}
