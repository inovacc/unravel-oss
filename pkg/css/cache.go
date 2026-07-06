/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/store"
)

const (
	cacheEntryType = "css-extraction"
	cacheDataFile  = "result.json"
	cacheTagPrefix = "css-"
)

// CachedExtract wraps Extract with store-backed caching.
// On cache hit the stored result is returned without re-extraction.
// If opts.NoCache is true, the cache is bypassed entirely.
func CachedExtract(path string, opts Options) (*Result, error) {
	if opts.NoCache {
		return Extract(path, opts)
	}

	s := store.New()
	key := cacheKey(path, opts)

	// Try cache lookup.
	cached, err := cacheLookup(s, key)
	if err == nil && cached != nil {
		cached.OutputDir = opts.OutputDir // update to caller's output dir
		return cached, nil
	}

	// Cache miss: run extraction.
	result, err := Extract(path, opts)
	if err != nil {
		return nil, err
	}

	// Store in cache (best-effort, don't fail on cache errors).
	_ = cacheStore(s, key, result)

	return result, nil
}

// cacheKey produces a SHA-256 hex digest of the input path and relevant options.
func cacheKey(path string, opts Options) string {
	h := sha256.New()

	// Include absolute path for uniqueness.
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	h.Write([]byte(abs))
	h.Write([]byte{0x00})

	// Include file modification time if available.
	if info, statErr := os.Stat(path); statErr == nil {
		h.Write([]byte(info.ModTime().String()))
	}
	h.Write([]byte{0x00})

	// Include option flags that affect output.
	flags := fmt.Sprintf("n=%v,d=%v,ri=%v,rv=%v,ru=%v",
		opts.Normalize, opts.Deduplicate, opts.ResolveImports,
		opts.ResolveVars, opts.RemoveUnused)
	h.Write([]byte(flags))

	return hex.EncodeToString(h.Sum(nil))
}

// cacheLookup searches for a cached CSS extraction result by key.
func cacheLookup(s *store.Store, key string) (*Result, error) {
	entries, err := s.List()
	if err != nil {
		return nil, fmt.Errorf("cache lookup: %w", err)
	}

	for _, e := range entries {
		if e.Type != cacheEntryType {
			continue
		}

		// Check metadata for cache key match.
		if e.Metadata != nil && e.Metadata["cache_key"] == key {
			return readCachedResult(s, e.ID)
		}

		// Fallback: check metadata.json sidecar.
		metaPath := filepath.Join(e.CacheDir, "metadata.json")
		metaData, readErr := os.ReadFile(metaPath)
		if readErr != nil {
			continue
		}

		var meta map[string]string
		if jsonErr := json.Unmarshal(metaData, &meta); jsonErr != nil {
			continue
		}

		if meta["cache_key"] == key {
			return readCachedResult(s, e.ID)
		}
	}

	return nil, nil // cache miss
}

// readCachedResult reads and deserializes a Result from a cache entry.
func readCachedResult(s *store.Store, id string) (*Result, error) {
	data, err := s.ReadFile(id, cacheDataFile)
	if err != nil {
		return nil, nil // corrupted entry treated as miss
	}

	var result Result
	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		return nil, nil // corrupted data treated as miss
	}

	return &result, nil
}

// cacheStore writes a CSS extraction result to the store.
func cacheStore(s *store.Store, key string, result *Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("cache store marshal: %w", err)
	}

	tags := []string{cacheTagPrefix + key[:8]}

	entry, err := s.Put(
		"css://"+key,
		cacheEntryType,
		tags,
		map[string][]byte{cacheDataFile: data},
	)
	if err != nil {
		return fmt.Errorf("cache store put: %w", err)
	}

	// Write metadata sidecar for durable lookup.
	if entry.Metadata == nil {
		entry.Metadata = make(map[string]string)
	}
	entry.Metadata["cache_key"] = key

	metaBytes, _ := json.Marshal(entry.Metadata)
	metaPath := filepath.Join(entry.CacheDir, "metadata.json")
	if writeErr := os.WriteFile(metaPath, metaBytes, 0o644); writeErr != nil {
		return fmt.Errorf("cache store metadata: %w", writeErr)
	}

	return nil
}
