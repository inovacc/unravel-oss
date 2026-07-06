package reconstruct

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
	cacheEntryType = "reconstruction"
	cacheDataFile  = "result.json"
	cacheTagPrefix = "recon-"
)

// CacheKey produces a SHA-256 hex digest of content + null byte + promptVersion.
// The null byte separator prevents collisions between content/version boundaries.
func CacheKey(content string, promptVersion string) string {
	h := sha256.New()
	h.Write([]byte(content))
	h.Write([]byte{0x00}) // null byte separator
	h.Write([]byte(promptVersion))
	return hex.EncodeToString(h.Sum(nil))
}

// CacheLookup searches for a cached reconstruction result by key.
// Returns nil, nil on cache miss (not an error).
func CacheLookup(s *store.Store, key string) (*Result, error) {
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

		// Fallback: check the metadata.json file inside the entry dir.
		metaPath := filepath.Join(e.CacheDir, "metadata.json")
		metaData, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}

		var meta map[string]string
		if err := json.Unmarshal(metaData, &meta); err != nil {
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
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, nil // corrupted data treated as miss
	}

	return &result, nil
}

// CacheStore writes a reconstruction result to the store with provenance metadata.
func CacheStore(s *store.Store, key string, result *Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("cache store marshal: %w", err)
	}

	promptVersion := ""
	if result.Provenance != nil {
		promptVersion = result.Provenance.PromptVersion
	}

	tags := []string{cacheTagPrefix + key[:8]} // short prefix tag for quick filtering

	entry, err := s.Put(
		"reconstruction://"+key, // virtual source path using key
		cacheEntryType,
		tags,
		map[string][]byte{cacheDataFile: data},
	)
	if err != nil {
		return fmt.Errorf("cache store put: %w", err)
	}

	// Set metadata on the entry for lookup.
	if entry.Metadata == nil {
		entry.Metadata = make(map[string]string)
	}
	entry.Metadata["cache_key"] = key
	entry.Metadata["prompt_version"] = promptVersion

	// Write metadata as a file inside the entry directory for durable lookup.
	metaBytes, _ := json.Marshal(entry.Metadata)
	metaPath := filepath.Join(entry.CacheDir, "metadata.json")
	if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
		return fmt.Errorf("cache store metadata: %w", err)
	}

	return nil
}
