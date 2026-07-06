/*
Copyright (c) 2026 Security Research
*/
package cve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// cacheTTL is the canonical 24h disk-cache TTL (D-04).
const cacheTTL = 24 * time.Hour

// cache is a (source, ecosystem, package, version)-keyed file cache rooted at
// $UserCacheDir/unravel/cve/<source>/<key>.json.
type cache struct {
	root     string // overridable for tests
	disabled bool
}

// newCache returns a fresh cache rooted under the user cache dir. Falls back
// to a temp dir if UserCacheDir is unavailable.
func newCache() *cache {
	root, err := os.UserCacheDir()
	if err != nil {
		root = os.TempDir()
	}
	return &cache{root: filepath.Join(root, "unravel", "cve")}
}

// newCacheAt returns a cache rooted at an explicit path (used by tests).
func newCacheAt(root string) *cache {
	return &cache{root: root}
}

// disabledCache returns a noop cache (used when Options.NoCache is set).
func disabledCache() *cache { return &cache{disabled: true} }

// CacheKey derives the deterministic key for a (ecosystem, package, version,
// source) tuple. Returns the first 32 hex chars of sha256.
func CacheKey(ecosystem, pkg, version, source string) string {
	h := sha256.New()
	h.Write([]byte(ecosystem))
	h.Write([]byte{0})
	h.Write([]byte(pkg))
	h.Write([]byte{0})
	h.Write([]byte(version))
	h.Write([]byte{0})
	h.Write([]byte(source))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// path returns the on-disk path for (source, key).
func (c *cache) path(source, key string) string {
	return filepath.Join(c.root, source, key+".json")
}

// Get returns (data, true) on a fresh hit; (nil, false) on miss or stale.
func (c *cache) Get(source, key string) ([]byte, bool) {
	if c == nil || c.disabled {
		return nil, false
	}
	p := c.path(source, key)
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > cacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return data, true
}

// Put atomically writes data to (source, key) using the path-traversal-guarded
// writer from pkg/knowledge.
func (c *cache) Put(source, key string, data []byte) error {
	if c == nil || c.disabled {
		return nil
	}
	p := c.path(source, key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("cve cache mkdir: %w", err)
	}
	return writeFileAtomicLocal(p, data, 0o600)
}

// writeFileAtomicLocal is an in-package mirror of knowledge.WriteFileAtomic
// (path-traversal-rejecting + symlink-rejecting + temp+rename). Inlined to
// break the pkg/knowledge → pkg/cve import cycle introduced when
// pkg/knowledge gained a CVE-aware deps writer (14-02).
func writeFileAtomicLocal(path string, data []byte, perm os.FileMode) error {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if seg == ".." {
			return fmt.Errorf("cve cache: path traversal rejected")
		}
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("cve cache: resolve abs: %w", err)
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cve cache: symlink target rejected")
		}
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("cve cache: mkdir parent: %w", err)
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("cve cache: write tmp: %w", err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cve cache: rename: %w", err)
	}
	return nil
}
