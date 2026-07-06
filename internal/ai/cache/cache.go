/*
Copyright (c) 2026 Security Research

Phase 11 / Wave 0 (D-08, D-15): Shared sha256+0x00+modelID cache lifted from
pkg/forensic/exec_summary.go (RPT-04) and pkg/frida/enrich/cache.go (FRIDA-01).
The 0x00 separator carries forward Phase 9 Pitfall 2 collision defense:
without it, (a, b) and (a', b') concatenations could alias.

On-disk layout: <store.CacheDir()>/<namespace>/<filename>.
Atomic writes via temp + os.Rename (D-15). Any I/O error on Get is a miss.
*/
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/store"
)

// Key returns hex(sha256(prompt || 0x00 || modelID)).
// Byte-identical to pre-lift forensic.ComputeCacheKey and frida.computeCacheKey
// for the same inputs (Phase 11 D-08, RESEARCH Pitfall 1).
func Key(prompt, modelID string) string {
	h := sha256.New()
	h.Write([]byte(prompt))
	h.Write([]byte{0x00})
	h.Write([]byte(modelID))
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached body. Any I/O error (incl. ENOENT) is a miss.
func Get(namespace, filename string) ([]byte, bool) {
	body, err := os.ReadFile(path(namespace, filename))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		return nil, false
	}
	return body, true
}

// Put writes atomically (unique temp + os.Rename). MkdirAll(0o755) is
// idempotent. A unique per-call temp file (os.CreateTemp in the destination
// dir) avoids the fixed-name torn-rename race when two goroutines cache the
// same key concurrently, and the temp file is removed on any failure path so
// a rename error (Windows sharing violation, EXDEV, locked dest) cannot leak
// an orphan *.tmp. Mirrors pkg/store/store.go writeIndex.
func Put(namespace, filename string, body []byte) error {
	p := path(namespace, filename)
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(filename)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Clean up the temp file on every error path before returning. On the
	// happy path the rename consumes tmp, so the remove becomes a no-op.
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func path(ns, filename string) string {
	return filepath.Join(store.CacheDir(), ns, filename)
}
