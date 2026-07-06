/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// errPathTraversal is returned when a write target resolves outside the intended
// directory tree (T-07-01).
var errPathTraversal = errors.New("knowledge: path traversal rejected")

// errSymlinkReject is returned when the write target is an existing symlink
// (T-07-02).
var errSymlinkReject = errors.New("knowledge: symlink target rejected")

// writeFileAtomic writes data to path using a temp-file-plus-rename so that
// readers never observe a partial file. It rejects any path containing ".."
// segments after Clean and refuses to follow symlinks at the destination.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	// T-07-01: reject any ".." segment in the raw input. Checking after Clean
	// would silently allow `tmp/../escape.txt` (Clean rewrites it to
	// `escape.txt` at the parent), defeating the trust boundary.
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if seg == ".." {
			return errPathTraversal
		}
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve abs: %w", err)
	}
	// T-07-02: reject symlink targets via Lstat (does not follow links).
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errSymlinkReject
		}
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// writeJSONAtomic marshals v with indented JSON and writes it via writeFileAtomic.
func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	return writeFileAtomic(path, data, 0o644)
}

// WriteFileAtomic is the exported entry point used by Phase 8 (pkg/capture/visual)
// and any future package needing temp+rename + symlink-reject + path-traversal-rejection
// semantics. Thin forwarder over writeFileAtomic to keep one source of truth (D-19/D-22).
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomic(path, data, perm)
}

// WriteJSONAtomic marshals v as indented JSON and writes atomically with the same guards.
func WriteJSONAtomic(path string, v any) error {
	return writeJSONAtomic(path, v)
}
