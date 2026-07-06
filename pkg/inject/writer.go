/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrPathTraversal is returned when outDir contains ".." segments.
var ErrPathTraversal = errors.New("inject: path traversal rejected")

// ErrSymlinkReject is returned when the destination already exists as a symlink.
var ErrSymlinkReject = errors.New("inject: symlink target rejected")

// WriteSeamsJSON writes result to <outDir>/security/injection_seams.json
// atomically. The outDir is rejected if it contains ".." segments.
//
// 16-05: this used to delegate to pkg/knowledge.WriteFileAtomic, but
// pkg/knowledge transitively imports pkg/dissect (via knowledge/extract.go).
// pkg/dissect now also imports pkg/inject for the seam scaffold, so we
// inline the temp+rename + symlink-reject + traversal-reject semantics
// here to break the import cycle. Behaviour mirrors
// pkg/knowledge/atomic.go::writeFileAtomic byte-for-byte.
func WriteSeamsJSON(outDir string, result *ScanResult) error {
	if result == nil {
		return errors.New("inject: nil result")
	}
	for _, seg := range strings.Split(filepath.ToSlash(outDir), "/") {
		if seg == ".." {
			return ErrPathTraversal
		}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal seams: %w", err)
	}

	target := filepath.Join(outDir, "security", "injection_seams.json")
	return writeFileAtomic(target, data, 0o644)
}

// writeFileAtomic writes data to path via temp-file-plus-rename. It rejects
// any path containing ".." segments and refuses to follow existing symlinks.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if seg == ".." {
			return ErrPathTraversal
		}
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve abs: %w", err)
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrSymlinkReject
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
