/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
)

// WriteLatestPointer creates or updates <kbDir>/visual/latest as a symlink to
// <runID>. On Windows non-Developer-Mode accounts the symlink fails with
// ERROR_PRIVILEGE_NOT_HELD; the function then falls back to writing
// <kbDir>/visual/latest.txt containing the runID slug (D-12, RESEARCH Pitfall 2).
//
// This is the SOLE curated symlink Phase 8 ever creates; D-19 symlink-reject
// remains in force for every other write site.
func WriteLatestPointer(kbDir, runID string) error {
	if err := validateSlug(runID); err != nil {
		return err
	}
	base := filepath.Join(kbDir, "visual")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return fmt.Errorf("mkdir visual/: %w", err)
	}
	link := filepath.Join(base, "latest")
	tmp := link + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(runID, tmp); err != nil {
		// Windows fallback (privilege not held) OR any symlink failure.
		return knowledge.WriteFileAtomic(filepath.Join(base, "latest.txt"), []byte(runID), 0o644)
	}
	_ = os.Remove(link)
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return knowledge.WriteFileAtomic(filepath.Join(base, "latest.txt"), []byte(runID), 0o644)
	}
	return nil
}

// validateSlug rejects empty values, path separators, and pure-dot inputs.
func validateSlug(s string) error {
	if s == "" {
		return fmt.Errorf("empty run-id")
	}
	if strings.ContainsAny(s, "/\\") {
		return fmt.Errorf("invalid run-id slug: %q", s)
	}
	if s == "." || s == ".." {
		return fmt.Errorf("invalid run-id slug: %q", s)
	}
	return nil
}
