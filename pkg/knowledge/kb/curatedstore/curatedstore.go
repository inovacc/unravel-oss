// Package curatedstore is the read-only retrieval layer for the on-disk
// curated kb-store artifacts (<store-base>/apps/<kb_id>/versions/<ks_id>/**).
// Pure: filesystem-only, no DB, no AI, no writes.
package curatedstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrPathEscape is returned when a requested relative path would escape the
// per-kb_id curated root.
var ErrPathEscape = errors.New("curatedstore: path escapes kb-store root")

// Root returns the curated root for a canonical kb_id under storeBase
// (storeBase is fsutil.KBStoreRoot()): <storeBase>/apps/<kbID>.
func Root(storeBase, kbID string) string {
	return filepath.Join(storeBase, "apps", kbID)
}

// SafeJoin cleans rel and guarantees the result stays within root. Rejects
// absolute paths, any ".." segment, and any path whose final location (after
// symlink evaluation of existing components) escapes root.
func SafeJoin(root, rel string) (string, error) {
	if rel == "" {
		return root, nil
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") {
		return "", ErrPathEscape
	}
	for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
		if seg == ".." {
			return "", ErrPathEscape
		}
	}
	joined := filepath.Join(root, filepath.FromSlash(rel))
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	// Reject if any existing ancestor within the path is a symlink leaving root.
	if real, err := filepath.EvalSymlinks(absJoined); err == nil {
		realRoot, _ := filepath.EvalSymlinks(absRoot)
		if realRoot == "" {
			realRoot = absRoot
		}
		if real != realRoot && !strings.HasPrefix(real, realRoot+string(os.PathSeparator)) {
			return "", ErrPathEscape
		}
	}
	if absJoined != absRoot && !strings.HasPrefix(absJoined, absRoot+string(os.PathSeparator)) {
		return "", ErrPathEscape
	}
	return joined, nil
}

// Entry is one curated artifact.
type Entry struct {
	Path     string `json:"path"` // relative to the kb_id root
	Size     int64  `json:"size"`
	Category string `json:"category"` // beautified|decompiled|reconstructed|decrypted|other
}

func categorize(rel string) string {
	l := strings.ToLower(rel)
	switch {
	case strings.Contains(l, "beautif") || strings.HasSuffix(l, ".beautified.js"):
		return "beautified"
	case strings.Contains(l, "decompil") || strings.HasSuffix(l, ".java") || strings.HasSuffix(l, ".cs"):
		return "decompiled"
	case strings.Contains(l, "reconstruct") || strings.Contains(l, "/src/"):
		return "reconstructed"
	case strings.Contains(l, "decrypt"):
		return "decrypted"
	default:
		return "other"
	}
}

// List walks root (typically Root(...)) returning up to max entries (sorted
// by relative path for determinism), a truncated flag, and exists=false when
// root does not exist (an explicit honest-empty, not an error).
func List(root string, max int) (entries []Entry, truncated bool, exists bool, err error) {
	if fi, statErr := os.Stat(root); statErr != nil || !fi.IsDir() {
		if os.IsNotExist(statErr) {
			return nil, false, false, nil
		}
		if statErr != nil {
			return nil, false, false, statErr
		}
		return nil, false, false, nil
	}
	var all []Entry
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, rErr := filepath.Rel(root, p)
		if rErr != nil {
			return rErr
		}
		info, iErr := d.Info()
		if iErr != nil {
			return iErr
		}
		all = append(all, Entry{Path: filepath.ToSlash(rel), Size: info.Size(), Category: categorize(rel)})
		return nil
	})
	if walkErr != nil {
		return nil, false, true, walkErr
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Path < all[j].Path })
	if max > 0 && len(all) > max {
		return all[:max], true, true, nil
	}
	return all, false, true, nil
}
