/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// WalkOptions configures WalkDirectory. Zero values are replaced with the
// defaults documented on each field.
type WalkOptions struct {
	// MaxDepth bounds the walk; default 6.
	MaxDepth int
	// RejectSymlinks, when true, skips any symlinked entries and records a
	// "symlink rejected: <path>" note in XAMLIndex.Errors. Default true.
	RejectSymlinks bool
	// IncludeXBF, when true, records *.xbf files with Kind:"xbf" but does NOT
	// decode them (plan 04 does that). Default true.
	IncludeXBF bool
	// MaxFileSize bounds per-file parsing; oversized files are recorded as
	// XAMLEntry with Errors only. Default 16 MiB.
	MaxFileSize int64

	// rejectSymlinksSet distinguishes a deliberate `false` from the zero
	// value when applying defaults.
	rejectSymlinksSet bool
	// includeXBFSet distinguishes a deliberate `false` from the zero value.
	includeXBFSet bool
}

// DefaultWalkOptions returns the canonical defaults applied when fields are
// left at zero values.
func DefaultWalkOptions() WalkOptions {
	return WalkOptions{
		MaxDepth:          6,
		RejectSymlinks:    true,
		IncludeXBF:        true,
		MaxFileSize:       16 << 20,
		rejectSymlinksSet: true,
		includeXBFSet:     true,
	}
}

func (o *WalkOptions) applyDefaults() {
	d := DefaultWalkOptions()
	if o.MaxDepth <= 0 {
		o.MaxDepth = d.MaxDepth
	}
	if !o.rejectSymlinksSet && !o.RejectSymlinks {
		o.RejectSymlinks = d.RejectSymlinks
	}
	if !o.includeXBFSet && !o.IncludeXBF {
		o.IncludeXBF = d.IncludeXBF
	}
	if o.MaxFileSize <= 0 {
		o.MaxFileSize = d.MaxFileSize
	}
}

// WalkDirectory traverses root with depth/size/symlink guards and produces a
// winui.XAMLIndex of raw *.xaml entries (parsed) and *.xbf entries
// (recorded only). Top-level audit notices land in the returned index's
// Errors slice. Per-file parse problems land in XAMLEntry.Errors.
func WalkDirectory(root string, opts WalkOptions) (*winui.XAMLIndex, error) {
	opts.applyDefaults()

	cleanRoot := filepath.Clean(root)
	if strings.Contains(cleanRoot, "..") {
		return nil, fmt.Errorf("walk root contains '..': %q", root)
	}
	absRoot, err := filepath.Abs(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve root: %w", err)
	}
	info, err := os.Lstat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("stat root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("walk root is a symlink: %q", absRoot)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("walk root is not a directory: %q", absRoot)
	}

	idx := &winui.XAMLIndex{Entries: []winui.XAMLEntry{}}

	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			idx.Errors = append(idx.Errors, fmt.Sprintf("walk error %s: %v", path, werr))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == absRoot {
			return nil
		}
		rel, rerr := filepath.Rel(absRoot, path)
		if rerr != nil {
			idx.Errors = append(idx.Errors, fmt.Sprintf("rel error %s: %v", path, rerr))
			return nil
		}
		depth := strings.Count(rel, string(filepath.Separator)) + 1
		if depth > opts.MaxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Symlink rejection — d.Type() reflects the entry's own type without
		// dereferencing.
		if d.Type()&fs.ModeSymlink != 0 {
			if opts.RejectSymlinks {
				idx.Errors = append(idx.Errors, fmt.Sprintf("symlink rejected: %s", rel))
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			return nil
		}

		lower := strings.ToLower(d.Name())
		switch {
		case strings.HasSuffix(lower, ".xaml"):
			processXAML(idx, path, rel, opts)
		case strings.HasSuffix(lower, ".xbf"):
			if opts.IncludeXBF {
				processXBF(idx, path, rel)
			}
		}
		return nil
	})
	if walkErr != nil {
		idx.Errors = append(idx.Errors, fmt.Sprintf("walk: %v", walkErr))
	}
	return idx, nil
}

func processXAML(idx *winui.XAMLIndex, abs, rel string, opts WalkOptions) {
	st, err := os.Stat(abs)
	if err != nil {
		idx.Entries = append(idx.Entries, winui.XAMLEntry{
			Path:   rel,
			Kind:   "raw",
			Errors: []string{fmt.Sprintf("stat: %v", err)},
		})
		return
	}
	size := st.Size()
	if size > opts.MaxFileSize {
		idx.Entries = append(idx.Entries, winui.XAMLEntry{
			Path:        rel,
			Kind:        "raw",
			SourceBytes: size,
			Errors:      []string{fmt.Sprintf("file size exceeds limit: %dB > %dB", size, opts.MaxFileSize)},
		})
		return
	}
	entry, perr := ParseRawXAML(abs)
	entry.Path = rel
	entry.SourceBytes = size
	if perr != nil {
		entry.Errors = append(entry.Errors, fmt.Sprintf("open: %v", perr))
	}
	idx.Entries = append(idx.Entries, entry)
}

func processXBF(idx *winui.XAMLIndex, abs, rel string) {
	st, err := os.Stat(abs)
	e := winui.XAMLEntry{Path: rel, Kind: "xbf"}
	if err != nil {
		e.Errors = append(e.Errors, fmt.Sprintf("stat: %v", err))
	} else {
		e.SourceBytes = st.Size()
	}
	idx.Entries = append(idx.Entries, e)
}
