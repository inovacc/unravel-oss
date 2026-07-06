/*
Copyright (c) 2026 Security Research
*/

// TreeWriter + WriteTreeAtomic are the shared asset-tree writer for hosts
// that need only a plain tree write (no host-specific install ritual). The
// claude host keeps its own writer in claude/install.go because it interleaves
// settings.json + marketplace patching; codex/gemini can share this instead of
// each duplicating the loop.
//
// Contract: every file from Walk + ManifestFiles is written via tmp+rename
// (atomic). After the write, any pre-existing file under a sweepDir (relative
// to target) NOT produced this run is removed, so an install over an older
// tree drops stale assets.

package aihost

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// TreeWriter is the host surface WriteTreeAtomic needs: the rendered asset
// tree (Walk) plus the manifest files (.<host>-plugin/..., .mcp.json).
// claude.Host, codex.Host, and gemini.Host all satisfy it.
type TreeWriter interface {
	// Walk invokes fn once per rendered asset with its slash-relative path
	// and bytes. A non-nil fn error aborts the walk.
	Walk(fn func(path string, data []byte) error) error
	// ManifestFiles returns the plugin manifest files keyed by slash-relative
	// path (e.g. ".mcp.json").
	ManifestFiles() (map[string][]byte, error)
}

// WriteTreeAtomic writes every asset + manifest file from h into target using
// tmp+rename, then sweeps stale files under sweepDirs. Returns the number of
// files written.
func WriteTreeAtomic(h TreeWriter, target string, sweepDirs []string) (int, error) {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return 0, fmt.Errorf("aihost: mkdir %s: %w", target, err)
	}
	wanted := map[string]struct{}{}
	count := 0
	writeOne := func(rel string, data []byte) error {
		dst := filepath.Join(target, filepath.FromSlash(rel))
		wanted[filepath.Clean(dst)] = struct{}{}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("aihost: mkdir parent of %s: %w", rel, err)
		}
		if err := atomicWriteFile(dst, data); err != nil {
			return fmt.Errorf("aihost: write %s: %w", rel, err)
		}
		count++
		return nil
	}
	if err := h.Walk(writeOne); err != nil {
		return count, err
	}
	mfs, err := h.ManifestFiles()
	if err != nil {
		return count, err
	}
	for rel, data := range mfs {
		if err := writeOne(rel, data); err != nil {
			return count, err
		}
	}
	for _, sub := range sweepDirs {
		subPath := filepath.Join(target, sub)
		_ = filepath.WalkDir(subPath, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return nil
			}
			if _, ok := wanted[filepath.Clean(p)]; !ok {
				if rmErr := os.Remove(p); rmErr == nil {
					fmt.Fprintf(os.Stderr, "[install] swept stale: %s\n", p)
				}
			}
			return nil
		})
	}
	return count, nil
}

func atomicWriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
