/*
Copyright (c) 2026 Security Research
*/

// Package asar repatch.go: write API that rebuilds an ASAR archive with
// selected entries replaced by new bytes. Pure additive — does not touch
// the existing read-only API. See plan 46-01.
package asar

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrAsarRepatchEntryNotFound indicates a replacement path was supplied
// for an entry that does not exist in the source ASAR.
var ErrAsarRepatchEntryNotFound = errors.New("asar: repatch entry not found")

// ErrAsarRepatchSizeMismatch wraps unexpected offset/size rebuild failures.
// In v1 this should be unreachable; we keep it for forensic logging.
var ErrAsarRepatchSizeMismatch = errors.New("asar: repatch size mismatch")

// ErrAsarRepatchSamePath rejects in-place repatch.
var ErrAsarRepatchSamePath = errors.New("asar: repatch dst must differ from src")

// Repatch rebuilds an ASAR archive at dstPath from srcPath, replacing the
// contents of the entries named in `replacements` (forward-slash paths)
// with the supplied bytes. Unchanged entries are stream-copied byte-for-byte.
//
// Write is atomic: a temp file is built next to dstPath and renamed on success.
// If any step fails, dstPath is not created.
func Repatch(srcPath, dstPath string, replacements map[string][]byte) error {
	if srcPath == dstPath {
		return ErrAsarRepatchSamePath
	}

	src, header, _, dataOffset, err := OpenAndParse(srcPath)
	if err != nil {
		return fmt.Errorf("repatch: open src: %w", err)
	}
	defer func() { _ = src.Close() }()

	// Flatten existing entries (files only).
	files := CollectFiles(header.Files, "")
	flat := make([]ExtractedFile, 0, len(files))
	for _, f := range files {
		if f.IsDir || f.Unpacked {
			continue
		}
		flat = append(flat, f)
	}
	sort.Slice(flat, func(i, j int) bool { return flat[i].Path < flat[j].Path })

	// Validate every replacement key exists.
	exists := make(map[string]bool, len(flat))
	for _, f := range flat {
		exists[f.Path] = true
	}
	for k := range replacements {
		if !exists[k] {
			return fmt.Errorf("%w: %s", ErrAsarRepatchEntryNotFound, k)
		}
	}

	// Build new contiguous data segment, recording new offsets.
	newOffsets := make(map[string]int64, len(flat))
	newSizes := make(map[string]int64, len(flat))
	var data bytes.Buffer

	for _, f := range flat {
		off := int64(data.Len())
		if repl, ok := replacements[f.Path]; ok {
			if _, err := data.Write(repl); err != nil {
				return fmt.Errorf("repatch: buffer replacement %s: %w", f.Path, err)
			}
			newSizes[f.Path] = int64(len(repl))
		} else {
			if _, err := src.Seek(dataOffset+f.Offset, io.SeekStart); err != nil {
				return fmt.Errorf("repatch: seek %s: %w", f.Path, err)
			}
			if _, err := io.CopyN(&data, src, f.Size); err != nil {
				return fmt.Errorf("repatch: copy %s: %w", f.Path, err)
			}
			newSizes[f.Path] = f.Size
		}
		newOffsets[f.Path] = off
	}

	// Rewrite header offsets/sizes in-place on the parsed header tree.
	if err := rewriteOffsets(header.Files, "", newOffsets, newSizes); err != nil {
		return fmt.Errorf("%w: %v", ErrAsarRepatchSizeMismatch, err)
	}

	hdrJSON, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("repatch: marshal header: %w", err)
	}

	padLen := (4 - (len(hdrJSON) % 4)) % 4
	padded := make([]byte, len(hdrJSON)+padLen)
	copy(padded, hdrJSON)
	for i := len(hdrJSON); i < len(padded); i++ {
		padded[i] = ' '
	}

	prefix := make([]byte, 16)
	headerSize := uint32(8 + len(padded))
	binary.LittleEndian.PutUint32(prefix[0:4], 4)
	binary.LittleEndian.PutUint32(prefix[4:8], headerSize)
	binary.LittleEndian.PutUint32(prefix[8:12], headerSize-4)
	binary.LittleEndian.PutUint32(prefix[12:16], uint32(len(hdrJSON)))

	// Atomic write: temp file in same directory then rename.
	dstDir := filepath.Dir(dstPath)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("repatch: mkdir dst: %w", err)
	}
	tmp, err := os.CreateTemp(dstDir, ".asar-repatch-*.tmp")
	if err != nil {
		return fmt.Errorf("repatch: create tmp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(prefix); err != nil {
		cleanup()
		return fmt.Errorf("repatch: write prefix: %w", err)
	}
	if _, err := tmp.Write(padded); err != nil {
		cleanup()
		return fmt.Errorf("repatch: write header: %w", err)
	}
	if _, err := tmp.Write(data.Bytes()); err != nil {
		cleanup()
		return fmt.Errorf("repatch: write data: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("repatch: close tmp: %w", err)
	}
	if err := os.Rename(tmpName, dstPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("repatch: rename: %w", err)
	}
	return nil
}

// rewriteOffsets walks the header tree and rewrites Offset/Size on each file
// entry using the new offsets/sizes maps keyed by forward-slash path.
func rewriteOffsets(files map[string]*FileEntry, prefix string, offs, sizes map[string]int64) error {
	for name, entry := range files {
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		if entry.Files != nil {
			if err := rewriteOffsets(entry.Files, path, offs, sizes); err != nil {
				return err
			}
			continue
		}
		if entry.Unpacked {
			continue
		}
		off, ok := offs[path]
		if !ok {
			return fmt.Errorf("missing offset for %s", path)
		}
		entry.Offset = fmt.Sprintf("%d", off)
		entry.Size = sizes[path]
	}
	return nil
}

// RepatchWithPreloadInject is a convenience wrapper: it overwrites the
// "preload.js" entry (or another supplied preload path) with the given JS
// bytes. It does not modify main.js webPreferences — use Repatch directly
// for that. The path argument is the entry name in forward-slash form
// (e.g. "preload.js" or "src/preload.js"). If the entry does not exist,
// ErrAsarRepatchEntryNotFound is returned.
func RepatchWithPreloadInject(srcPath, dstPath, preloadPath string, preloadJS []byte) error {
	preloadPath = strings.TrimSpace(preloadPath)
	if preloadPath == "" {
		preloadPath = "preload.js"
	}
	return Repatch(srcPath, dstPath, map[string][]byte{preloadPath: preloadJS})
}
