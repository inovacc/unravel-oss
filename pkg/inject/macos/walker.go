/*
Copyright (c) 2026 Security Research
*/
package macos

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// Mach-O magic numbers (host + reverse byte order).
const (
	magicThin32  = 0xfeedface
	magicThin64  = 0xfeedfacf
	magicFat     = 0xcafebabe
	magicFatRev  = 0xbebafeca
	magicThin32R = 0xcefaedfe
	magicThin64R = 0xcffaedfe
)

// Mach-O LC ids that are not parsed into typed structs by debug/macho.
// They arrive in File.Loads as LoadBytes.
const (
	lcLoadWeakDylib macho.LoadCmd = 0x18
	lcCodeSignature macho.LoadCmd = 0x1d
)

// IsMachO peeks the first 4 bytes of path and reports whether they match
// a recognized Mach-O thin or fat magic number.
func IsMachO(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var buf [4]byte
	if _, err := io.ReadFull(f, buf[:]); err != nil {
		return false
	}
	m := binary.BigEndian.Uint32(buf[:])
	switch m {
	case magicThin32, magicThin64, magicFat, magicFatRev,
		magicThin32R, magicThin64R:
		return true
	}
	return false
}

// WalkMachO opens path and returns a per-arch list of injection seams.
// Thin binaries return a slice of length 1; fat (universal) binaries
// return one ArchReport per embedded slice.
func WalkMachO(path string) ([]inject.ArchReport, error) {
	if fat, err := macho.OpenFat(path); err == nil {
		defer func() { _ = fat.Close() }()
		out := make([]inject.ArchReport, 0, len(fat.Arches))
		for _, a := range fat.Arches {
			out = append(out, walkOne(path, a.File))
		}
		return out, nil
	} else if !errors.Is(err, macho.ErrNotFat) {
		return nil, fmt.Errorf("open fat: %w", err)
	}

	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open thin: %w", err)
	}
	defer func() { _ = f.Close() }()
	return []inject.ArchReport{walkOne(path, f)}, nil
}

// walkOne walks a single thin slice and returns its ArchReport. Hardened-
// runtime / library-validation flags are folded into Seam.SigningBlocks
// and trigger a confidence downgrade across the whole arch.
func walkOne(path string, f *macho.File) inject.ArchReport {
	ar := inject.ArchReport{Arch: f.Cpu.String()}

	for _, lc := range f.Loads {
		switch v := lc.(type) {
		case *macho.Dylib:
			ar.Seams = append(ar.Seams, mkSeam("LC_LOAD_DYLIB", path, v.Name))
		case *macho.Rpath:
			ar.Seams = append(ar.Seams, mkSeam("LC_RPATH", path, v.Path))
		case macho.LoadBytes:
			raw := []byte(v)
			if len(raw) < 8 {
				continue
			}
			cmd := macho.LoadCmd(f.ByteOrder.Uint32(raw[0:4]))
			if cmd == lcLoadWeakDylib {
				name := readWeakDylibName(raw, f.ByteOrder)
				if name != "" {
					ar.Seams = append(ar.Seams, mkSeam("LC_LOAD_WEAK_DYLIB", path, name))
				}
			}
		}
	}

	// Attach signing-block info to every seam in this arch.
	if blob := readCodeSignature(path, f); len(blob) > 0 {
		flags, err := ParseSuperBlob(blob)
		if err == nil {
			blocks := SigningBlockStrings(flags)
			if len(blocks) > 0 {
				for i := range ar.Seams {
					ar.Seams[i].SigningBlocks = blocks
					ar.Seams[i].Confidence = DowngradeConfidence(ar.Seams[i].Confidence)
				}
			}
		}
	}

	return ar
}

// readWeakDylibName parses a raw LC_LOAD_WEAK_DYLIB cmd block and returns
// the dylib path. Layout matches LC_LOAD_DYLIB:
//
//	uint32 cmd
//	uint32 cmdsize
//	uint32 name_offset (lc_str union)
//	uint32 timestamp
//	uint32 current_version
//	uint32 compat_version
//	C-string name (padded)
func readWeakDylibName(raw []byte, bo binary.ByteOrder) string {
	if len(raw) < 24 {
		return ""
	}
	off := bo.Uint32(raw[8:12])
	if int(off) >= len(raw) {
		return ""
	}
	end := bytes.IndexByte(raw[off:], 0)
	if end < 0 {
		return string(raw[off:])
	}
	return string(raw[off : int(off)+end])
}

// readCodeSignature finds the LC_CODE_SIGNATURE load-command on f and
// returns the raw SuperBlob bytes by reading from path. Returns nil if no
// signature load-command is present or any I/O step fails.
//
// LC_CODE_SIGNATURE arrives as LoadBytes:
//
//	uint32 cmd      = 0x1d
//	uint32 cmdsize  = 16
//	uint32 dataoff
//	uint32 datasize
func readCodeSignature(path string, f *macho.File) []byte {
	for _, l := range f.Loads {
		raw, ok := l.(macho.LoadBytes)
		if !ok || len(raw) < 16 {
			continue
		}
		cmd := macho.LoadCmd(f.ByteOrder.Uint32(raw[0:4]))
		if cmd != lcCodeSignature {
			continue
		}
		dataoff := f.ByteOrder.Uint32(raw[8:12])
		datasize := f.ByteOrder.Uint32(raw[12:16])
		if datasize == 0 {
			return nil
		}
		fh, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer func() { _ = fh.Close() }()
		buf := make([]byte, datasize)
		if _, err := fh.ReadAt(buf, int64(dataoff)); err != nil {
			return nil
		}
		return buf
	}
	return nil
}

// mkSeam constructs a Seam pointing at path with target as snippet.
func mkSeam(kind, path, target string) inject.Seam {
	return inject.Seam{
		Kind:       kind,
		Confidence: inject.ConfidenceMedium,
		Framework:  inject.FrameworkMacOS,
		Evidence: []inject.Evidence{
			{Type: inject.EvidenceFileContent, Path: path, Snippet: target},
		},
		ReachableRuntime: kind == "LC_LOAD_DYLIB",
	}
}
