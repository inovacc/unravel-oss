/*
Copyright (c) 2026 Security Research
*/
package macos

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Mach-O 64-bit header layout (32 bytes, little-endian):
//
//	uint32 magic      = 0xfeedfacf
//	uint32 cputype    = 0x0100000c (CPU_TYPE_ARM64)
//	uint32 cpusubtype = 0          (any)
//	uint32 filetype   = 2          (MH_EXECUTE)
//	uint32 ncmds      = N
//	uint32 sizeofcmds = total bytes after header
//	uint32 flags      = 0
//	uint32 reserved   = 0
const (
	machoMagic64  = 0xfeedfacf
	cpuTypeArm64  = 0x0100000c
	cpuTypeX8664  = 0x01000007
	mhExecute     = 0x2
	lcDylib       = 0xc
	lcRpathCmd    = 0x8000001c
	lcLoadWeakCmd = 0x18
	lcCodeSigCmd  = 0x1d
	fatMagicBE    = 0xcafebabe // big-endian header
	cdMagicBE     = 0xfade0c02
	superMagicBE  = 0xfade0cc0
)

// padTo8 returns n rounded up to a multiple of 8.
func padTo8(n int) int { return (n + 7) &^ 7 }

// buildLcDylib assembles an LC_LOAD_DYLIB or LC_LOAD_WEAK_DYLIB block:
//
//	uint32 cmd
//	uint32 cmdsize
//	uint32 name_offset (lc_str union, points into this LC)
//	uint32 timestamp
//	uint32 current_version
//	uint32 compat_version
//	C-string name (null-terminated, padded to 8-byte boundary)
func buildLcDylib(cmd uint32, name string) []byte {
	const headerSize = 24
	bodyLen := len(name) + 1 // null terminator
	cmdsize := padTo8(headerSize + bodyLen)
	out := make([]byte, cmdsize)
	binary.LittleEndian.PutUint32(out[0:4], cmd)
	binary.LittleEndian.PutUint32(out[4:8], uint32(cmdsize))
	binary.LittleEndian.PutUint32(out[8:12], headerSize) // name offset
	// timestamp/current/compat = 0
	copy(out[headerSize:], name)
	// remaining bytes zero (null terminator + padding)
	return out
}

// buildLcRpath assembles an LC_RPATH block:
//
//	uint32 cmd
//	uint32 cmdsize
//	uint32 path_offset (lc_str union)
//	C-string path (null-terminated, padded to 8-byte boundary)
func buildLcRpath(path string) []byte {
	const headerSize = 12
	bodyLen := len(path) + 1
	cmdsize := padTo8(headerSize + bodyLen)
	out := make([]byte, cmdsize)
	binary.LittleEndian.PutUint32(out[0:4], lcRpathCmd)
	binary.LittleEndian.PutUint32(out[4:8], uint32(cmdsize))
	binary.LittleEndian.PutUint32(out[8:12], headerSize)
	copy(out[headerSize:], path)
	return out
}

// buildLcCodeSignature assembles an LC_CODE_SIGNATURE block (16 bytes,
// always cmdsize=16):
//
//	uint32 cmd      = 0x1d
//	uint32 cmdsize  = 16
//	uint32 dataoff
//	uint32 datasize
func buildLcCodeSignature(dataoff, datasize uint32) []byte {
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], lcCodeSigCmd)
	binary.LittleEndian.PutUint32(out[4:8], 16)
	binary.LittleEndian.PutUint32(out[8:12], dataoff)
	binary.LittleEndian.PutUint32(out[12:16], datasize)
	return out
}

// buildHeader64 assembles the 32-byte Mach-O 64 header.
func buildHeader64(cpuType, ncmds, sizeofcmds uint32) []byte {
	out := make([]byte, 32)
	binary.LittleEndian.PutUint32(out[0:4], machoMagic64)
	binary.LittleEndian.PutUint32(out[4:8], cpuType)
	binary.LittleEndian.PutUint32(out[8:12], 0) // subtype
	binary.LittleEndian.PutUint32(out[12:16], mhExecute)
	binary.LittleEndian.PutUint32(out[16:20], ncmds)
	binary.LittleEndian.PutUint32(out[20:24], sizeofcmds)
	binary.LittleEndian.PutUint32(out[24:28], 0) // flags
	binary.LittleEndian.PutUint32(out[28:32], 0) // reserved
	return out
}

// buildThinARM64Stub returns a minimal Mach-O 64 ARM64 binary with one
// LC_LOAD_DYLIB, one LC_LOAD_WEAK_DYLIB, and one LC_RPATH. Bytes parse
// via debug/macho.NewFile.
func buildThinARM64Stub(t *testing.T, dylib, weakDylib, rpath string) []byte {
	t.Helper()
	lcs := [][]byte{
		buildLcDylib(lcDylib, dylib),
		buildLcDylib(lcLoadWeakCmd, weakDylib),
		buildLcRpath(rpath),
	}
	var lcBytes []byte
	for _, lc := range lcs {
		lcBytes = append(lcBytes, lc...)
	}
	hdr := buildHeader64(cpuTypeArm64, uint32(len(lcs)), uint32(len(lcBytes)))
	return append(hdr, lcBytes...)
}

// buildFatX86_64ARM64Stub returns a fat (universal) Mach-O wrapping two
// thin slices (x86_64 + arm64). Bytes parse via debug/macho.NewFatFile.
//
// Fat header (big-endian):
//
//	uint32 magic   = 0xcafebabe
//	uint32 nfat    = 2
//
// Then 2 x FatArch:
//
//	uint32 cputype
//	uint32 cpusubtype
//	uint32 offset
//	uint32 size
//	uint32 align (power of 2)
func buildFatX86_64ARM64Stub(t *testing.T) []byte {
	t.Helper()
	slice1 := buildThinSimple(cpuTypeX8664)
	slice2 := buildThinSimple(cpuTypeArm64)

	// Fat header + 2 arch entries.
	const headerSize = 8
	const archEntry = 20
	hdrTotal := headerSize + 2*archEntry

	// Align both slices to 4 KiB boundary (align=12).
	const align = 1 << 12
	off1 := align
	for off1 < hdrTotal {
		off1 += align
	}
	size1 := len(slice1)
	off2 := off1 + size1
	if rem := off2 % align; rem != 0 {
		off2 += align - rem
	}
	size2 := len(slice2)
	total := off2 + size2

	out := make([]byte, total)
	// Fat header (big-endian).
	binary.BigEndian.PutUint32(out[0:4], fatMagicBE)
	binary.BigEndian.PutUint32(out[4:8], 2)

	// Arch 1.
	binary.BigEndian.PutUint32(out[8:12], cpuTypeX8664)
	binary.BigEndian.PutUint32(out[12:16], 0)
	binary.BigEndian.PutUint32(out[16:20], uint32(off1))
	binary.BigEndian.PutUint32(out[20:24], uint32(size1))
	binary.BigEndian.PutUint32(out[24:28], 12)

	// Arch 2.
	binary.BigEndian.PutUint32(out[28:32], cpuTypeArm64)
	binary.BigEndian.PutUint32(out[32:36], 0)
	binary.BigEndian.PutUint32(out[36:40], uint32(off2))
	binary.BigEndian.PutUint32(out[40:44], uint32(size2))
	binary.BigEndian.PutUint32(out[44:48], 12)

	copy(out[off1:], slice1)
	copy(out[off2:], slice2)
	return out
}

// buildThinSimple returns a thin Mach-O 64 with one LC_LOAD_DYLIB and one
// LC_RPATH (used as fat slice content).
func buildThinSimple(cpuType uint32) []byte {
	lcs := [][]byte{
		buildLcDylib(lcDylib, "@rpath/Stub.dylib"),
		buildLcRpath("/usr/local/lib"),
	}
	var lcBytes []byte
	for _, lc := range lcs {
		lcBytes = append(lcBytes, lc...)
	}
	hdr := buildHeader64(cpuType, uint32(len(lcs)), uint32(len(lcBytes)))
	return append(hdr, lcBytes...)
}

// buildSuperBlob returns a SuperBlob with one CodeDirectory whose flags
// field equals cdFlags. The blob layout:
//
//	uint32 magic   = 0xfade0cc0  (BE)
//	uint32 length
//	uint32 count   = 1
//	BlobIndex: type=0, offset=20
//	CodeDirectory:
//	  uint32 magic = 0xfade0c02  (BE)
//	  uint32 length
//	  uint32 version
//	  uint32 flags  <-- cdFlags
//	  ... 12 more bytes (zeroed) ...
func buildSuperBlob(cdFlags uint32) []byte {
	const cdSize = 32 // magic+length+version+flags+12B padding
	const superHeader = 12
	const blobIndex = 8
	cdOffset := superHeader + blobIndex
	total := cdOffset + cdSize

	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], superMagicBE)
	binary.BigEndian.PutUint32(out[4:8], uint32(total))
	binary.BigEndian.PutUint32(out[8:12], 1)  // count
	binary.BigEndian.PutUint32(out[12:16], 0) // slot type 0 = CD
	binary.BigEndian.PutUint32(out[16:20], uint32(cdOffset))

	binary.BigEndian.PutUint32(out[cdOffset+0:cdOffset+4], cdMagicBE)
	binary.BigEndian.PutUint32(out[cdOffset+4:cdOffset+8], cdSize)
	binary.BigEndian.PutUint32(out[cdOffset+8:cdOffset+12], 0x20400) // version
	binary.BigEndian.PutUint32(out[cdOffset+12:cdOffset+16], cdFlags)
	return out
}

// buildHardenedThinStub returns a thin Mach-O ARM64 binary identical to
// buildThinARM64Stub PLUS an LC_CODE_SIGNATURE load-command whose payload
// is a SuperBlob with cdFlags set.
func buildHardenedThinStub(t *testing.T, dylib, weakDylib, rpath string, cdFlags uint32) []byte {
	t.Helper()

	dylibLC := buildLcDylib(lcDylib, dylib)
	weakLC := buildLcDylib(lcLoadWeakCmd, weakDylib)
	rpathLC := buildLcRpath(rpath)

	// Compute layout BEFORE building the codesig LC so we can fill its
	// dataoff/datasize.
	headerSize := 32
	lcSize := len(dylibLC) + len(weakLC) + len(rpathLC) + 16 // codesig LC = 16
	sigOffset := headerSize + lcSize
	sigBlob := buildSuperBlob(cdFlags)
	sigSize := len(sigBlob)

	codesigLC := buildLcCodeSignature(uint32(sigOffset), uint32(sigSize))

	// Reassemble in order: header | LCs | (padding none) | sig blob.
	hdr := buildHeader64(cpuTypeArm64, 4, uint32(lcSize))

	out := make([]byte, 0, sigOffset+sigSize)
	out = append(out, hdr...)
	out = append(out, dylibLC...)
	out = append(out, weakLC...)
	out = append(out, rpathLC...)
	out = append(out, codesigLC...)
	out = append(out, sigBlob...)
	return out
}

// writeFixture writes b to a temp file under t.TempDir() and returns its
// absolute path.
func writeFixture(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}
