/*
Copyright (c) 2026 Security Research
*/

package embed

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalPE constructs a minimal but valid PE32+ image. If rsrcPayloads
// is non-empty, a `.rsrc` section is appended; each payload becomes a single
// RT_RCDATA entry under a unique Name ID.
//
// If withTruncatedRsrc is true, the .rsrc section is declared in the section
// header (large VirtualSize) but its raw data is shorter than the directory
// header — used to exercise the truncation guard.
//
// If craftOversizeSize is true, the IMAGE_RESOURCE_DATA_ENTRY.Size field for
// the FIRST payload is overwritten to a value that exceeds the section size,
// to exercise the bounds-check guard.
func buildMinimalPE(t *testing.T, rsrcPayloads [][]byte, withTruncatedRsrc, craftOversizeSize bool) string {
	t.Helper()

	const fileAlign uint32 = 0x200
	const sectAlign uint32 = 0x1000

	// --- Build .rsrc section data ---
	var rsrcData []byte
	if len(rsrcPayloads) > 0 {
		rsrcData = buildRsrcSection(rsrcPayloads, sectAlignedRVA(2)) // .rsrc will be section #2 (index 1) after .text
		if craftOversizeSize {
			// Find the first IMAGE_RESOURCE_DATA_ENTRY and overwrite its Size.
			// Layout: top dir (16) + 1 type entry (8) + name dir (16) + 1 name entry (8) + lang dir (16) + 1 lang entry (8) + data entries...
			// First data entry begins at offset = 16+8+16+8+16+8*N where N = total lang entries.
			// We embed ID at position derived from buildRsrcSection layout below — simplest is to scan for our payload bytes.
			// For test simplicity: we know layout has data entries after directories. The first data entry's Size field
			// is the second uint32 of the first IMAGE_RESOURCE_DATA_ENTRY.
			off := firstDataEntryOffset(len(rsrcPayloads))
			if off+8 <= len(rsrcData) {
				binary.LittleEndian.PutUint32(rsrcData[off+4:off+8], 0xFFFFFFFF) // huge size
			}
		}
	}

	if withTruncatedRsrc {
		// Build a rsrc section whose top-level directory claims many ID
		// entries but stops short — exercises the entries-out-of-bounds guard.
		rsrcData = make([]byte, 16)
		binary.LittleEndian.PutUint16(rsrcData[12:14], 0)    // named=0
		binary.LittleEndian.PutUint16(rsrcData[14:16], 0xFF) // claims 255 ID entries
	}

	// --- Build .text section (8 bytes of NOPs, just to have a section) ---
	textData := make([]byte, 16)

	// Section table layout:
	//   1) .text  RVA=0x1000, file offset = headerEnd aligned
	//   2) .rsrc  RVA=0x2000, file offset = .text end aligned
	textRawSize := alignUp(uint32(len(textData)), fileAlign)
	rsrcRawSize := alignUp(uint32(len(rsrcData)), fileAlign)

	// PE headers size budget: DOS+stub (64) + PE sig (4) + COFF (20) + OptHdr(PE32+ standard 240) + 2 sections * 40 = ~408. Round to fileAlign=0x200 -> 0x400.
	headersRawSize := max(alignUp(uint32(0x180), fileAlign), 0x400)

	textFileOff := headersRawSize
	rsrcFileOff := textFileOff + textRawSize

	imageSize := alignUp(0x2000+rsrcRawSize, sectAlign) // .rsrc starts at RVA 0x2000

	// --- DOS header ---
	buf := bytes.Buffer{}
	dos := make([]byte, 64)
	dos[0] = 'M'
	dos[1] = 'Z'
	binary.LittleEndian.PutUint32(dos[60:64], 64) // e_lfanew -> PE sig at offset 64
	buf.Write(dos)

	// --- PE signature ---
	buf.WriteString("PE\x00\x00")

	// --- COFF header (20 bytes) ---
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:2], 0x8664) // Machine: AMD64
	binary.LittleEndian.PutUint16(coff[2:4], 2)      // NumberOfSections
	binary.LittleEndian.PutUint32(coff[4:8], 0)      // TimeDateStamp
	binary.LittleEndian.PutUint16(coff[16:18], 240)  // SizeOfOptionalHeader (PE32+)
	binary.LittleEndian.PutUint16(coff[18:20], 0x22) // Characteristics: EXEC | LARGE_ADDR_AWARE
	buf.Write(coff)

	// --- Optional header (PE32+, 240 bytes incl. data dirs) ---
	opt := make([]byte, 240)
	binary.LittleEndian.PutUint16(opt[0:2], 0x20B)            // PE32+
	binary.LittleEndian.PutUint32(opt[16:20], 0x1000)         // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(opt[20:24], 0x1000)         // BaseOfCode
	binary.LittleEndian.PutUint64(opt[24:32], 0x140000000)    // ImageBase (PE32+: 8 bytes at +24)
	binary.LittleEndian.PutUint32(opt[32:36], sectAlign)      // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:40], fileAlign)      // FileAlignment
	binary.LittleEndian.PutUint16(opt[40:42], 6)              // MajorOSVer
	binary.LittleEndian.PutUint16(opt[48:50], 6)              // MajorSubsysVer
	binary.LittleEndian.PutUint32(opt[56:60], imageSize)      // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:64], headersRawSize) // SizeOfHeaders
	binary.LittleEndian.PutUint16(opt[68:70], 3)              // Subsystem: console
	binary.LittleEndian.PutUint16(opt[70:72], 0)              // DllCharacteristics
	// SizeOfStackReserve/Commit, SizeOfHeapReserve/Commit, LoaderFlags @ +72..+108
	binary.LittleEndian.PutUint32(opt[108:112], 16) // NumberOfRvaAndSizes
	// Data directories occupy bytes 112..240 (16*8). If .rsrc present, set RESOURCE_TABLE entry (index 2).
	if len(rsrcData) > 0 {
		// Resource Table = data dir [2]
		dirOff := 112 + 2*8
		binary.LittleEndian.PutUint32(opt[dirOff:dirOff+4], 0x2000)                  // VA
		binary.LittleEndian.PutUint32(opt[dirOff+4:dirOff+8], uint32(len(rsrcData))) // Size
	}
	buf.Write(opt)

	// --- Section headers (40 bytes each) ---
	textHdr := buildSectionHeader(".text", uint32(len(textData)), 0x1000, textRawSize, textFileOff, 0x60000020)
	buf.Write(textHdr)

	if len(rsrcData) > 0 {
		rsrcHdr := buildSectionHeader(".rsrc", uint32(len(rsrcData)), 0x2000, rsrcRawSize, rsrcFileOff, 0x40000040)
		buf.Write(rsrcHdr)
	} else {
		// emit a no-op second section to keep NumberOfSections=2 honest
		emptyHdr := buildSectionHeader(".empty", 0, 0x2000, 0, rsrcFileOff, 0x40000040)
		buf.Write(emptyHdr)
	}

	// Pad to headersRawSize.
	for buf.Len() < int(headersRawSize) {
		buf.WriteByte(0)
	}

	// --- .text raw data ---
	buf.Write(textData)
	for buf.Len() < int(textFileOff+textRawSize) {
		buf.WriteByte(0)
	}

	// --- .rsrc raw data ---
	if len(rsrcData) > 0 {
		buf.Write(rsrcData)
		for buf.Len() < int(rsrcFileOff+rsrcRawSize) {
			buf.WriteByte(0)
		}
	}

	path := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write pe: %v", err)
	}
	return path
}

func sectAlignedRVA(_ int) uint32 { return 0x2000 }

func alignUp(v, a uint32) uint32 {
	if a == 0 {
		return v
	}
	return (v + a - 1) &^ (a - 1)
}

func buildSectionHeader(name string, virtSize, virtAddr, rawSize, rawOff, chars uint32) []byte {
	h := make([]byte, 40)
	copy(h[0:8], name)
	binary.LittleEndian.PutUint32(h[8:12], virtSize)
	binary.LittleEndian.PutUint32(h[12:16], virtAddr)
	binary.LittleEndian.PutUint32(h[16:20], rawSize)
	binary.LittleEndian.PutUint32(h[20:24], rawOff)
	binary.LittleEndian.PutUint32(h[36:40], chars)
	return h
}

// buildRsrcSection lays out a minimal Type=10 (RT_RCDATA) tree with one Name
// per payload, each having one Language=0 entry pointing at its data.
//
// Layout:
//
//	off 0:                       Top-level dir header (16) — 0 named, 1 ID entry
//	off 16:                      Type entry (8)  -> ID=10, subdir at off 24
//	off 24:                      Name dir header (16) — 0 named, N ID entries
//	off 40:                      Name entries (8 each) -> ID=i+1, subdir at off X_i
//	off 40+8*N:                  per-Name lang dir (16) + 1 lang entry (8) for each name
//	...
//	then IMAGE_RESOURCE_DATA_ENTRY records (16 each)
//	then payload bytes
func buildRsrcSection(payloads [][]byte, sectionVA uint32) []byte {
	N := uint32(len(payloads))

	// We'll compute offsets after laying out the directory tree of fixed shape.
	// Sizes:
	//   topDir = 16, topEntries = 8 * 1
	//   nameDir = 16, nameEntries = 8 * N
	//   per-name: langDir(16) + langEntry(8) = 24
	//   data entries: 16 * N
	headerEnd := 16 + 8 + 16 + 8*N + 24*N
	dataEntriesOff := headerEnd
	payloadsOff := dataEntriesOff + 16*N

	totalSize := payloadsOff
	for _, p := range payloads {
		totalSize += alignUp(uint32(len(p)), 4)
	}

	out := make([]byte, totalSize)

	// Top-level dir: 0 named, 1 ID
	binary.LittleEndian.PutUint16(out[12:14], 0)
	binary.LittleEndian.PutUint16(out[14:16], 1)
	// Top-level entry @ off 16: ID=10 (RT_RCDATA), subdir at offset 24
	binary.LittleEndian.PutUint32(out[16:20], 10)
	binary.LittleEndian.PutUint32(out[20:24], 0x80000000|24)

	// Name dir @ off 24: 0 named, N IDs
	binary.LittleEndian.PutUint16(out[24+12:24+14], 0)
	binary.LittleEndian.PutUint16(out[24+14:24+16], uint16(N))

	// Name entries start at off 40
	for i := range N {
		entryOff := uint32(40) + i*8
		// Per-name language dir off
		langDirOff := uint32(40) + 8*N + i*24
		binary.LittleEndian.PutUint32(out[entryOff:entryOff+4], i+1) // Name ID
		binary.LittleEndian.PutUint32(out[entryOff+4:entryOff+8], 0x80000000|langDirOff)
	}

	// Per-name lang dir + entry
	payloadOff := payloadsOff
	for i := range N {
		langDirOff := uint32(40) + 8*N + i*24
		binary.LittleEndian.PutUint16(out[langDirOff+12:langDirOff+14], 0)
		binary.LittleEndian.PutUint16(out[langDirOff+14:langDirOff+16], 1)
		// Lang entry at langDirOff+16: lang=0, points to data entry at dataEntriesOff + 16*i
		dataEntryOff := dataEntriesOff + 16*i
		binary.LittleEndian.PutUint32(out[langDirOff+16:langDirOff+20], 0)            // language
		binary.LittleEndian.PutUint32(out[langDirOff+20:langDirOff+24], dataEntryOff) // points to data entry (NOT subdir)

		// IMAGE_RESOURCE_DATA_ENTRY at dataEntryOff:
		//   OffsetToData (RVA) = sectionVA + payloadOff
		//   Size = len(payloads[i])
		//   CodePage = 0
		//   Reserved = 0
		binary.LittleEndian.PutUint32(out[dataEntryOff:dataEntryOff+4], sectionVA+payloadOff)
		binary.LittleEndian.PutUint32(out[dataEntryOff+4:dataEntryOff+8], uint32(len(payloads[i])))

		// Copy payload bytes.
		copy(out[payloadOff:], payloads[i])
		payloadOff += alignUp(uint32(len(payloads[i])), 4)
	}

	return out
}

// firstDataEntryOffset mirrors the layout in buildRsrcSection.
func firstDataEntryOffset(numPayloads int) int {
	N := uint32(numPayloads)
	return int(16 + 8 + 16 + 8*N + 24*N)
}

// ---------------------- Tests ----------------------

func TestScanPE_NoResources(t *testing.T) {
	path := buildMinimalPE(t, nil, false, false)
	out, err := ScanPE(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want empty, got %+v", out)
	}
}

func TestScanPE_RTRCDATA_XML(t *testing.T) {
	path := buildMinimalPE(t, [][]byte{[]byte(`<?xml version="1.0"?><Page/>`)}, false, false)
	out, err := ScanPE(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out) != 1 || out[0].Kind != "xml" {
		t.Fatalf("want 1 xml entry, got %+v", out)
	}
	if !bytes.HasPrefix(out[0].Bytes, []byte("<?xml")) {
		t.Fatalf("payload mismatch: %q", out[0].Bytes)
	}
	if out[0].Offset <= 0 {
		t.Fatalf("offset should be > 0, got %d", out[0].Offset)
	}
}

func TestScanPE_RTRCDATA_XBFMagic(t *testing.T) {
	path := buildMinimalPE(t, [][]byte{append([]byte{'X', 'B', 'F', 0x00}, 0xDE, 0xAD)}, false, false)
	out, err := ScanPE(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out) != 1 || out[0].Kind != "xbf" {
		t.Fatalf("want 1 xbf entry, got %+v", out)
	}
}

func TestScanPE_RTRCDATA_Other(t *testing.T) {
	path := buildMinimalPE(t, [][]byte{{0x1F, 0x8B, 0x08, 0x00}}, false, false)
	out, err := ScanPE(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out) != 1 || out[0].Kind != "unknown" {
		t.Fatalf("want 1 unknown entry, got %+v", out)
	}
}

func TestScanPE_MultipleResources(t *testing.T) {
	path := buildMinimalPE(t, [][]byte{
		[]byte(`<?xml version="1.0"?><A/>`),
		append([]byte{'X', 'B', 'F', 0x00}, 0xAA),
		{0x00, 0x01, 0x02, 0x03},
	}, false, false)
	out, err := ScanPE(path)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 entries got %d (%+v)", len(out), out)
	}
	got := []string{out[0].Kind, out[1].Kind, out[2].Kind}
	want := []string{"xml", "xbf", "unknown"}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("entry %d: want %s got %s", i, want[i], got[i])
		}
	}
}

func TestScanPE_MalformedRsrc(t *testing.T) {
	path := buildMinimalPE(t, [][]byte{[]byte("doesnt-matter")}, true, false)
	_, err := ScanPE(path)
	if err == nil {
		t.Fatalf("want error for truncated rsrc")
	}
}

func TestScanPE_NotAPEFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(path, []byte("not a pe"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ScanPE(path)
	if err == nil {
		t.Fatalf("want error for non-PE")
	}
}

func TestScanPE_BoundsCheck(t *testing.T) {
	path := buildMinimalPE(t, [][]byte{[]byte(`<?xml ?>`)}, false, true /*craftOversizeSize*/)
	_, err := ScanPE(path)
	if err == nil {
		t.Fatalf("want error for oversize resource Size")
	}
}
