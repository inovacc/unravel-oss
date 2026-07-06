/*
Copyright (c) 2026 Security Research
*/
package clr

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"
)

// metaRegion builds a minimal BSJB metadata region: signature 0x424A5342,
// version "v4.0.30319", 1 stream ("#~") with empty payload. It is enough for
// image.go to locate+slurp and for metadata.Parse (M0-B) to root-validate.
func metaRegion() []byte {
	ver := []byte("v4.0.30319\x00")
	// pad version length to 4-byte boundary.
	for len(ver)%4 != 0 {
		ver = append(ver, 0)
	}
	hdr := make([]byte, 0, 64)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0x424A5342) // "BSJB"
	hdr = binary.LittleEndian.AppendUint16(hdr, 1)          // MajorVersion
	hdr = binary.LittleEndian.AppendUint16(hdr, 1)          // MinorVersion
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)          // Reserved
	hdr = binary.LittleEndian.AppendUint32(hdr, uint32(len(ver)))
	hdr = append(hdr, ver...)
	hdr = binary.LittleEndian.AppendUint16(hdr, 0) // Flags
	hdr = binary.LittleEndian.AppendUint16(hdr, 1) // Streams = 1
	// Stream header: Offset (rel to metadata root), Size, name "#~\0\0".
	streamOff := uint32(len(hdr)) + 12 // this stream-header is 12 bytes ("#~\0\0")
	hdr = binary.LittleEndian.AppendUint32(hdr, streamOff)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0) // Size (empty #~ payload)
	hdr = append(hdr, '#', '~', 0, 0)
	return hdr
}

// synthManagedPE writes a minimal PE32+ with a populated IMAGE_COR20_HEADER and
// an embedded BSJB metadata region. Hand-rolled (Go stdlib only writes, not
// generates, PE). Returns the COR20 header's MetaData RVA for assertions.
//
// Layout: headers in first 0x400 bytes; one ".text" section mapped at
// VirtualAddress 0x2000 / PointerToRawData 0x400. COR20 header sits at the
// section start (RVA 0x2000); the BSJB region follows it inside the section.
func synthManagedPE(t *testing.T, path string) (metaRVA uint32) {
	t.Helper()

	const (
		ntHeaderOffset = 0x80
		secVA          = 0x2000
		secRaw         = 0x400
		cor20Size      = 72 // IMAGE_COR20_HEADER is 72 bytes
	)

	meta := metaRegion()
	metaRVA = secVA + cor20Size

	// File = 0x400 headers + section raw data large enough for COR20+meta.
	rawLen := cor20Size + len(meta) + 16
	buf := make([]byte, secRaw+roundUp(rawLen, 0x200))

	// DOS header.
	buf[0], buf[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(buf[0x3c:], ntHeaderOffset)
	copy(buf[ntHeaderOffset:], []byte{'P', 'E', 0, 0})

	// IMAGE_FILE_HEADER (20 bytes) at ntHeaderOffset+4.
	fh := buf[ntHeaderOffset+4:]
	binary.LittleEndian.PutUint16(fh[0:], 0x8664) // Machine AMD64
	binary.LittleEndian.PutUint16(fh[2:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(fh[16:], 240)   // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(fh[18:], 0x2022)

	// IMAGE_OPTIONAL_HEADER64 at ntHeaderOffset+24.
	oh := buf[ntHeaderOffset+24:]
	binary.LittleEndian.PutUint16(oh[0:], 0x20b) // PE32+
	binary.LittleEndian.PutUint32(oh[108:], 16)  // NumberOfRvaAndSizes
	dd := oh[112:]
	// DataDirectory[14] = COM Descriptor -> RVA secVA, Size cor20Size.
	binary.LittleEndian.PutUint32(dd[14*8:], secVA)
	binary.LittleEndian.PutUint32(dd[14*8+4:], cor20Size)

	// Section header (40 bytes) at ntHeaderOffset+24+240.
	sh := buf[ntHeaderOffset+24+240:]
	copy(sh[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sh[8:], uint32(rawLen)) // VirtualSize
	binary.LittleEndian.PutUint32(sh[12:], secVA)         // VirtualAddress
	binary.LittleEndian.PutUint32(sh[16:], uint32(roundUp(rawLen, 0x200)))
	binary.LittleEndian.PutUint32(sh[20:], secRaw) // PointerToRawData
	binary.LittleEndian.PutUint32(sh[36:], 0x60000020)

	// IMAGE_COR20_HEADER at section start (file offset secRaw).
	c := buf[secRaw:]
	binary.LittleEndian.PutUint32(c[0:], cor20Size) // Cb
	binary.LittleEndian.PutUint16(c[4:], 2)         // MajorRuntimeVersion
	binary.LittleEndian.PutUint16(c[6:], 5)         // MinorRuntimeVersion
	binary.LittleEndian.PutUint32(c[8:], metaRVA)   // MetaData.RVA
	binary.LittleEndian.PutUint32(c[12:], uint32(len(meta)))
	binary.LittleEndian.PutUint32(c[16:], 1) // Flags = COMIMAGE_FLAGS_ILONLY

	// BSJB region right after the COR20 header.
	copy(buf[secRaw+cor20Size:], meta)

	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return metaRVA
}

func roundUp(n, a int) int { return (n + a - 1) / a * a }

func TestToken_Alias(t *testing.T) {
	// clr.Token is a type alias for clrtok.Token: same accessors, same values.
	if got := Token(0x06000001).RowID(); got != 1 {
		t.Errorf("clr.Token(0x06000001).RowID() = %#x, want 1", got)
	}
	if got := Token(0x06000001).TableID(); got != 0x06 {
		t.Errorf("clr.Token(0x06000001).TableID() = %#x, want 0x06", got)
	}
	// Alias identity: a clrtok.Token is assignable to clr.Token with no conversion.
	var ct clrtok.Token = 0x02000123
	var alias Token = ct
	if alias.TableID() != 0x02 || alias.RowID() != 0x123 {
		t.Errorf("alias identity broken: %#x", uint32(alias))
	}
}

func TestOpen_COR20Decode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "min.dll")
	wantMetaRVA := synthManagedPE(t, p)

	img, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	c := img.cor20
	if c.Cb != 72 {
		t.Errorf("Cb = %d, want 72", c.Cb)
	}
	if c.MajorRuntimeVersion != 2 || c.MinorRuntimeVersion != 5 {
		t.Errorf("runtime ver = %d.%d, want 2.5", c.MajorRuntimeVersion, c.MinorRuntimeVersion)
	}
	if c.MetaData.RVA != wantMetaRVA {
		t.Errorf("MetaData.RVA = %#x, want %#x", c.MetaData.RVA, wantMetaRVA)
	}
	if c.Flags != 1 {
		t.Errorf("Flags = %#x, want 1 (ILONLY)", c.Flags)
	}
}

func TestOpen_NotManaged(t *testing.T) {
	// Reuse the unmanaged synthPE shape: COM dir zeroed.
	p := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(p, []byte("not a pe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("want error opening non-PE, got nil")
	}
}

func TestRVAToOffset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "min.dll")
	metaRVA := synthManagedPE(t, p)
	img, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Section is VA 0x2000 -> raw 0x400. COR20 at VA 0x2000.
	off, ok := img.RVAToOffset(0x2000)
	if !ok || off != 0x400 {
		t.Fatalf("RVAToOffset(0x2000) = %#x,%v; want 0x400,true", off, ok)
	}
	// metaRVA maps just past the COR20 header.
	if _, ok := img.RVAToOffset(metaRVA); !ok {
		t.Fatalf("RVAToOffset(metaRVA=%#x) not mapped", metaRVA)
	}
	// RVA below any section -> unmapped.
	if _, ok := img.RVAToOffset(0x10); ok {
		t.Fatal("RVAToOffset(0x10) mapped; want unmapped")
	}
	// RVA past section's raw extent -> unmapped (bounds-check vs raw data).
	if _, ok := img.RVAToOffset(0x2000 + 0x100000); ok {
		t.Fatal("RVAToOffset(far) mapped; want unmapped")
	}
}

func TestMetadata_Slurp(t *testing.T) {
	p := filepath.Join(t.TempDir(), "min.dll")
	synthManagedPE(t, p)
	img, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	meta := img.Metadata()
	if len(meta) < 4 {
		t.Fatalf("metadata too short: %d", len(meta))
	}
	if binary.LittleEndian.Uint32(meta) != 0x424A5342 {
		t.Errorf("metadata sig = %#x, want 0x424A5342 (BSJB)", binary.LittleEndian.Uint32(meta))
	}
	if int(img.cor20.MetaData.Size) != len(meta) {
		t.Errorf("metadata len = %d, want MetaData.Size %d", len(meta), img.cor20.MetaData.Size)
	}
}

func TestMetadata_BadSig(t *testing.T) {
	// corruptMetaSig writes a managed PE whose metadata region lacks BSJB.
	p := filepath.Join(t.TempDir(), "badmeta.dll")
	corruptMetaSig(t, p)
	if _, err := Open(p); !errors.Is(err, ErrBadMetadataSig) {
		t.Fatalf("Open = %v, want ErrBadMetadataSig", err)
	}
}

// corruptMetaSig builds the valid fixture, then clobbers the BSJB signature in
// the file's metadata region so Open must reject it.
func corruptMetaSig(t *testing.T, path string) {
	t.Helper()
	synthManagedPE(t, path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Metadata sits at file offset secRaw(0x400)+cor20Size(72).
	binary.LittleEndian.PutUint32(data[0x400+72:], 0xDEADBEEF)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOpen_PanicSafety(t *testing.T) {
	dir := t.TempDir()

	// Garbage (not a PE).
	garbage := filepath.Join(dir, "garbage.bin")
	if err := os.WriteFile(garbage, []byte("xxxxxxxxxxxxxxxx"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Valid PE shape but COM dir points past EOF: truncate a good fixture.
	truncCor20 := filepath.Join(dir, "trunc_cor20.dll")
	synthManagedPE(t, truncCor20)
	data, _ := os.ReadFile(truncCor20)
	if err := os.WriteFile(truncCor20, data[:0x400+8], 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"garbage", garbage},
		{"truncated cor20", truncCor20},
		{"nonexistent", filepath.Join(dir, "nope.dll")},
		{"empty path", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img, err := Open(tt.path) // must not panic
			if err == nil {
				t.Fatalf("Open(%q) = nil err, want error", tt.path)
			}
			if img != nil {
				t.Fatalf("Open(%q) returned non-nil image with error", tt.path)
			}
		})
	}
}

func TestOpenReaderAt_ShortRead(t *testing.T) {
	// Claim a larger size than the underlying bytes provide.
	r := bytesReaderAt([]byte("MZ"))
	if _, err := OpenReaderAt(r, 4096); err == nil {
		t.Fatal("OpenReaderAt short read = nil err, want error")
	}
}

func TestSentinelErrors_AreDistinct(t *testing.T) {
	if errors.Is(ErrNotManaged, ErrBadMetadataSig) {
		t.Fatal("ErrNotManaged and ErrBadMetadataSig must be distinct")
	}
}

func TestSeam_ReaderAtAndRVAToOffset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "min.dll")
	synthManagedPE(t, p)
	img, err := Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// ReaderAt must surface the same bytes as the on-disk image.
	off, ok := img.RVAToOffset(0x2000) // COR20 header start = file 0x400
	if !ok {
		t.Fatal("RVAToOffset(0x2000) unmapped")
	}
	got := make([]byte, 4)
	if _, err := img.ReaderAt().ReadAt(got, int64(off)); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if binary.LittleEndian.Uint32(got) != 72 { // COR20.Cb
		t.Errorf("ReaderAt byte mismatch: %#x", got)
	}

	// Seam-shape lock: RVAToOffset must satisfy the func type M1 consumes.
	var resolver func(uint32) (int, bool) = img.RVAToOffset
	if _, ok := resolver(0x2000); !ok {
		t.Fatal("seam resolver not usable")
	}
	var _ io.ReaderAt = img.ReaderAt()

	// Metadata() must be non-empty and BSJB-rooted (M0-B entry point).
	if len(img.Metadata()) < 4 {
		t.Fatal("Metadata() empty at seam")
	}
}

func TestSynthManagedPE_Opens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "min.dll")
	synthManagedPE(t, p)
	f, err := pe.Open(p)
	if err != nil {
		t.Fatalf("pe.Open: %v", err)
	}
	defer func() { _ = f.Close() }()
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("want OptionalHeader64, got %T", f.OptionalHeader)
	}
	if oh.DataDirectory[14].VirtualAddress == 0 {
		t.Fatal("COM descriptor dir empty")
	}
}
