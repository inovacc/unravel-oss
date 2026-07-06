package cert

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalPE constructs a minimal PE binary whose security data directory
// points to a WIN_CERTIFICATE header at a specified offset with a given certLen.
// Used to drive the cert parser against crafted inputs without real PKCS#7 data.
func buildMinimalPE(t *testing.T, secVA, secSize, certLen uint32) string {
	t.Helper()

	// Allocate enough space for the DOS stub + PE header + optional header + cert table.
	// We write a PE32 with a minimal optional header.
	const (
		dosHeaderSize  = 0x40
		peSignOff      = 0x3c // offset in DOS header that holds PE offset
		coffHeaderSize = 20
		optHeaderSize  = 96 // PE32 optional header including 16 data directories
		sectionAlign   = 0x1000
	)

	peOff := uint32(dosHeaderSize)
	optHeaderOff := peOff + 4 + coffHeaderSize
	dataDirOff := optHeaderOff + 68 // data directories start at offset 68 in PE32 opt header

	// The security directory sits right after the PE headers in our test binary.
	// secVA is where the WIN_CERTIFICATE header starts.
	totalSize := max(
		// extra padding
		secVA+secSize+16, 512)
	buf := make([]byte, totalSize)

	// DOS header: MZ magic + PE offset at 0x3c
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[peSignOff:], peOff)

	// PE signature
	copy(buf[peOff:], []byte{'P', 'E', 0, 0})

	// COFF header: machine=x86, 0 sections, optional header size
	coffOff := peOff + 4
	binary.LittleEndian.PutUint16(buf[coffOff:], 0x014c)           // machine: IMAGE_FILE_MACHINE_I386
	binary.LittleEndian.PutUint16(buf[coffOff+2:], 0)              // numberOfSections
	binary.LittleEndian.PutUint16(buf[coffOff+16:], optHeaderSize) // sizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[coffOff+18:], 0x0002)        // characteristics: executable

	// PE32 Optional header magic
	binary.LittleEndian.PutUint16(buf[optHeaderOff:], 0x010b) // PE32
	// numberOfRvaAndSizes (at offset optHeaderOff+92 for PE32) = 16
	binary.LittleEndian.PutUint32(buf[optHeaderOff+92:], 16)

	// Security data directory (entry 4 = imageDirectoryEntrySecurity)
	// Each data directory is 8 bytes: VirtualAddress(4) + Size(4)
	secDirOff := dataDirOff + 4*8 // entry 4
	binary.LittleEndian.PutUint32(buf[secDirOff:], secVA)
	binary.LittleEndian.PutUint32(buf[secDirOff+4:], secSize)

	// Write the WIN_CERTIFICATE header at secVA (if within buffer)
	if secVA > 0 && int(secVA)+8 <= len(buf) {
		binary.LittleEndian.PutUint32(buf[secVA:], certLen)  // dwLength
		binary.LittleEndian.PutUint16(buf[secVA+4:], 0x0200) // wRevision (WIN_CERT_REVISION_2_0)
		binary.LittleEndian.PutUint16(buf[secVA+6:], 0x0002) // wCertificateType: PKCS#7
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.exe")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatalf("write test PE: %v", err)
	}
	return path
}

// TestCertLen_OOBSeek verifies that a PE whose security directory VirtualAddress+Size
// extends beyond the file produces an error rather than a seek to arbitrary offset.
func TestCertLen_OOBSeek(t *testing.T) {
	// secVA points past the end of the file; Size is non-zero so we enter the cert path.
	path := buildMinimalPE(t, 0xFFFFFF00, 0x200, 0x08)
	_, err := extractPECertificates(path, &CertInfo{})
	if err == nil {
		t.Fatal("expected error for security directory extending beyond file, got nil")
	}
}

// TestCertLen_Unbounded verifies that a crafted certLen of 0xFFFFFFFF is rejected
// before a 4 GiB allocation is attempted.
func TestCertLen_Unbounded(t *testing.T) {
	// Security directory is within the file, but certLen is huge.
	const secVA = 256
	const secSize = 16 // small, certLen exceeds this
	path := buildMinimalPE(t, secVA, secSize, 0xFFFFFFFF)
	_, err := extractPECertificates(path, &CertInfo{})
	if err == nil {
		t.Fatal("expected error for certLen=0xFFFFFFFF, got nil")
	}
}

// TestCertLen_ExceedsSecDir verifies that certLen > secDir.Size is rejected.
func TestCertLen_ExceedsSecDir(t *testing.T) {
	const secVA = 256
	const secSize = 20      // secDir.Size = 20
	const certLen = 0x10000 // certLen >> secSize
	path := buildMinimalPE(t, secVA, secSize, certLen)
	_, err := extractPECertificates(path, &CertInfo{})
	if err == nil {
		t.Fatal("expected error for certLen > secDir.Size, got nil")
	}
}
