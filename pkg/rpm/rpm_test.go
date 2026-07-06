/* Copyright (c) 2026 Security Research */
package rpm

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		size int64
		want string
	}{
		{name: "zero", size: 0, want: "0 bytes"},
		{name: "small", size: 512, want: "512 bytes"},
		{name: "one KB", size: 1024, want: "1.0 KB"},
		{name: "kilobytes", size: 2560, want: "2.5 KB"},
		{name: "one MB", size: 1024 * 1024, want: "1.0 MB"},
		{name: "megabytes", size: 5 * 1024 * 1024, want: "5.0 MB"},
		{name: "one GB", size: 1024 * 1024 * 1024, want: "1.0 GB"},
		{name: "1023 bytes", size: 1023, want: "1023 bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatBytes(tt.size)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.size, got, tt.want)
			}
		})
	}
}

func TestInfo_NonexistentFile(t *testing.T) {
	_, err := Info("/tmp/nonexistent-rpm-12345.rpm")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestInfo_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "invalid.rpm")

	if err := os.WriteFile(f, []byte("not an rpm file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Info(f)
	if err == nil {
		t.Error("expected error for invalid rpm file")
	}
}

func TestExtract_NonexistentFile(t *testing.T) {
	_, err := Extract("/tmp/nonexistent-rpm-12345.rpm", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestVerify_NonexistentFile(t *testing.T) {
	_, err := Verify("/tmp/nonexistent-rpm-12345.rpm")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadLead_InvalidMagic(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "bad.rpm")

	data := make([]byte, 96)
	copy(data[0:4], []byte{0x00, 0x00, 0x00, 0x00}) // wrong magic

	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = file.Close() }()

	_, err = readLead(file)
	if err == nil {
		t.Error("expected error for invalid RPM magic")
	}
}

func TestReadLead_ValidMagic(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.rpm")

	data := make([]byte, 96)
	// RPM magic: 0xEDABEEDB
	data[0] = 0xED
	data[1] = 0xAB
	data[2] = 0xEE
	data[3] = 0xDB
	data[4] = 3                              // major version
	data[5] = 0                              // minor version
	binary.BigEndian.PutUint16(data[6:8], 0) // type: binary

	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = file.Close() }()

	lead, err := readLead(file)
	if err != nil {
		t.Fatalf("readLead: %v", err)
	}

	if lead.Major != 3 {
		t.Errorf("expected major=3, got %d", lead.Major)
	}
}

// casesPath resolves a path relative to the cases/ directory at the project root.
func casesPath(t *testing.T, relPath string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not find project root")
		}
		dir = parent
	}
	p := filepath.Join(dir, "cases", relPath)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skipf("test case not available: %s", p)
	}
	return p
}

func TestGolden_Info_Basesystem(t *testing.T) {
	rpmPath := casesPath(t, "linux/input/basesystem.rpm")

	result, err := Info(rpmPath)
	if err != nil {
		// The test file may be a placeholder (e.g. HTML 404); skip if not valid RPM
		t.Skipf("Info failed (file may not be a valid RPM): %v", err)
	}

	if result.Name != "basesystem" {
		t.Errorf("Name = %q, want %q", result.Name, "basesystem")
	}
	if result.FileName != "basesystem.rpm" {
		t.Errorf("FileName = %q, want %q", result.FileName, "basesystem.rpm")
	}
	if result.RPMVersion == "" {
		t.Error("expected non-empty RPMVersion")
	}
}

func TestGolden_Verify_Basesystem(t *testing.T) {
	rpmPath := casesPath(t, "linux/input/basesystem.rpm")

	result, err := Verify(rpmPath)
	if err != nil {
		t.Skipf("Verify failed (file may not be a valid RPM): %v", err)
	}

	if result.FileName != "basesystem.rpm" {
		t.Errorf("FileName = %q, want %q", result.FileName, "basesystem.rpm")
	}
}

func TestGetString(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: 6, Offset: 0, Count: 1}, // type 6 = string
		},
		Data: []byte("test-package\x00"),
	}

	got := getString(h, 1000)
	if got != "test-package" {
		t.Errorf("getString(1000) = %q, want %q", got, "test-package")
	}

	// Non-existent tag
	got = getString(h, 9999)
	if got != "" {
		t.Errorf("getString(9999) = %q, want empty", got)
	}
}

func TestGetInt32(t *testing.T) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, 42)

	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: 4, Offset: 0, Count: 1}, // type 4 = int32
		},
		Data: data,
	}

	got := getInt32(h, 1000)
	if got != 42 {
		t.Errorf("getInt32(1000) = %d, want 42", got)
	}

	// Non-existent tag
	got = getInt32(h, 9999)
	if got != 0 {
		t.Errorf("getInt32(9999) = %d, want 0", got)
	}
}

func TestGetBin(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: typeBin, Offset: 0, Count: 4},
		},
		Data: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00},
	}

	got := getBin(h, 1000)
	if len(got) != 4 || got[0] != 0xDE || got[3] != 0xEF {
		t.Errorf("getBin(1000) = %v, want [DE AD BE EF]", got)
	}

	got = getBin(h, 9999)
	if got != nil {
		t.Errorf("getBin(9999) = %v, want nil", got)
	}
}

func TestGetBin_OffsetOverflow(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: typeBin, Offset: 0, Count: 100},
		},
		Data: []byte{0x01, 0x02},
	}

	got := getBin(h, 1000)
	if got != nil {
		t.Errorf("getBin with overflow = %v, want nil", got)
	}
}

func TestGetString_OffsetOverflow(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: 6, Offset: 999, Count: 1},
		},
		Data: []byte("short"),
	}

	got := getString(h, 1000)
	if got != "" {
		t.Errorf("getString with overflow = %q, want empty", got)
	}
}

func TestGetInt32_OffsetOverflow(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: typeInt32, Offset: 999, Count: 1},
		},
		Data: []byte{0x01, 0x02},
	}

	got := getInt32(h, 1000)
	if got != 0 {
		t.Errorf("getInt32 with overflow = %d, want 0", got)
	}
}

func TestFormatBytes_EdgeCases(t *testing.T) {
	tests := []struct {
		size int64
		want string
	}{
		{0, "0 bytes"},
		{1, "1 bytes"},
		{1023, "1023 bytes"},
		{10240, "10.0 KB"},
		{10*1024*1024 + 512*1024, "10.5 MB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.size)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.size, got, tt.want)
		}
	}
}

// --- Synthetic header section tests ---

// buildHeaderSection constructs a binary header section (preamble + index entries + data store).
func buildHeaderSection(entries []IndexEntry, data []byte) []byte {
	var buf bytes.Buffer

	// Header magic (3 bytes)
	buf.Write([]byte{0x8E, 0xAD, 0xE8})
	// Version (1 byte)
	buf.WriteByte(0x01)
	// Reserved (4 bytes)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))
	// nindex
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(entries)))
	// hsize
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(data)))

	// Index entries (16 bytes each)
	for _, e := range entries {
		_ = binary.Write(&buf, binary.BigEndian, e)
	}

	// Data store
	buf.Write(data)

	return buf.Bytes()
}

// buildLead constructs a valid 96-byte RPM lead.
func buildLead(name string, major, minor uint8) []byte {
	lead := Lead{
		Magic:         rpmMagic,
		Major:         major,
		Minor:         minor,
		Type:          0, // binary
		SignatureType: 5,
	}
	copy(lead.Name[:], name)

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, &lead)

	return buf.Bytes()
}

// buildMinimalRPM constructs a minimal valid RPM with given header tags and optional gzip CPIO payload.
func buildMinimalRPM(sigEntries []IndexEntry, sigData []byte, mainEntries []IndexEntry, mainData []byte, payload []byte) []byte {
	var buf bytes.Buffer

	// Lead (96 bytes)
	buf.Write(buildLead("test-pkg", 3, 0))

	// Signature header
	buf.Write(buildHeaderSection(sigEntries, sigData))

	// Align to 8-byte boundary
	pos := buf.Len()
	pad := (8 - (pos % 8)) % 8
	for range pad {
		buf.WriteByte(0)
	}

	// Main header
	buf.Write(buildHeaderSection(mainEntries, mainData))

	// Payload
	if len(payload) > 0 {
		buf.Write(payload)
	}

	return buf.Bytes()
}

func TestReadHeaderSection_Valid(t *testing.T) {
	// Build a header with one string entry
	dataStore := []byte("hello\x00")
	entries := []IndexEntry{
		{Tag: 1000, Type: typeString, Offset: 0, Count: 1},
	}

	raw := buildHeaderSection(entries, dataStore)
	r := bytes.NewReader(raw)

	h, err := readHeaderSection(r)
	if err != nil {
		t.Fatalf("readHeaderSection: %v", err)
	}

	if len(h.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(h.Entries))
	}

	if h.Entries[0].Tag != 1000 {
		t.Errorf("tag = %d, want 1000", h.Entries[0].Tag)
	}

	got := getString(h, 1000)
	if got != "hello" {
		t.Errorf("getString = %q, want %q", got, "hello")
	}
}

func TestReadHeaderSection_InvalidMagic(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	r := bytes.NewReader(data)

	_, err := readHeaderSection(r)
	if err == nil {
		t.Error("expected error for invalid header magic")
	}
}

func TestReadHeaderSection_TooShort(t *testing.T) {
	data := []byte{0x8E, 0xAD}
	r := bytes.NewReader(data)

	_, err := readHeaderSection(r)
	if err == nil {
		t.Error("expected error for truncated header")
	}
}

func TestReadHeaderSection_ZeroEntries(t *testing.T) {
	raw := buildHeaderSection(nil, []byte{})
	r := bytes.NewReader(raw)

	h, err := readHeaderSection(r)
	if err != nil {
		t.Fatalf("readHeaderSection: %v", err)
	}

	if len(h.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(h.Entries))
	}
}

func TestInfo_Synthetic(t *testing.T) {
	// Build data store with multiple string tags
	var dataStore bytes.Buffer
	nameOffset := dataStore.Len()
	dataStore.WriteString("test-package\x00")
	versionOffset := dataStore.Len()
	dataStore.WriteString("1.2.3\x00")
	archOffset := dataStore.Len()
	dataStore.WriteString("x86_64\x00")
	compressorOffset := dataStore.Len()
	dataStore.WriteString("gzip\x00")

	mainEntries := []IndexEntry{
		{Tag: tagName, Type: typeString, Offset: uint32(nameOffset), Count: 1},
		{Tag: tagVersion, Type: typeString, Offset: uint32(versionOffset), Count: 1},
		{Tag: tagArch, Type: typeString, Offset: uint32(archOffset), Count: 1},
		{Tag: tagPayloadCompressor, Type: typeString, Offset: uint32(compressorOffset), Count: 1},
	}

	// Sig header with an MD5 hash
	md5Data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	sigEntries := []IndexEntry{
		{Tag: sigTagMD5, Type: typeBin, Offset: 0, Count: uint32(len(md5Data))},
	}

	rpmData := buildMinimalRPM(sigEntries, md5Data, mainEntries, dataStore.Bytes(), nil)

	tmpFile := filepath.Join(t.TempDir(), "test.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Info(tmpFile)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Name != "test-package" {
		t.Errorf("Name = %q, want %q", result.Name, "test-package")
	}

	if result.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", result.Version, "1.2.3")
	}

	if result.Arch != "x86_64" {
		t.Errorf("Arch = %q, want %q", result.Arch, "x86_64")
	}

	if result.RPMVersion != "3.0" {
		t.Errorf("RPMVersion = %q, want %q", result.RPMVersion, "3.0")
	}

	if result.Type != "binary" {
		t.Errorf("Type = %q, want %q", result.Type, "binary")
	}

	if !result.HasSignature {
		t.Error("expected HasSignature=true with MD5 tag")
	}

	if result.HeaderTagCount != 4 {
		t.Errorf("HeaderTagCount = %d, want 4", result.HeaderTagCount)
	}

	if result.SigTagCount != 1 {
		t.Errorf("SigTagCount = %d, want 1", result.SigTagCount)
	}
}

func TestVerify_Synthetic(t *testing.T) {
	// Build sig header with SHA1 (string type) and MD5 (bin type)
	var sigData bytes.Buffer
	md5Hash := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	sigData.Write(md5Hash)
	sha1Offset := sigData.Len()
	sigData.WriteString("abc123sha1hash\x00")

	sigEntries := []IndexEntry{
		{Tag: sigTagMD5, Type: typeBin, Offset: 0, Count: uint32(len(md5Hash))},
		{Tag: sigTagSHA1, Type: typeString, Offset: uint32(sha1Offset), Count: 1},
	}

	// Minimal main header (needs at least empty data)
	mainEntries := []IndexEntry{}

	rpmData := buildMinimalRPM(sigEntries, sigData.Bytes(), mainEntries, []byte{}, nil)

	tmpFile := filepath.Join(t.TempDir(), "verify.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(tmpFile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Hashes["md5"] == "" {
		t.Error("expected md5 hash in result")
	}

	if result.Hashes["sha1"] != "abc123sha1hash" {
		t.Errorf("sha1 = %q, want %q", result.Hashes["sha1"], "abc123sha1hash")
	}
}

// buildCPIOEntry constructs a single CPIO newc entry.
func buildCPIOEntry(name string, mode uint32, data []byte) []byte {
	var buf bytes.Buffer

	nameBytes := append([]byte(name), 0) // null-terminated
	nameSize := len(nameBytes)
	fileSize := len(data)

	header := fmt.Sprintf("070701"+
		"%08X"+ // inode
		"%08X"+ // mode
		"%08X"+ // uid
		"%08X"+ // gid
		"%08X"+ // nlink
		"%08X"+ // mtime
		"%08X"+ // filesize
		"%08X"+ // devmajor
		"%08X"+ // devminor
		"%08X"+ // rdevmajor
		"%08X"+ // rdevminor
		"%08X"+ // namesize
		"%08X", // check
		1, mode, 0, 0, 1, 0, fileSize, 0, 0, 0, 0, nameSize, 0)

	buf.WriteString(header)
	buf.Write(nameBytes)

	// Pad name to 4-byte boundary (from start of header)
	headerAndName := 110 + nameSize
	namePad := (4 - (headerAndName % 4)) % 4
	for range namePad {
		buf.WriteByte(0)
	}

	// File data
	buf.Write(data)

	// Pad data to 4-byte boundary
	dataPad := (4 - (fileSize % 4)) % 4
	for range dataPad {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

func buildCPIOTrailer() []byte {
	return buildCPIOEntry("TRAILER!!!", 0, nil)
}

func TestExtractCPIO(t *testing.T) {
	var archive bytes.Buffer

	// Add a directory
	archive.Write(buildCPIOEntry("testdir", 0o040755, nil))

	// Add a regular file
	fileContent := []byte("hello world")
	archive.Write(buildCPIOEntry("testdir/hello.txt", 0o100644, fileContent))

	// Add trailer
	archive.Write(buildCPIOTrailer())

	outDir := t.TempDir()
	files, dirs, totalSize, errs := extractCPIO(&archive, outDir)

	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	if dirs != 1 {
		t.Errorf("dirs = %d, want 1", dirs)
	}

	if files != 1 {
		t.Errorf("files = %d, want 1", files)
	}

	if totalSize != int64(len(fileContent)) {
		t.Errorf("totalSize = %d, want %d", totalSize, len(fileContent))
	}

	// Verify file contents
	got, err := os.ReadFile(filepath.Join(outDir, "testdir", "hello.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}

	if string(got) != "hello world" {
		t.Errorf("file content = %q, want %q", got, "hello world")
	}
}

func TestExtractCPIO_PathTraversal(t *testing.T) {
	var archive bytes.Buffer

	archive.Write(buildCPIOEntry("../../etc/passwd", 0o100644, []byte("pwned")))
	archive.Write(buildCPIOTrailer())

	outDir := t.TempDir()
	files, _, _, errs := extractCPIO(&archive, outDir)

	if files != 0 {
		t.Errorf("expected 0 files extracted for path traversal, got %d", files)
	}

	if len(errs) == 0 {
		t.Error("expected path traversal error")
	}
}

func TestExtract_Synthetic(t *testing.T) {
	// Build CPIO archive
	var cpioData bytes.Buffer
	cpioData.Write(buildCPIOEntry("readme.txt", 0o100644, []byte("test content")))
	cpioData.Write(buildCPIOTrailer())

	// Gzip compress the CPIO data
	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	if _, err := gzw.Write(cpioData.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}

	// Build data store with compressor tag
	var mainData bytes.Buffer
	mainData.WriteString("gzip\x00")
	mainEntries := []IndexEntry{
		{Tag: tagPayloadCompressor, Type: typeString, Offset: 0, Count: 1},
	}

	rpmData := buildMinimalRPM(nil, []byte{}, mainEntries, mainData.Bytes(), gzBuf.Bytes())

	tmpFile := filepath.Join(t.TempDir(), "extract.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	report, err := Extract(tmpFile, outDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if report.Files != 1 {
		t.Errorf("Files = %d, want 1", report.Files)
	}

	if report.Compressor != "gzip" {
		t.Errorf("Compressor = %q, want %q", report.Compressor, "gzip")
	}

	// Verify file extracted
	got, err := os.ReadFile(filepath.Join(outDir, "readme.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}

	if string(got) != "test content" {
		t.Errorf("content = %q, want %q", got, "test content")
	}
}

func TestExtractCPIO_Symlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		tmp := t.TempDir()
		if err := os.Symlink("target", filepath.Join(tmp, "link")); err != nil {
			t.Skip("symlinks require elevated privileges on Windows")
		}
	}
	var archive bytes.Buffer

	// Add a regular file
	archive.Write(buildCPIOEntry("target.txt", 0o100644, []byte("target content")))
	// Add a symlink (mode 0o120000 + perms, data = link target)
	archive.Write(buildCPIOEntry("link.txt", 0o120777, []byte("target.txt")))
	archive.Write(buildCPIOTrailer())

	outDir := t.TempDir()
	files, _, _, errs := extractCPIO(&archive, outDir)

	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	if files != 2 {
		t.Errorf("files = %d, want 2", files)
	}

	// Verify symlink
	linkTarget, err := os.Readlink(filepath.Join(outDir, "link.txt"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}

	if linkTarget != "target.txt" {
		t.Errorf("symlink target = %q, want %q", linkTarget, "target.txt")
	}
}

func TestExtractCPIO_BadMagic(t *testing.T) {
	data := bytes.NewReader([]byte("BADMAGICxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
	_, _, _, errs := extractCPIO(data, t.TempDir())

	if len(errs) == 0 {
		t.Error("expected error for bad CPIO magic")
	}
}

func TestGetString_I18NString(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: typeI18NString, Offset: 0, Count: 1},
		},
		Data: []byte("localized-name\x00"),
	}

	got := getString(h, 1000)
	if got != "localized-name" {
		t.Errorf("getString(i18n) = %q, want %q", got, "localized-name")
	}
}

func TestGetString_WrongType(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: typeBin, Offset: 0, Count: 4},
		},
		Data: []byte{0x01, 0x02, 0x03, 0x04},
	}

	got := getString(h, 1000)
	if got != "" {
		t.Errorf("getString(bin type) = %q, want empty", got)
	}
}

func TestGetInt32_WrongType(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: typeString, Offset: 0, Count: 1},
		},
		Data: []byte("text\x00"),
	}

	got := getInt32(h, 1000)
	if got != 0 {
		t.Errorf("getInt32(string type) = %d, want 0", got)
	}
}

func TestGetBin_WrongType(t *testing.T) {
	h := &HeaderSection{
		Entries: []IndexEntry{
			{Tag: 1000, Type: typeString, Offset: 0, Count: 1},
		},
		Data: []byte("text\x00"),
	}

	got := getBin(h, 1000)
	if got != nil {
		t.Errorf("getBin(string type) = %v, want nil", got)
	}
}

func TestInfo_Synthetic_SourceType(t *testing.T) {
	// Build RPM with Type=1 (source)
	lead := Lead{
		Magic: rpmMagic,
		Major: 3,
		Minor: 0,
		Type:  1, // source RPM
	}
	copy(lead.Name[:], "source-pkg")

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, &lead)

	// Sig header (empty)
	buf.Write(buildHeaderSection(nil, []byte{}))

	// Align
	pos := buf.Len()
	pad := (8 - (pos % 8)) % 8
	for range pad {
		buf.WriteByte(0)
	}

	// Main header with name tag
	var mainData bytes.Buffer
	mainData.WriteString("my-source\x00")
	mainEntries := []IndexEntry{
		{Tag: tagName, Type: typeString, Offset: 0, Count: 1},
	}
	buf.Write(buildHeaderSection(mainEntries, mainData.Bytes()))

	tmpFile := filepath.Join(t.TempDir(), "source.rpm")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Info(tmpFile)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Type != "source" {
		t.Errorf("Type = %q, want %q", result.Type, "source")
	}
}

// --- Additional coverage tests ---

func TestInfo_Synthetic_AllSigTags(t *testing.T) {
	// Build sig data: MD5 (bin), SHA1 (string), SHA256 (string), RSA, DSA, PGP, GPG markers
	var sigData bytes.Buffer

	md5Hash := make([]byte, 16)
	for i := range md5Hash {
		md5Hash[i] = byte(i + 1)
	}
	md5Offset := sigData.Len()
	sigData.Write(md5Hash)

	sha1Offset := sigData.Len()
	sigData.WriteString("deadbeefsha1value\x00")

	sha256Offset := sigData.Len()
	sigData.WriteString("abcd1234sha256value\x00")

	// RSA, DSA, PGP, GPG use bin type with placeholder data
	rsaOffset := sigData.Len()
	sigData.Write([]byte{0x01, 0x02})

	dsaOffset := sigData.Len()
	sigData.Write([]byte{0x03, 0x04})

	pgpOffset := sigData.Len()
	sigData.Write([]byte{0x05, 0x06})

	gpgOffset := sigData.Len()
	sigData.Write([]byte{0x07, 0x08})

	sigEntries := []IndexEntry{
		{Tag: sigTagMD5, Type: typeBin, Offset: uint32(md5Offset), Count: 16},
		{Tag: sigTagSHA1, Type: typeString, Offset: uint32(sha1Offset), Count: 1},
		{Tag: sigTagSHA256, Type: typeString, Offset: uint32(sha256Offset), Count: 1},
		{Tag: sigTagRSA, Type: typeBin, Offset: uint32(rsaOffset), Count: 2},
		{Tag: sigTagDSA, Type: typeBin, Offset: uint32(dsaOffset), Count: 2},
		{Tag: sigTagPGP, Type: typeBin, Offset: uint32(pgpOffset), Count: 2},
		{Tag: sigTagGPG, Type: typeBin, Offset: uint32(gpgOffset), Count: 2},
	}

	// Main header with epoch tag (int32)
	var mainData bytes.Buffer
	nameOffset := mainData.Len()
	mainData.WriteString("allsigs-pkg\x00")
	epochOffset := mainData.Len()
	epochBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(epochBuf, 5)
	mainData.Write(epochBuf)

	mainEntries := []IndexEntry{
		{Tag: tagName, Type: typeString, Offset: uint32(nameOffset), Count: 1},
		{Tag: tagEpoch, Type: typeInt32, Offset: uint32(epochOffset), Count: 1},
	}

	rpmData := buildMinimalRPM(sigEntries, sigData.Bytes(), mainEntries, mainData.Bytes(), nil)

	tmpFile := filepath.Join(t.TempDir(), "allsigs.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Info(tmpFile)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if !result.HasSignature {
		t.Error("expected HasSignature=true")
	}

	if result.SignatureInfo["sha1"] != "deadbeefsha1value" {
		t.Errorf("sha1 = %q, want %q", result.SignatureInfo["sha1"], "deadbeefsha1value")
	}

	if result.SignatureInfo["sha256"] != "abcd1234sha256value" {
		t.Errorf("sha256 = %q, want %q", result.SignatureInfo["sha256"], "abcd1234sha256value")
	}

	if result.SignatureInfo["rsa_header_sig"] != "present" {
		t.Errorf("rsa_header_sig = %q, want %q", result.SignatureInfo["rsa_header_sig"], "present")
	}

	if result.SignatureInfo["dsa_header_sig"] != "present" {
		t.Errorf("dsa_header_sig = %q, want %q", result.SignatureInfo["dsa_header_sig"], "present")
	}

	if result.SignatureInfo["pgp_sig"] != "present" {
		t.Errorf("pgp_sig = %q, want %q", result.SignatureInfo["pgp_sig"], "present")
	}

	if result.SignatureInfo["gpg_sig"] != "present" {
		t.Errorf("gpg_sig = %q, want %q", result.SignatureInfo["gpg_sig"], "present")
	}

	if result.Epoch != "5" {
		t.Errorf("Epoch = %q, want %q", result.Epoch, "5")
	}
}

func TestVerify_Synthetic_AllSigTags(t *testing.T) {
	var sigData bytes.Buffer

	md5Hash := make([]byte, 16)
	md5Offset := sigData.Len()
	sigData.Write(md5Hash)

	sha256Offset := sigData.Len()
	sigData.WriteString("sha256hashvalue\x00")

	rsaOffset := sigData.Len()
	sigData.Write([]byte{0xAA})

	dsaOffset := sigData.Len()
	sigData.Write([]byte{0xBB})

	pgpOffset := sigData.Len()
	sigData.Write([]byte{0xCC})

	gpgOffset := sigData.Len()
	sigData.Write([]byte{0xDD})

	sigEntries := []IndexEntry{
		{Tag: sigTagMD5, Type: typeBin, Offset: uint32(md5Offset), Count: 16},
		{Tag: sigTagSHA256, Type: typeString, Offset: uint32(sha256Offset), Count: 1},
		{Tag: sigTagRSA, Type: typeBin, Offset: uint32(rsaOffset), Count: 1},
		{Tag: sigTagDSA, Type: typeBin, Offset: uint32(dsaOffset), Count: 1},
		{Tag: sigTagPGP, Type: typeBin, Offset: uint32(pgpOffset), Count: 1},
		{Tag: sigTagGPG, Type: typeBin, Offset: uint32(gpgOffset), Count: 1},
	}

	rpmData := buildMinimalRPM(sigEntries, sigData.Bytes(), nil, []byte{}, nil)

	tmpFile := filepath.Join(t.TempDir(), "verify_all.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(tmpFile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Hashes["sha256"] != "sha256hashvalue" {
		t.Errorf("sha256 = %q, want %q", result.Hashes["sha256"], "sha256hashvalue")
	}

	if !result.HasSignature {
		t.Error("expected HasSignature=true")
	}

	expectedSigs := map[string]bool{
		"RSA (header-only)":    false,
		"DSA (header-only)":    false,
		"PGP (header+payload)": false,
		"GPG (header+payload)": false,
	}

	for _, s := range result.Signatures {
		expectedSigs[s] = true
	}

	for sig, found := range expectedSigs {
		if !found {
			t.Errorf("expected signature %q in result", sig)
		}
	}
}

func TestExtract_Synthetic_DefaultOutputDir(t *testing.T) {
	// When outputDir is empty, Extract derives a name from the rpm filename.
	var cpioData bytes.Buffer
	cpioData.Write(buildCPIOEntry("file.txt", 0o100644, []byte("data")))
	cpioData.Write(buildCPIOTrailer())

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	if _, err := gzw.Write(cpioData.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}

	var mainData bytes.Buffer
	mainData.WriteString("gzip\x00")
	mainEntries := []IndexEntry{
		{Tag: tagPayloadCompressor, Type: typeString, Offset: 0, Count: 1},
	}

	rpmData := buildMinimalRPM(nil, []byte{}, mainEntries, mainData.Bytes(), gzBuf.Bytes())

	// Write RPM into a dedicated temp dir so the derived output dir lands nearby.
	rpmDir := t.TempDir()
	tmpFile := filepath.Join(rpmDir, "mypkg.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	// Empty outputDir — Extract should derive "mypkg_extracted".
	report, err := Extract(tmpFile, "")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if report.Output == "" {
		t.Error("expected non-empty Output in report")
	}

	// Clean up derived output dir.
	_ = os.RemoveAll(report.Output)
}

func TestExtract_Synthetic_DefaultCompressor(t *testing.T) {
	// When no compressor tag is present the code defaults to "gzip".
	var cpioData bytes.Buffer
	cpioData.Write(buildCPIOEntry("hello.txt", 0o100644, []byte("hello")))
	cpioData.Write(buildCPIOTrailer())

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	if _, err := gzw.Write(cpioData.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}

	// Main header with NO compressor tag — code should fall back to "gzip".
	rpmData := buildMinimalRPM(nil, []byte{}, nil, []byte{}, gzBuf.Bytes())

	tmpFile := filepath.Join(t.TempDir(), "nocomp.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	report, err := Extract(tmpFile, outDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if report.Compressor != "gzip" {
		t.Errorf("Compressor = %q, want %q", report.Compressor, "gzip")
	}

	if report.Files != 1 {
		t.Errorf("Files = %d, want 1", report.Files)
	}
}

func TestExtract_Synthetic_Bzip2(t *testing.T) {
	// bzip2 compression requires the external bzip2 binary since Go's standard
	// library only provides a bzip2 reader, not a writer.
	if _, err := os.Stat("/usr/bin/bzip2"); err != nil {
		t.Skip("bzip2 binary not available")
	}

	var cpioData bytes.Buffer
	cpioData.Write(buildCPIOEntry("bz2file.txt", 0o100644, []byte("bzip2 content")))
	cpioData.Write(buildCPIOTrailer())

	tmpCPIO := filepath.Join(t.TempDir(), "payload.cpio")
	if err := os.WriteFile(tmpCPIO, cpioData.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	proc, err := os.StartProcess("/usr/bin/bzip2", []string{"bzip2", "-k", tmpCPIO},
		&os.ProcAttr{Files: []*os.File{nil, os.Stdout, os.Stderr}})
	if err != nil {
		t.Skipf("could not start bzip2: %v", err)
	}

	state, err := proc.Wait()
	if err != nil || !state.Success() {
		t.Skipf("bzip2 compression failed")
	}

	bz2Data, err := os.ReadFile(tmpCPIO + ".bz2")
	if err != nil {
		t.Skipf("could not read bzip2 output: %v", err)
	}

	var mainData bytes.Buffer
	mainData.WriteString("bzip2\x00")
	mainEntries := []IndexEntry{
		{Tag: tagPayloadCompressor, Type: typeString, Offset: 0, Count: 1},
	}

	rpmData := buildMinimalRPM(nil, []byte{}, mainEntries, mainData.Bytes(), bz2Data)
	tmpFile := filepath.Join(t.TempDir(), "bzip2.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	report, err := Extract(tmpFile, outDir)
	if err != nil {
		t.Fatalf("Extract bzip2: %v", err)
	}

	if report.Compressor != "bzip2" {
		t.Errorf("Compressor = %q, want %q", report.Compressor, "bzip2")
	}

	if report.Files != 1 {
		t.Errorf("Files = %d, want 1", report.Files)
	}
}

func TestExtract_Synthetic_LzmaUnsupported(t *testing.T) {
	var mainData bytes.Buffer
	mainData.WriteString("lzma\x00")
	mainEntries := []IndexEntry{
		{Tag: tagPayloadCompressor, Type: typeString, Offset: 0, Count: 1},
	}

	rpmData := buildMinimalRPM(nil, []byte{}, mainEntries, mainData.Bytes(), []byte("fake payload"))
	tmpFile := filepath.Join(t.TempDir(), "lzma.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	report, err := Extract(tmpFile, outDir)
	if err == nil {
		t.Error("expected error for lzma compressor")
	}

	// report may be returned even on error
	if report != nil && report.Compressor != "lzma" {
		t.Errorf("Compressor = %q, want %q", report.Compressor, "lzma")
	}
}

func TestExtract_Synthetic_UnknownCompressor(t *testing.T) {
	// An unknown compressor falls through to the default case (raw reader).
	// Without valid CPIO data the extraction will emit cpio errors but not fail Extract itself.
	var mainData bytes.Buffer
	mainData.WriteString("unknown\x00")
	mainEntries := []IndexEntry{
		{Tag: tagPayloadCompressor, Type: typeString, Offset: 0, Count: 1},
	}

	rpmData := buildMinimalRPM(nil, []byte{}, mainEntries, mainData.Bytes(), []byte("not-cpio"))
	tmpFile := filepath.Join(t.TempDir(), "unknown_comp.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	report, err := Extract(tmpFile, outDir)
	if err != nil {
		t.Fatalf("Extract with unknown compressor: %v", err)
	}

	if report.Compressor != "unknown" {
		t.Errorf("Compressor = %q, want %q", report.Compressor, "unknown")
	}
}

func TestExtract_Synthetic_InvalidGzip(t *testing.T) {
	var mainData bytes.Buffer
	mainData.WriteString("gzip\x00")
	mainEntries := []IndexEntry{
		{Tag: tagPayloadCompressor, Type: typeString, Offset: 0, Count: 1},
	}

	rpmData := buildMinimalRPM(nil, []byte{}, mainEntries, mainData.Bytes(), []byte("not gzip data"))
	tmpFile := filepath.Join(t.TempDir(), "badgzip.rpm")
	if err := os.WriteFile(tmpFile, rpmData, 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	_, err := Extract(tmpFile, outDir)
	if err == nil {
		t.Error("expected error for invalid gzip payload")
	}
}

func TestExtract_Synthetic_InvalidFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.rpm")
	if err := os.WriteFile(tmpFile, []byte("not an rpm"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Extract(tmpFile, t.TempDir())
	if err == nil {
		t.Error("expected error for invalid RPM file in Extract")
	}
}

func TestVerify_Synthetic_InvalidFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.rpm")
	if err := os.WriteFile(tmpFile, []byte("not an rpm"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Verify(tmpFile)
	if err == nil {
		t.Error("expected error for invalid RPM file in Verify")
	}
}

func TestReadHeaderSection_TooLarge(t *testing.T) {
	// Construct a header preamble with nindex and hsize exceeding limits.
	var buf bytes.Buffer
	buf.Write([]byte{0x8E, 0xAD, 0xE8})                      // magic
	buf.WriteByte(0x01)                                      // version
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))      // reserved
	_ = binary.Write(&buf, binary.BigEndian, uint32(200000)) // nindex > 100000
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))      // hsize

	r := bytes.NewReader(buf.Bytes())
	_, err := readHeaderSection(r)
	if err == nil {
		t.Error("expected error for too-large header")
	}
}

func TestExtractCPIO_EmptyAndDotNames(t *testing.T) {
	// Entries with empty name or "." should be skipped (continue path in extractCPIO).
	// We craft CPIO entries directly: name="" (after stripping "./" prefix) and name="."
	var archive bytes.Buffer

	// An entry whose name is "." after stripping — use mode=regular file with no data
	archive.Write(buildCPIOEntry(".", 0o100644, nil))

	// A normal entry to confirm loop continues
	archive.Write(buildCPIOEntry("real.txt", 0o100644, []byte("real")))
	archive.Write(buildCPIOTrailer())

	outDir := t.TempDir()
	files, _, _, errs := extractCPIO(&archive, outDir)

	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	// "." is skipped, "real.txt" has filesize>0 so it counts
	if files != 1 {
		t.Errorf("files = %d, want 1", files)
	}
}

func TestExtractCPIO_ZeroSizeNonDirFile(t *testing.T) {
	// A regular file with filesize=0 should not be written (else branch not taken).
	// Confirm it does not increment files count and no error occurs.
	var archive bytes.Buffer
	archive.Write(buildCPIOEntry("empty.txt", 0o100644, nil))
	archive.Write(buildCPIOTrailer())

	outDir := t.TempDir()
	files, dirs, _, errs := extractCPIO(&archive, outDir)

	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}

	if files != 0 {
		t.Errorf("files = %d, want 0 (zero-size file not counted)", files)
	}

	if dirs != 0 {
		t.Errorf("dirs = %d, want 0", dirs)
	}
}

func TestReadHeaderSection_MultipleEntries(t *testing.T) {
	var dataStore bytes.Buffer
	// String at offset 0
	dataStore.WriteString("name\x00")
	// Int32 at offset 5
	int32Offset := dataStore.Len()
	int32Buf := make([]byte, 4)
	binary.BigEndian.PutUint32(int32Buf, 99)
	dataStore.Write(int32Buf)

	entries := []IndexEntry{
		{Tag: 1000, Type: typeString, Offset: 0, Count: 1},
		{Tag: 1001, Type: typeInt32, Offset: uint32(int32Offset), Count: 1},
	}

	raw := buildHeaderSection(entries, dataStore.Bytes())
	r := bytes.NewReader(raw)

	h, err := readHeaderSection(r)
	if err != nil {
		t.Fatalf("readHeaderSection: %v", err)
	}

	if len(h.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(h.Entries))
	}

	if got := getString(h, 1000); got != "name" {
		t.Errorf("getString(1000) = %q, want %q", got, "name")
	}

	if got := getInt32(h, 1001); got != 99 {
		t.Errorf("getInt32(1001) = %d, want 99", got)
	}
}
