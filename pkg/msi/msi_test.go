/*
Copyright (c) 2026 Security Research
*/
package msi

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// casesPath resolves a path relative to the cases/ directory at the project root.
// Skips the test if the file doesn't exist.
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

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 bytes"},
		{512, "512 bytes"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.input)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeStreamName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Property", "Property"},
		{"\x05DigitalSignature", "_DigitalSignature"},
		{"foo/bar", "foo_bar"},
		{"", "_unnamed"},
		{"a:b*c?d", "a_b_c_d"},
		{"\x01CompObj", "_CompObj"},
		{"normal_name", "normal_name"},
	}

	for _, tt := range tests {
		got := sanitizeStreamName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeStreamName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStringVal(t *testing.T) {
	row := map[string]any{
		"Name":  "test",
		"Value": 42,
	}

	if got := stringVal(row, "Name"); got != "test" {
		t.Errorf("stringVal Name = %q, want %q", got, "test")
	}

	if got := stringVal(row, "Missing"); got != "" {
		t.Errorf("stringVal Missing = %q, want empty", got)
	}

	if got := stringVal(row, "Value"); got != "42" {
		t.Errorf("stringVal Value = %q, want %q", got, "42")
	}
}

func TestIntVal(t *testing.T) {
	tests := []struct {
		input any
		want  int
	}{
		{int(42), 42},
		{int64(100), 100},
		{uint32(200), 200},
		{"string", 0},
		{nil, 0},
	}

	for _, tt := range tests {
		got := intVal(tt.input)
		if got != tt.want {
			t.Errorf("intVal(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestDecodeColumnType(t *testing.T) {
	tests := []struct {
		raw       uint16
		indexSize int
		wantType  columnType
		wantWidth int
		wantNull  bool
	}{
		{0x0000, 2, colShortInt, 2, true},
		{0x1000, 2, colShortInt, 2, false},
		{0x0100, 2, colLongInt, 4, true},
		{0x1100, 2, colLongInt, 4, false},
		{0x0800, 2, colString, 2, true},
		{0x0800, 4, colString, 4, true},
		{0x1800, 4, colString, 4, false},
	}

	for _, tt := range tests {
		col := decodeColumnType(tt.raw, tt.indexSize)
		if col.Type != tt.wantType {
			t.Errorf("decodeColumnType(0x%04x, %d) type = %d, want %d", tt.raw, tt.indexSize, col.Type, tt.wantType)
		}

		if col.Width != tt.wantWidth {
			t.Errorf("decodeColumnType(0x%04x, %d) width = %d, want %d", tt.raw, tt.indexSize, col.Width, tt.wantWidth)
		}

		if col.Nullable != tt.wantNull {
			t.Errorf("decodeColumnType(0x%04x, %d) nullable = %v, want %v", tt.raw, tt.indexSize, col.Nullable, tt.wantNull)
		}
	}
}

func TestDecodeMSIStreamName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"SummaryInformation", "SummaryInformation"},
		// The 0x4840 prefix is the table marker
	}

	for _, tt := range tests {
		got := decodeMSIStreamName(tt.name)
		if got != tt.want {
			t.Errorf("decodeMSIStreamName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMimeToChar(t *testing.T) {
	tests := []struct {
		val  int
		want byte
	}{
		{0, '0'},
		{9, '9'},
		{10, 'A'},
		{35, 'Z'},
		{36, 'a'},
		{61, 'z'},
		{62, '.'},
		{63, '_'},
	}

	for _, tt := range tests {
		got := mimeToChar(tt.val)
		if got != tt.want {
			t.Errorf("mimeToChar(%d) = %c, want %c", tt.val, got, tt.want)
		}
	}
}

func TestStringIndexSize(t *testing.T) {
	tr := &tableReader{stringPool: make([]string, 100)}
	if got := tr.stringIndexSize(); got != 2 {
		t.Errorf("stringIndexSize() = %d, want 2 for small pool", got)
	}

	tr.stringPool = make([]string, 70000)
	if got := tr.stringIndexSize(); got != 4 {
		t.Errorf("stringIndexSize() = %d, want 4 for large pool", got)
	}

	tr.stringPool = make([]string, 65535)
	if got := tr.stringIndexSize(); got != 2 {
		t.Errorf("stringIndexSize() = %d, want 2 for exactly 65535", got)
	}

	tr.stringPool = make([]string, 65536)
	if got := tr.stringIndexSize(); got != 4 {
		t.Errorf("stringIndexSize() = %d, want 4 for exactly 65536", got)
	}
}

func TestReadStringIndex(t *testing.T) {
	tr := &tableReader{}

	buf2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf2, 42)

	if got := tr.readStringIndex(buf2); got != 42 {
		t.Errorf("readStringIndex(2 bytes) = %d, want 42", got)
	}

	buf4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf4, 99999)

	if got := tr.readStringIndex(buf4); got != 99999 {
		t.Errorf("readStringIndex(4 bytes) = %d, want 99999", got)
	}

	if got := tr.readStringIndex([]byte{0}); got != 0 {
		t.Errorf("readStringIndex(1 byte) = %d, want 0", got)
	}

	if got := tr.readStringIndex(nil); got != 0 {
		t.Errorf("readStringIndex(nil) = %d, want 0", got)
	}
}

func TestGetString(t *testing.T) {
	tr := &tableReader{stringPool: []string{"", "hello", "world"}}

	if got := tr.getString(0); got != "" {
		t.Errorf("getString(0) = %q, want empty", got)
	}

	if got := tr.getString(1); got != "hello" {
		t.Errorf("getString(1) = %q, want %q", got, "hello")
	}

	if got := tr.getString(2); got != "world" {
		t.Errorf("getString(2) = %q, want %q", got, "world")
	}

	if got := tr.getString(99); got != "" {
		t.Errorf("getString(99) = %q, want empty", got)
	}

	if got := tr.getString(-1); got != "" {
		t.Errorf("getString(-1) = %q, want empty", got)
	}
}

func TestGetPropertyValue(t *testing.T) {
	tr := &tableReader{}
	rows := []map[string]any{
		{"Property": "ProductName", "Value": "Test App"},
		{"Property": "ProductVersion", "Value": "1.0.0"},
		{"Property": "Manufacturer", "Value": "Test Corp"},
	}

	if got := tr.getPropertyValue(rows, "ProductName"); got != "Test App" {
		t.Errorf("getPropertyValue(ProductName) = %q, want %q", got, "Test App")
	}

	if got := tr.getPropertyValue(rows, "ProductVersion"); got != "1.0.0" {
		t.Errorf("getPropertyValue(ProductVersion) = %q, want %q", got, "1.0.0")
	}

	if got := tr.getPropertyValue(rows, "Missing"); got != "" {
		t.Errorf("getPropertyValue(Missing) = %q, want empty", got)
	}

	if got := tr.getPropertyValue(nil, "ProductName"); got != "" {
		t.Errorf("getPropertyValue on nil = %q, want empty", got)
	}
}

func TestInfoNonexistent(t *testing.T) {
	_, err := Info("/nonexistent/file.msi")
	if err == nil {
		t.Error("Info() should fail for nonexistent file")
	}
}

func TestExtractNonexistent(t *testing.T) {
	_, err := Extract("/nonexistent/file.msi", "")
	if err == nil {
		t.Error("Extract() should fail for nonexistent file")
	}
}

func TestVerifyNonexistent(t *testing.T) {
	_, err := Verify("/nonexistent/file.msi")
	if err == nil {
		t.Error("Verify() should fail for nonexistent file")
	}
}

func TestInfoInvalidFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.msi")
	if err := os.WriteFile(f, []byte("not a valid MSI file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Info(f)
	if err == nil {
		t.Error("Info() should fail for invalid MSI")
	}
}

func TestExtractInvalidFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.msi")
	if err := os.WriteFile(f, []byte("not a valid MSI file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Extract(f, "")
	if err == nil {
		t.Error("Extract() should fail for invalid MSI")
	}
}

func TestVerifyInvalidFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.msi")
	if err := os.WriteFile(f, []byte("not a valid MSI file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Verify(f)
	if err == nil {
		t.Error("Verify() should fail for invalid MSI")
	}
}

func TestIsMSIInvalidData(t *testing.T) {
	data := "not a valid CFBF file at all"
	r := strings.NewReader(data)

	if IsMSI(r, int64(len(data))) {
		t.Error("IsMSI should return false for non-CFBF data")
	}
}

func TestInfoEmptyFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "empty.msi")
	if err := os.WriteFile(f, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Info(f)
	if err == nil {
		t.Error("Info() should fail for empty file")
	}
}

func TestFileNameParsing(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"SHORT~1|LongFileName.txt", "LongFileName.txt"},
		{"simple.txt", "simple.txt"},
		{"A|B|C", "B|C"},
	}

	for _, tt := range tests {
		parts := strings.SplitN(tt.input, "|", 2)
		got := tt.input
		if len(parts) == 2 {
			got = parts[1]
		}

		if got != tt.want {
			t.Errorf("parse %q = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// Golden tests using real MSI files from the cases/ directory.

func TestGolden_Info_7ZipMSI(t *testing.T) {
	msiPath := casesPath(t, "windows/input/7z2409-x64.msi")

	result, err := Info(msiPath)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.FileName != "7z2409-x64.msi" {
		t.Errorf("FileName = %q, want %q", result.FileName, "7z2409-x64.msi")
	}

	if result.Size == 0 {
		t.Error("expected Size > 0")
	}

	// Should have tables parsed
	if len(result.Tables) == 0 {
		t.Error("expected Tables to be populated")
	}

	// Should contain standard MSI tables
	tableSet := make(map[string]bool)
	for _, tbl := range result.Tables {
		tableSet[tbl] = true
	}

	for _, expected := range []string{"Property", "File", "Registry", "Component", "Directory"} {
		if !tableSet[expected] {
			t.Errorf("expected table %q in tables list", expected)
		}
	}

	// Should have files
	if result.FileCount == 0 {
		t.Error("expected FileCount > 0")
	}

	if len(result.Files) == 0 {
		t.Error("expected Files to be populated")
	}

	// Should have registry entries (7-Zip sets registry for shell integration)
	if len(result.RegistryEntries) == 0 {
		t.Error("expected RegistryEntries to be populated")
	}
}

func TestGolden_Extract_7ZipMSI(t *testing.T) {
	msiPath := casesPath(t, "windows/input/7z2409-x64.msi")
	outDir := filepath.Join(t.TempDir(), "extracted")

	report, err := Extract(msiPath, outDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if report.Streams == 0 {
		t.Error("expected Streams > 0")
	}

	if report.Files == 0 {
		t.Error("expected extracted files > 0")
	}

	if report.TotalSize == 0 {
		t.Error("expected TotalSize > 0")
	}

	if len(report.Errors) > 0 {
		t.Errorf("unexpected errors: %v", report.Errors)
	}

	// Verify output directory has files
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	if len(entries) == 0 {
		t.Error("expected files in output directory")
	}
}

func TestGolden_Verify_7ZipMSI(t *testing.T) {
	msiPath := casesPath(t, "windows/input/7z2409-x64.msi")

	result, err := Verify(msiPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.FileName != "7z2409-x64.msi" {
		t.Errorf("FileName = %q, want %q", result.FileName, "7z2409-x64.msi")
	}

	// 7-Zip MSI may or may not be signed; just verify the function succeeds
	// and returns a valid result
	_ = result.HasSignature
}

func TestGolden_IsMSI_7ZipMSI(t *testing.T) {
	msiPath := casesPath(t, "windows/input/7z2409-x64.msi")

	f, err := os.Open(msiPath)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	if !IsMSI(f, stat.Size()) {
		t.Error("IsMSI should return true for a real MSI file")
	}
}
