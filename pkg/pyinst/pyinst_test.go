package pyinst

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// buildCookie21 builds a valid PyInstaller 2.1+ cookie (88 bytes).
// overlayPos is where the overlay starts relative to the file start.
// tocOffFromOverlay is the TOC offset from overlay start.
// tocLen is the TOC length in bytes.
// pyver is the encoded Python version (e.g. 311 for 3.11).
// pylibname is the Python library name (max 64 chars, null-padded).
func buildCookie21(pkgLen uint32, tocOff uint32, tocLen int32, pyver int32, pylibname string) []byte {
	buf := make([]byte, Cookie21Size)
	copy(buf[0:8], Magic)
	binary.BigEndian.PutUint32(buf[8:12], pkgLen)
	binary.BigEndian.PutUint32(buf[12:16], tocOff)
	binary.BigEndian.PutUint32(buf[16:20], uint32(tocLen))
	binary.BigEndian.PutUint32(buf[20:24], uint32(pyver))
	copy(buf[24:88], pylibname)
	return buf
}

// buildCookie20 builds a valid PyInstaller 2.0 cookie (24 bytes).
func buildCookie20(pkgLen int32, tocOff int32, tocLen int32, pyver int32) []byte {
	buf := make([]byte, Cookie20Size)
	copy(buf[0:8], Magic)
	binary.BigEndian.PutUint32(buf[8:12], uint32(pkgLen))
	binary.BigEndian.PutUint32(buf[12:16], uint32(tocOff))
	binary.BigEndian.PutUint32(buf[16:20], uint32(tocLen))
	binary.BigEndian.PutUint32(buf[20:24], uint32(pyver))
	return buf
}

// buildTOCEntry builds one TOC entry in the CArchive format.
func buildTOCEntry(name string, pos, cmprSize, uncmprSize uint32, compressed bool, typeByte byte) []byte {
	nameBytes := append([]byte(name), 0) // null-terminated
	entrySize := 4 + 4 + 4 + 4 + 1 + 1 + len(nameBytes)
	buf := make([]byte, entrySize)
	binary.BigEndian.PutUint32(buf[0:4], uint32(entrySize))
	binary.BigEndian.PutUint32(buf[4:8], pos)
	binary.BigEndian.PutUint32(buf[8:12], cmprSize)
	binary.BigEndian.PutUint32(buf[12:16], uncmprSize)
	if compressed {
		buf[16] = 1
	}
	buf[17] = typeByte
	copy(buf[18:], nameBytes)
	return buf
}

// buildFakePyInstBinary constructs a minimal PyInstaller binary (2.1+) with one TOC entry.
func buildFakePyInstBinary(pyver int32, pylibname string, entries []tocEntrySpec) []byte {
	// Stub: some fake bootloader data
	stub := bytes.Repeat([]byte{0x00}, 64)

	// Overlay starts after stub
	overlayStart := len(stub)

	// Build entry data blobs and collect TOC entries
	var entryDataBuf bytes.Buffer
	var tocBuf bytes.Buffer

	for _, e := range entries {
		pos := uint32(entryDataBuf.Len())
		var dataToWrite []byte
		if e.compressed {
			var zBuf bytes.Buffer
			w := zlib.NewWriter(&zBuf)
			_, _ = w.Write(e.data)
			_ = w.Close()
			dataToWrite = zBuf.Bytes()
		} else {
			dataToWrite = e.data
		}
		cmprSize := uint32(len(dataToWrite))
		uncmprSize := uint32(len(e.data))
		entryDataBuf.Write(dataToWrite)

		tocEntry := buildTOCEntry(e.name, pos, cmprSize, uncmprSize, e.compressed, e.typeByte)
		tocBuf.Write(tocEntry)
	}

	tocOff := uint32(entryDataBuf.Len())
	tocLen := int32(tocBuf.Len())

	// Build the overlay: [entry data] [TOC] [cookie]
	var overlay bytes.Buffer
	overlay.Write(entryDataBuf.Bytes())
	overlay.Write(tocBuf.Bytes())

	pkgLen := uint32(overlay.Len() + Cookie21Size)
	cookie := buildCookie21(pkgLen, tocOff, tocLen, pyver, pylibname)
	overlay.Write(cookie)

	// Combine stub + overlay
	var result bytes.Buffer
	result.Write(stub)
	result.Write(overlay.Bytes())

	_ = overlayStart // used implicitly via pkgLen
	return result.Bytes()
}

type tocEntrySpec struct {
	name       string
	data       []byte
	compressed bool
	typeByte   byte
}

// writeTempFile writes data to a temp file and returns the path.
func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIsPyInstaller(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    bool
		wantErr bool
	}{
		{
			name: "valid magic at end",
			data: append(bytes.Repeat([]byte{0x00}, 100), Magic...),
			want: true,
		},
		{
			name: "valid magic embedded",
			data: func() []byte {
				b := make([]byte, 200)
				copy(b[150:], Magic)
				return b
			}(),
			want: true,
		},
		{
			name: "no magic cookie",
			data: bytes.Repeat([]byte{0xDE, 0xAD}, 100),
			want: false,
		},
		{
			name: "empty file",
			data: []byte{},
			want: false,
		},
		{
			name: "file smaller than magic",
			data: []byte{0x01, 0x02, 0x03},
			want: false,
		},
		{
			name: "partial magic (7 of 8 bytes)",
			data: append(bytes.Repeat([]byte{0x00}, 50), Magic[:7]...),
			want: false,
		},
		{
			name: "magic exactly",
			data: Magic,
			want: true,
		},
		{
			name: "PE-like stub with magic at tail",
			data: func() []byte {
				// Simulate PE header MZ + padding + cookie
				pe := []byte{'M', 'Z'}
				pe = append(pe, bytes.Repeat([]byte{0x00}, 8190)...)
				pe = append(pe, Magic...)
				return pe
			}(),
			want: true,
		},
		{
			name: "random binary no magic",
			data: func() []byte {
				b := make([]byte, 16384)
				for i := range b {
					b[i] = byte(i % 251)
				}
				return b
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, "test.exe", tt.data)
			got, err := IsPyInstaller(path)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("IsPyInstaller() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPyInstaller_FileNotFound(t *testing.T) {
	_, err := IsPyInstaller("/nonexistent/path/file.exe")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantPyInst    bool
		wantVer       string
		wantPyVer     string
		wantPyLib     string
		wantEntries   int
		wantMainCount int
	}{
		{
			name: "valid 2.1+ binary with entries",
			data: buildFakePyInstBinary(311, "libpython3.11.so", []tocEntrySpec{
				{name: "main_script", data: []byte("print('hello')"), compressed: false, typeByte: 's'},
				{name: "mymodule", data: []byte("x = 1"), compressed: false, typeByte: 'm'},
				{name: "PYZ-00.pyz", data: []byte{0x00}, compressed: false, typeByte: 'z'},
			}),
			wantPyInst:    true,
			wantVer:       "2.1+",
			wantPyVer:     "3.11",
			wantPyLib:     "libpython3.11.so",
			wantEntries:   3,
			wantMainCount: 1,
		},
		{
			name: "valid 2.1+ with compressed entry",
			data: buildFakePyInstBinary(310, "libpython3.10.so", []tocEntrySpec{
				{name: "app", data: bytes.Repeat([]byte("import os\n"), 100), compressed: true, typeByte: 's'},
			}),
			wantPyInst:    true,
			wantVer:       "2.1+",
			wantPyVer:     "3.10",
			wantPyLib:     "libpython3.10.so",
			wantEntries:   1,
			wantMainCount: 1,
		},
		{
			name: "bootstrap scripts excluded from main",
			data: buildFakePyInstBinary(311, "libpython3.11.so", []tocEntrySpec{
				{name: "pyiboot01_bootstrap", data: []byte("boot"), compressed: false, typeByte: 's'},
				{name: "pyi_rth_pkgutil", data: []byte("hook"), compressed: false, typeByte: 's'},
				{name: "pyimod03_importers", data: []byte("imp"), compressed: false, typeByte: 's'},
				{name: "real_app", data: []byte("app"), compressed: false, typeByte: 's'},
			}),
			wantPyInst:    true,
			wantVer:       "2.1+",
			wantPyVer:     "3.11",
			wantEntries:   4,
			wantMainCount: 1, // only real_app
		},
		{
			name:       "non-PyInstaller binary",
			data:       bytes.Repeat([]byte{0xDE, 0xAD}, 100),
			wantPyInst: false,
		},
		{
			name:       "empty file",
			data:       []byte{},
			wantPyInst: false,
		},
		{
			name: "magic present but truncated cookie (less than 24 bytes after magic)",
			data: func() []byte {
				b := bytes.Repeat([]byte{0x00}, 50)
				// Place magic near end so there's not enough room for a cookie
				b = append(b, Magic...)
				b = append(b, 0x00, 0x00, 0x00) // only 3 bytes after magic, need 16+
				return b
			}(),
			wantPyInst: true, // magic IS found
			wantVer:    "",   // but cookie parse fails
			wantPyVer:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, "test.exe", tt.data)
			result, err := Analyze(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsPyInst != tt.wantPyInst {
				t.Errorf("IsPyInst = %v, want %v", result.IsPyInst, tt.wantPyInst)
			}
			if tt.wantVer != "" && result.InstallerVer != tt.wantVer {
				t.Errorf("InstallerVer = %q, want %q", result.InstallerVer, tt.wantVer)
			}
			if tt.wantPyVer != "" && result.PyVersion != tt.wantPyVer {
				t.Errorf("PyVersion = %q, want %q", result.PyVersion, tt.wantPyVer)
			}
			if tt.wantPyLib != "" && result.PyLibName != tt.wantPyLib {
				t.Errorf("PyLibName = %q, want %q", result.PyLibName, tt.wantPyLib)
			}
			if tt.wantEntries > 0 && result.EntryCount != tt.wantEntries {
				t.Errorf("EntryCount = %d, want %d", result.EntryCount, tt.wantEntries)
			}
			if tt.wantMainCount > 0 && len(result.MainScripts) != tt.wantMainCount {
				t.Errorf("MainScripts count = %d, want %d", len(result.MainScripts), tt.wantMainCount)
			}
		})
	}
}

func TestAnalyze_FileNotFound(t *testing.T) {
	_, err := Analyze("/nonexistent/path/file.exe")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestAnalyze_Cookie20(t *testing.T) {
	// Build a 2.0 format binary (no pylibname field).
	// We need to construct it manually since buildFakePyInstBinary uses 2.1+.
	stub := bytes.Repeat([]byte{0x00}, 64)

	entryData := []byte("print('hello')")
	tocEntry := buildTOCEntry("main", 0, uint32(len(entryData)), uint32(len(entryData)), false, 's')

	tocOff := int32(len(entryData))
	tocLen := int32(len(tocEntry))
	pkgLen := int32(len(entryData) + len(tocEntry) + Cookie20Size)

	cookie := buildCookie20(pkgLen, tocOff, tocLen, 37) // Python 3.7

	var overlay bytes.Buffer
	overlay.Write(entryData)
	overlay.Write(tocEntry)
	overlay.Write(cookie)

	var file bytes.Buffer
	file.Write(stub)
	file.Write(overlay.Bytes())

	path := writeTempFile(t, "test20.exe", file.Bytes())
	result, err := Analyze(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsPyInst {
		t.Error("expected IsPyInst=true for 2.0 binary")
	}
	if result.InstallerVer != "2.0" {
		t.Errorf("InstallerVer = %q, want %q", result.InstallerVer, "2.0")
	}
	if result.PyVersion != "3.7" {
		t.Errorf("PyVersion = %q, want %q", result.PyVersion, "3.7")
	}
	if result.EntryCount != 1 {
		t.Errorf("EntryCount = %d, want 1", result.EntryCount)
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name       string
		entries    []tocEntrySpec
		verbose    bool
		checkFiles []string // expected files in output dir
	}{
		{
			name: "extract uncompressed source",
			entries: []tocEntrySpec{
				{name: "main", data: []byte{0x55, 0x0d, 0x0d, 0x0a, 'h', 'e', 'l', 'l', 'o'}, compressed: false, typeByte: 's'},
			},
			checkFiles: []string{"main.pyc"},
		},
		{
			name: "extract compressed module",
			entries: []tocEntrySpec{
				{name: "mymod", data: bytes.Repeat([]byte("import sys\n"), 50), compressed: true, typeByte: 'm'},
			},
			checkFiles: []string{"mymod.pyc"},
		},
		{
			name: "extract PYZ entry",
			entries: []tocEntrySpec{
				{name: "PYZ-00", data: []byte("not-a-real-pyz-but-testing"), compressed: false, typeByte: 'z'},
			},
			checkFiles: []string{"PYZ-00.pyz"},
		},
		{
			name: "extract with verbose",
			entries: []tocEntrySpec{
				{name: "app", data: []byte("code"), compressed: false, typeByte: 's'},
			},
			verbose:    true,
			checkFiles: []string{"app.pyc"},
		},
		{
			name: "dependency entry (no extension added)",
			entries: []tocEntrySpec{
				{name: "libfoo.so", data: []byte{0x7f, 'E', 'L', 'F'}, compressed: false, typeByte: 'd'},
			},
			checkFiles: []string{"libfoo.so"},
		},
		{
			name: "package entry",
			entries: []tocEntrySpec{
				{name: "mypkg", data: []byte("pkg init"), compressed: false, typeByte: 'M'},
			},
			checkFiles: []string{"mypkg.pyc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildFakePyInstBinary(311, "libpython3.11.so", tt.entries)
			inputPath := writeTempFile(t, "test.exe", data)
			outputDir := filepath.Join(t.TempDir(), "out")

			result, err := Extract(inputPath, outputDir, tt.verbose)
			if err != nil {
				t.Fatalf("Extract() error: %v", err)
			}
			if !result.IsPyInst {
				t.Error("expected IsPyInst=true")
			}

			for _, expectedFile := range tt.checkFiles {
				p := filepath.Join(outputDir, expectedFile)
				if _, err := os.Stat(p); os.IsNotExist(err) {
					t.Errorf("expected file %q not found in output", expectedFile)
				}
			}

			// Check metadata file was written
			metaPath := filepath.Join(outputDir, "UNRAVEL_META.json")
			metaData, err := os.ReadFile(metaPath)
			if err != nil {
				t.Fatalf("expected UNRAVEL_META.json: %v", err)
			}
			var meta map[string]any
			if err := json.Unmarshal(metaData, &meta); err != nil {
				t.Errorf("UNRAVEL_META.json is not valid JSON: %v", err)
			}
		})
	}
}

func TestExtract_NotPyInstaller(t *testing.T) {
	path := writeTempFile(t, "notpyinst.exe", bytes.Repeat([]byte{0xDE, 0xAD}, 100))
	outputDir := filepath.Join(t.TempDir(), "out")
	_, err := Extract(path, outputDir, false)
	if err == nil {
		t.Error("expected error for non-PyInstaller binary")
	}
}

func TestExtract_FileNotFound(t *testing.T) {
	_, err := Extract("/nonexistent/path/file.exe", t.TempDir(), false)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestFindCookieInData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantIdx int
		wantErr bool
	}{
		{
			name:    "magic at start",
			data:    append(Magic, bytes.Repeat([]byte{0x00}, 50)...),
			wantIdx: 0,
		},
		{
			name:    "magic at offset 100",
			data:    append(bytes.Repeat([]byte{0x00}, 100), Magic...),
			wantIdx: 100,
		},
		{
			name: "multiple magic occurrences returns last",
			data: func() []byte {
				b := make([]byte, 0, 200)
				b = append(b, Magic...)
				b = append(b, bytes.Repeat([]byte{0x00}, 50)...)
				b = append(b, Magic...)
				return b
			}(),
			wantIdx: 8 + 50, // second occurrence
		},
		{
			name:    "no magic",
			data:    bytes.Repeat([]byte{0xFF}, 100),
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, err := findCookieInData(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if idx != tt.wantIdx {
				t.Errorf("index = %d, want %d", idx, tt.wantIdx)
			}
		})
	}
}

func TestDecodePyVer(t *testing.T) {
	tests := []struct {
		ver  int32
		want string
	}{
		{311, "3.11"},
		{310, "3.10"},
		{309, "3.9"},
		{308, "3.8"},
		{27, "2.7"},
		{37, "3.7"},
		{100, "1.0"},
		{0, "0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := decodePyVer(tt.ver)
			if got != tt.want {
				t.Errorf("decodePyVer(%d) = %q, want %q", tt.ver, got, tt.want)
			}
		})
	}
}

func TestTypeDescription(t *testing.T) {
	tests := []struct {
		flag string
		want string
	}{
		{"d", "dependency"},
		{"o", "runtime-option"},
		{"s", "source"},
		{"M", "package"},
		{"m", "module"},
		{"z", "PYZ"},
		{"Z", "PYZ"},
		{"b", "binary"},
		{"x", "data"},
		{"n", "namespace-pkg"},
		{"?", "data"}, // unknown
	}

	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			got := typeDescription(tt.flag)
			if got != tt.want {
				t.Errorf("typeDescription(%q) = %q, want %q", tt.flag, got, tt.want)
			}
		})
	}
}

func TestIsBootstrapScript(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"pyiboot01_bootstrap", true},
		{"pyi_rth_pkgutil", true},
		{"pyi_rth_inspect", true},
		{"pyimod03_importers", true},
		{"PYIBOOT01_BOOTSTRAP", true}, // case insensitive
		{"my_app", false},
		{"main", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBootstrapScript(tt.name)
			if got != tt.want {
				t.Errorf("isBootstrapScript(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"path/to/file", "path/to/file"}, // filepath.Clean keeps forward slashes on unix
		{"has\x00null", "hasnull"},
		{"../traversal", "_/traversal"},
		{"../../etc/passwd", "_/_/etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeName(tt.input)
			// Use filepath.Clean on expected too since behavior is OS-dependent
			expected := filepath.Clean(tt.want)
			if got != expected {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, expected)
			}
		})
	}
}

func TestFixPycHeader(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		pyver string
		check func(t *testing.T, result []byte)
	}{
		{
			name:  "header already present",
			data:  []byte{0x55, 0x0d, 0x0d, 0x0a, 'c', 'o', 'd', 'e'},
			pyver: "3.8",
			check: func(t *testing.T, result []byte) {
				// Should return original unchanged
				if len(result) != 8 {
					t.Errorf("expected length 8, got %d", len(result))
				}
			},
		},
		{
			name:  "header missing - adds Python 3.11 header",
			data:  []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			pyver: "3.11",
			check: func(t *testing.T, result []byte) {
				if len(result) != 16+5 {
					t.Errorf("expected length %d, got %d", 16+5, len(result))
				}
				// Check the magic header was prepended
				if result[2] != 0x0d || result[3] != 0x0a {
					t.Error("expected \\r\\n at bytes 2-3 of reconstructed header")
				}
			},
		},
		{
			name:  "short data (< 4 bytes)",
			data:  []byte{0x01, 0x02},
			pyver: "3.11",
			check: func(t *testing.T, result []byte) {
				// Should return data unchanged
				if len(result) != 2 {
					t.Errorf("expected length 2, got %d", len(result))
				}
			},
		},
		{
			name:  "empty data",
			data:  []byte{},
			pyver: "3.11",
			check: func(t *testing.T, result []byte) {
				if len(result) != 0 {
					t.Errorf("expected length 0, got %d", len(result))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fixPycHeader(tt.data, tt.pyver)
			tt.check(t, result)
		})
	}
}

func TestPycMagic(t *testing.T) {
	versions := []struct {
		pyver    string
		wantLen  int
		wantByte byte // first byte of magic
	}{
		{"3.13", 16, 0xf3},
		{"3.12", 16, 0xcb},
		{"3.11", 16, 0xa7},
		{"3.10", 16, 0x6f},
		{"3.9", 16, 0x61},
		{"3.8", 16, 0x55},
		{"3.7", 16, 0x42},
		{"3.6", 12, 0x33},
		{"3.5", 12, 0x17},
		{"3.4", 12, 0xee},
		{"unknown", 16, 0x55}, // defaults to 3.8
	}

	for _, tt := range versions {
		t.Run(tt.pyver, func(t *testing.T) {
			magic := pycMagic(tt.pyver)
			if len(magic) != tt.wantLen {
				t.Errorf("pycMagic(%q) length = %d, want %d", tt.pyver, len(magic), tt.wantLen)
			}
			if magic[0] != tt.wantByte {
				t.Errorf("pycMagic(%q)[0] = 0x%02x, want 0x%02x", tt.pyver, magic[0], tt.wantByte)
			}
			// All should have \r\n at bytes 2-3
			if magic[2] != 0x0d || magic[3] != 0x0a {
				t.Errorf("pycMagic(%q) missing \\r\\n at bytes 2-3", tt.pyver)
			}
		})
	}
}

func TestExtractEntry(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() ([]byte, int64, TOCEntry)
		wantNil bool
		wantLen int
	}{
		{
			name: "uncompressed entry",
			setup: func() ([]byte, int64, TOCEntry) {
				data := []byte("hello world this is test data")
				return data, 0, TOCEntry{
					Position:         0,
					CompressedSize:   uint32(len(data)),
					UncompressedSize: uint32(len(data)),
					IsCompressed:     false,
				}
			},
			wantLen: 29,
		},
		{
			name: "compressed entry",
			setup: func() ([]byte, int64, TOCEntry) {
				original := bytes.Repeat([]byte("compressible data\n"), 100)
				var buf bytes.Buffer
				w := zlib.NewWriter(&buf)
				_, _ = w.Write(original)
				_ = w.Close()
				compressed := buf.Bytes()
				data := compressed
				return data, 0, TOCEntry{
					Position:         0,
					CompressedSize:   uint32(len(compressed)),
					UncompressedSize: uint32(len(original)),
					IsCompressed:     true,
				}
			},
			wantLen: 1800, // 100 * 18
		},
		{
			name: "out of bounds entry",
			setup: func() ([]byte, int64, TOCEntry) {
				return []byte("short"), 0, TOCEntry{
					Position:         100, // way beyond data
					CompressedSize:   10,
					UncompressedSize: 10,
				}
			},
			wantNil: true,
		},
		{
			name: "zero size entry",
			setup: func() ([]byte, int64, TOCEntry) {
				return []byte("data"), 0, TOCEntry{
					Position:         0,
					CompressedSize:   0,
					UncompressedSize: 0,
				}
			},
			wantNil: true, // start == end
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, overlayPos, entry := tt.setup()
			result := extractEntry(data, overlayPos, entry)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %d bytes", len(result))
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if len(result) != tt.wantLen {
				t.Errorf("result length = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestMagicBytes(t *testing.T) {
	// Verify the magic constant matches the documented value
	expected := []byte{'M', 'E', 'I', 014, 013, 012, 013, 016}
	if !bytes.Equal(Magic, expected) {
		t.Errorf("Magic = %v, want %v", Magic, expected)
	}
	if len(Magic) != 8 {
		t.Errorf("Magic length = %d, want 8", len(Magic))
	}
}

func TestExtract_PathTraversal(t *testing.T) {
	// Ensure entries with path traversal are sanitized
	data := buildFakePyInstBinary(311, "libpython3.11.so", []tocEntrySpec{
		{name: "../escape", data: []byte("bad"), compressed: false, typeByte: 'd'},
	})
	inputPath := writeTempFile(t, "test.exe", data)
	outputDir := filepath.Join(t.TempDir(), "out")

	_, err := Extract(inputPath, outputDir, false)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	// Verify no file was written outside outputDir
	// The sanitized name replaces ".." with "_"
	escaped := filepath.Join(filepath.Dir(outputDir), "escape")
	if _, err := os.Stat(escaped); err == nil {
		t.Error("path traversal was not prevented — file escaped output directory")
	}
}

func TestWriteMetadata(t *testing.T) {
	dir := t.TempDir()
	result := &PyInstBinary{
		Name:         "test.exe",
		PyVersion:    "3.11",
		PyLibName:    "libpython3.11.so",
		InstallerVer: "2.1+",
		EntryCount:   5,
		MainScripts:  []string{"app", "helper"},
		OverlayPos:   1024,
		CookiePos:    2048,
	}

	writeMetadata(dir, result)

	metaPath := filepath.Join(dir, "UNRAVEL_META.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("failed to read metadata: %v", err)
	}

	var meta map[string]any
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("metadata is not valid JSON: %v", err)
	}

	if meta["python_version"] != "3.11" {
		t.Errorf("python_version = %v, want 3.11", meta["python_version"])
	}
	if meta["installer_version"] != "2.1+" {
		t.Errorf("installer_version = %v, want 2.1+", meta["installer_version"])
	}
	scripts, ok := meta["main_scripts"].([]any)
	if !ok || len(scripts) != 2 {
		t.Errorf("main_scripts count = %v, want 2", meta["main_scripts"])
	}
}
