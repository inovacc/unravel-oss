/*
Copyright (c) 2026 Security Research
*/
package advinstaller

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// buildMinimalPE builds a minimal valid PE (MZ header + PE signature + one section header).
// The returned bytes form a valid-enough PE for debug/pe.NewFile to parse.
func buildMinimalPE(overlay []byte) []byte {
	// DOS header: MZ magic + e_lfanew at offset 0x3C pointing to PE sig.
	dos := make([]byte, 128)
	dos[0] = 'M'
	dos[1] = 'Z'
	binary.LittleEndian.PutUint32(dos[0x3C:], 128) // e_lfanew = 128

	// PE signature "PE\0\0"
	peSig := []byte{'P', 'E', 0, 0}

	// COFF header (20 bytes)
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], 0x14C)   // Machine: i386
	binary.LittleEndian.PutUint16(coff[2:], 1)       // NumberOfSections: 1
	binary.LittleEndian.PutUint16(coff[16:], 96)     // SizeOfOptionalHeader: 96 (PE32 minimum)
	binary.LittleEndian.PutUint16(coff[18:], 0x0102) // Characteristics: EXECUTABLE_IMAGE

	// Optional header (PE32, 96 bytes minimum)
	opt := make([]byte, 96)
	binary.LittleEndian.PutUint16(opt[0:], 0x10B) // Magic: PE32
	binary.LittleEndian.PutUint32(opt[56:], 512)  // SectionAlignment
	binary.LittleEndian.PutUint32(opt[60:], 512)  // FileAlignment
	binary.LittleEndian.PutUint32(opt[80:], 16)   // NumberOfRvaAndSizes

	// Section header (40 bytes)
	sec := make([]byte, 40)
	copy(sec[0:8], ".text\x00\x00\x00")
	// Section raw data starts right after all headers; pad to 512 alignment.
	headerSize := len(dos) + len(peSig) + len(coff) + len(opt) + len(sec)
	sectionStart := ((headerSize / 512) + 1) * 512
	sectionDataSize := 512

	binary.LittleEndian.PutUint32(sec[8:], uint32(sectionDataSize))  // VirtualSize
	binary.LittleEndian.PutUint32(sec[12:], uint32(sectionStart))    // VirtualAddress
	binary.LittleEndian.PutUint32(sec[16:], uint32(sectionDataSize)) // SizeOfRawData
	binary.LittleEndian.PutUint32(sec[20:], uint32(sectionStart))    // PointerToRawData

	var buf bytes.Buffer
	buf.Write(dos)
	buf.Write(peSig)
	buf.Write(coff)
	buf.Write(opt)
	buf.Write(sec)

	// Pad to section start.
	for buf.Len() < sectionStart {
		buf.WriteByte(0)
	}

	// Write section data (NOP sled).
	for range sectionDataSize {
		buf.WriteByte(0x90)
	}

	// Write overlay.
	buf.Write(overlay)

	return buf.Bytes()
}

func writeTempFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write temp file %s: %v", path, err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Info tests
// ---------------------------------------------------------------------------

func TestInfo(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name           string
		data           []byte
		wantErr        bool
		wantIsAdvInst  bool
		wantMarkersCnt int
		wantMSI        bool
	}{
		{
			name:    "empty file",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "single byte",
			data:    []byte{0x00},
			wantErr: false,
		},
		{
			name:    "non-PE random bytes",
			data:    []byte("this is just a plain text file, not a PE"),
			wantErr: false,
		},
		{
			name:    "MZ header only, no markers",
			data:    append([]byte("MZ"), make([]byte, 200)...),
			wantErr: false,
		},
		{
			name: "MZ header with one Advanced Installer marker",
			data: func() []byte {
				d := make([]byte, 1024)
				d[0] = 'M'
				d[1] = 'Z'
				copy(d[100:], []byte("This binary uses Advanced Installer technology"))
				return d
			}(),
			wantErr:        false,
			wantIsAdvInst:  true,
			wantMarkersCnt: 1,
		},
		{
			name: "MZ header with multiple markers",
			data: func() []byte {
				d := make([]byte, 2048)
				d[0] = 'M'
				d[1] = 'Z'
				copy(d[100:], []byte("Advanced Installer"))
				copy(d[200:], []byte("Caphyon"))
				copy(d[300:], []byte("ai_bootstrapper"))
				copy(d[500:], []byte("AIDLG_"))
				return d
			}(),
			wantErr:        false,
			wantIsAdvInst:  true,
			wantMarkersCnt: 4,
		},
		{
			name: "MZ header with case-insensitive marker match",
			data: func() []byte {
				d := make([]byte, 512)
				d[0] = 'M'
				d[1] = 'Z'
				copy(d[100:], []byte("ADVANCED INSTALLER"))
				return d
			}(),
			wantErr:        false,
			wantIsAdvInst:  true,
			wantMarkersCnt: 1,
		},
		{
			name: "PE with embedded CFBF past 100KB",
			data: func() []byte {
				// MZ header + padding to 100KB + CFBF magic.
				d := make([]byte, 120*1024)
				d[0] = 'M'
				d[1] = 'Z'
				copy(d[100:], []byte("Advanced Installer"))
				copy(d[110*1024:], cfbfMagic)
				return d
			}(),
			wantErr:        false,
			wantIsAdvInst:  true,
			wantMarkersCnt: 1,
			wantMSI:        true,
		},
		{
			name: "PE with embedded CAB past 100KB (no CFBF)",
			data: func() []byte {
				d := make([]byte, 120*1024)
				d[0] = 'M'
				d[1] = 'Z'
				copy(d[110*1024:], cabMagic)
				return d
			}(),
			wantErr: false,
			wantMSI: true,
		},
		{
			name: "CFBF before 100KB threshold is ignored",
			data: func() []byte {
				d := make([]byte, 50*1024)
				d[0] = 'M'
				d[1] = 'Z'
				copy(d[1024:], cfbfMagic)
				return d
			}(),
			wantErr: false,
			wantMSI: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tmpDir, strings.ReplaceAll(tt.name, " ", "_")+".bin", tt.data)

			result, err := Info(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Path != path {
				t.Errorf("Path = %q, want %q", result.Path, path)
			}
			if result.Size != int64(len(tt.data)) {
				t.Errorf("Size = %d, want %d", result.Size, len(tt.data))
			}
			if result.IsAdvInstaller != tt.wantIsAdvInst {
				t.Errorf("IsAdvInstaller = %v, want %v", result.IsAdvInstaller, tt.wantIsAdvInst)
			}
			if len(result.Markers) != tt.wantMarkersCnt {
				t.Errorf("len(Markers) = %d, want %d; markers=%v", len(result.Markers), tt.wantMarkersCnt, result.Markers)
			}
			if result.HasEmbeddedMSI != tt.wantMSI {
				t.Errorf("HasEmbeddedMSI = %v, want %v", result.HasEmbeddedMSI, tt.wantMSI)
			}
		})
	}
}

func TestInfo_FileNotFound(t *testing.T) {
	_, err := Info("/nonexistent/path/to/file.exe")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// ---------------------------------------------------------------------------
// ExtractMSI tests
// ---------------------------------------------------------------------------

func TestExtractMSI(t *testing.T) {
	tests := []struct {
		name       string
		buildFile  func(t *testing.T, dir string) string
		wantErr    bool
		wantMethod string
		wantExt    string // expected output file extension
	}{
		{
			name: "non-PE file returns error",
			buildFile: func(t *testing.T, dir string) string {
				return writeTempFile(t, dir, "plain.txt", []byte("not a PE file at all"))
			},
			wantErr: true,
		},
		{
			name: "PE without embedded payload returns error",
			buildFile: func(t *testing.T, dir string) string {
				pe := buildMinimalPE(nil)
				return writeTempFile(t, dir, "clean.exe", pe)
			},
			wantErr: true,
		},
		{
			name: "PE with CFBF in overlay extracts via overlay method",
			buildFile: func(t *testing.T, dir string) string {
				// Build overlay: some padding + CFBF magic + fake MSI content.
				var overlay bytes.Buffer
				overlay.Write(make([]byte, 64)) // small gap
				overlay.Write(cfbfMagic)
				overlay.Write([]byte("FAKE-MSI-CONTENT-HERE"))
				pe := buildMinimalPE(overlay.Bytes())
				return writeTempFile(t, dir, "with_msi.exe", pe)
			},
			wantErr:    false,
			wantMethod: "overlay",
			wantExt:    ".msi",
		},
		{
			name: "PE with CAB in overlay extracts via cab method",
			buildFile: func(t *testing.T, dir string) string {
				// Build overlay large enough so that CAB magic lands past 100KB.
				// The minimal PE sections end around offset ~1024, so we need
				// ~100KB of padding in the overlay before the CAB magic.
				var overlay bytes.Buffer
				overlay.Write(make([]byte, 110*1024)) // push past 100KB threshold
				overlay.Write(cabMagic)
				overlay.Write([]byte("FAKE-CAB-CONTENT-HERE"))
				pe := buildMinimalPE(overlay.Bytes())
				return writeTempFile(t, dir, "with_cab.exe", pe)
			},
			wantErr:    false,
			wantMethod: "cab",
			wantExt:    ".cab",
		},
		{
			name: "large file with CFBF at 110KB extracts via resource method",
			buildFile: func(t *testing.T, dir string) string {
				// Build a file that is MZ but not a valid PE (so overlay method fails),
				// with CFBF magic at 110KB.
				d := make([]byte, 120*1024)
				d[0] = 'M'
				d[1] = 'Z'
				// Don't set valid PE headers, so peOverlayOffset will fail.
				// Place CFBF at 110KB.
				copy(d[110*1024:], cfbfMagic)
				copy(d[110*1024+len(cfbfMagic):], []byte("MSI-PAYLOAD"))
				return writeTempFile(t, dir, "resource_msi.exe", d)
			},
			wantErr:    false,
			wantMethod: "resource",
			wantExt:    ".msi",
		},
		{
			name: "large file with CAB at 110KB, no CFBF",
			buildFile: func(t *testing.T, dir string) string {
				d := make([]byte, 120*1024)
				d[0] = 'M'
				d[1] = 'Z'
				copy(d[110*1024:], cabMagic)
				copy(d[110*1024+len(cabMagic):], []byte("CAB-PAYLOAD"))
				return writeTempFile(t, dir, "cab_only.exe", d)
			},
			wantErr:    false,
			wantMethod: "cab",
			wantExt:    ".cab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcDir := t.TempDir()
			outDir := filepath.Join(t.TempDir(), "output")

			path := tt.buildFile(t, srcDir)

			result, err := ExtractMSI(path, outDir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if result != nil && result.Error == "" {
					t.Error("expected result.Error to be set on failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", result.Method, tt.wantMethod)
			}
			if result.MSIPath == "" {
				t.Fatal("MSIPath is empty")
			}
			if !strings.HasSuffix(result.MSIPath, tt.wantExt) {
				t.Errorf("MSIPath %q does not end with %q", result.MSIPath, tt.wantExt)
			}
			if result.MSISize <= 0 {
				t.Errorf("MSISize = %d, want > 0", result.MSISize)
			}
			// Verify the output file actually exists.
			if _, err := os.Stat(result.MSIPath); err != nil {
				t.Errorf("output file does not exist: %v", err)
			}
		})
	}
}

func TestExtractMSI_FileNotFound(t *testing.T) {
	_, err := ExtractMSI("/nonexistent/path/setup.exe", t.TempDir())
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestExtractMSI_InvalidOutputDir(t *testing.T) {
	// Build a valid PE with CFBF overlay so extraction proceeds to writePayload.
	var overlay bytes.Buffer
	overlay.Write(make([]byte, 64))
	overlay.Write(cfbfMagic)
	overlay.Write([]byte("MSI-DATA"))
	pe := buildMinimalPE(overlay.Bytes())

	srcDir := t.TempDir()
	path := writeTempFile(t, srcDir, "setup.exe", pe)

	// Use a path that cannot be created (file as parent directory).
	badOut := filepath.Join(path, "subdir") // path is a file, not a directory
	_, err := ExtractMSI(path, badOut)
	if err == nil {
		t.Fatal("expected error for invalid output directory")
	}
}

// ---------------------------------------------------------------------------
// findMagicOffset tests
// ---------------------------------------------------------------------------

func TestFindMagicOffset(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		magic     []byte
		minOffset int64
		wantOff   int64
		wantErr   bool
	}{
		{
			name:      "magic at exact minOffset",
			data:      append(make([]byte, 100), cfbfMagic...),
			magic:     cfbfMagic,
			minOffset: 100,
			wantOff:   100,
		},
		{
			name:      "magic past minOffset",
			data:      append(make([]byte, 200), cabMagic...),
			magic:     cabMagic,
			minOffset: 50,
			wantOff:   200,
		},
		{
			name:      "magic before minOffset not found",
			data:      append(cfbfMagic, make([]byte, 200)...),
			magic:     cfbfMagic,
			minOffset: 50,
			wantErr:   true,
		},
		{
			name:      "no magic in file",
			data:      make([]byte, 500),
			magic:     cfbfMagic,
			minOffset: 0,
			wantErr:   true,
		},
		{
			name:      "minOffset exceeds file size",
			data:      make([]byte, 50),
			magic:     cfbfMagic,
			minOffset: 100,
			wantErr:   true,
		},
		{
			name:      "empty file",
			data:      []byte{},
			magic:     cfbfMagic,
			minOffset: 0,
			wantErr:   true,
		},
	}

	tmpDir := t.TempDir()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tmpDir, strings.ReplaceAll(tt.name, " ", "_")+".bin", tt.data)

			off, err := findMagicOffset(path, tt.magic, tt.minOffset)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if off != tt.wantOff {
				t.Errorf("offset = %d, want %d", off, tt.wantOff)
			}
		})
	}
}

func TestFindMagicOffset_FileNotFound(t *testing.T) {
	_, err := findMagicOffset("/nonexistent/file.bin", cfbfMagic, 0)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// ---------------------------------------------------------------------------
// readHead tests
// ---------------------------------------------------------------------------

func TestReadHead(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		maxBytes int64
		wantLen  int
	}{
		{
			name:     "file smaller than maxBytes",
			data:     []byte("hello world"),
			maxBytes: 1024,
			wantLen:  11,
		},
		{
			name:     "file larger than maxBytes",
			data:     bytes.Repeat([]byte("A"), 5000),
			maxBytes: 1024,
			wantLen:  1024,
		},
		{
			name:     "empty file",
			data:     []byte{},
			maxBytes: 1024,
			wantLen:  0,
		},
		{
			name:     "exact size match",
			data:     []byte("12345"),
			maxBytes: 5,
			wantLen:  5,
		},
	}

	tmpDir := t.TempDir()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tmpDir, strings.ReplaceAll(tt.name, " ", "_")+".bin", tt.data)

			got, err := readHead(path, tt.maxBytes)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestReadHead_FileNotFound(t *testing.T) {
	_, err := readHead("/nonexistent/file.bin", 1024)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// ---------------------------------------------------------------------------
// peOverlayOffset tests
// ---------------------------------------------------------------------------

func TestPeOverlayOffset(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid PE returns positive offset",
			data:    buildMinimalPE(nil),
			wantErr: false,
		},
		{
			name:    "non-PE file returns error",
			data:    []byte("not a PE file"),
			wantErr: true,
		},
		{
			name:    "empty file returns error",
			data:    []byte{},
			wantErr: true,
		},
	}

	tmpDir := t.TempDir()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, tmpDir, strings.ReplaceAll(tt.name, " ", "_")+".bin", tt.data)

			off, err := peOverlayOffset(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if off <= 0 {
				t.Errorf("overlay offset = %d, want > 0", off)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// writePayload tests
// ---------------------------------------------------------------------------

func TestWritePayload(t *testing.T) {
	srcDir := t.TempDir()
	payload := []byte("THIS-IS-THE-PAYLOAD-DATA")
	prefix := bytes.Repeat([]byte{0}, 100)

	srcData := append(prefix, payload...)
	srcPath := writeTempFile(t, srcDir, "source.exe", srcData)

	tests := []struct {
		name     string
		offset   int64
		wantSize int64
		wantErr  bool
	}{
		{
			name:     "extract from offset 100",
			offset:   100,
			wantSize: int64(len(payload)),
		},
		{
			name:     "extract from offset 0 gets everything",
			offset:   0,
			wantSize: int64(len(srcData)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outDir := filepath.Join(t.TempDir(), "out")
			outPath, sz, err := writePayload(srcPath, tt.offset, outDir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sz != tt.wantSize {
				t.Errorf("written = %d, want %d", sz, tt.wantSize)
			}
			if !strings.HasSuffix(outPath, ".msi") {
				t.Errorf("output path %q should end with .msi", outPath)
			}
			// Verify content.
			content, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read output: %v", err)
			}
			if int64(len(content)) != tt.wantSize {
				t.Errorf("file size = %d, want %d", len(content), tt.wantSize)
			}
		})
	}
}

func TestWritePayload_SourceNotFound(t *testing.T) {
	outDir := t.TempDir()
	_, _, err := writePayload("/nonexistent/source.exe", 0, outDir)
	if err == nil {
		t.Fatal("expected error for nonexistent source")
	}
}

// ---------------------------------------------------------------------------
// BootstrapperInfo struct defaults
// ---------------------------------------------------------------------------

func TestBootstrapperInfo_Defaults(t *testing.T) {
	info := &BootstrapperInfo{}
	if info.IsAdvInstaller {
		t.Error("default IsAdvInstaller should be false")
	}
	if info.HasEmbeddedMSI {
		t.Error("default HasEmbeddedMSI should be false")
	}
	if len(info.Markers) != 0 {
		t.Error("default Markers should be empty")
	}
}

// ---------------------------------------------------------------------------
// ExtractResult struct defaults
// ---------------------------------------------------------------------------

func TestExtractResult_Defaults(t *testing.T) {
	result := &ExtractResult{}
	if result.Method != "" {
		t.Error("default Method should be empty")
	}
	if result.MSIPath != "" {
		t.Error("default MSIPath should be empty")
	}
}

// ---------------------------------------------------------------------------
// Magic byte constants sanity check
// ---------------------------------------------------------------------------

func TestMagicConstants(t *testing.T) {
	if len(cfbfMagic) != 8 {
		t.Errorf("cfbfMagic length = %d, want 8", len(cfbfMagic))
	}
	if len(cabMagic) != 4 {
		t.Errorf("cabMagic length = %d, want 4", len(cabMagic))
	}
	// CFBF starts with D0 CF
	if cfbfMagic[0] != 0xD0 || cfbfMagic[1] != 0xCF {
		t.Error("cfbfMagic should start with D0 CF")
	}
	// CAB starts with MSCF
	if string(cabMagic) != "MSCF" {
		t.Errorf("cabMagic = %q, want \"MSCF\"", string(cabMagic))
	}
}

// ---------------------------------------------------------------------------
// Marker list coverage
// ---------------------------------------------------------------------------

func TestAdvInstallerMarkers(t *testing.T) {
	if len(advInstallerMarkers) == 0 {
		t.Fatal("advInstallerMarkers should not be empty")
	}

	// Every marker should be found when embedded in an MZ file.
	for _, marker := range advInstallerMarkers {
		t.Run("marker_"+marker, func(t *testing.T) {
			d := make([]byte, 512)
			d[0] = 'M'
			d[1] = 'Z'
			copy(d[100:], []byte(marker))

			path := writeTempFile(t, t.TempDir(), "marker.bin", d)
			result, err := Info(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.IsAdvInstaller {
				t.Errorf("marker %q was not detected", marker)
			}
			found := slices.Contains(result.Markers, marker)
			if !found {
				t.Errorf("marker %q not in result.Markers: %v", marker, result.Markers)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Large file with magic spanning chunk boundary
// ---------------------------------------------------------------------------

func TestFindMagicOffset_ChunkBoundary(t *testing.T) {
	// Create a file slightly larger than 1MB (chunk size) to ensure
	// the overlap logic works when magic spans a chunk boundary.
	const chunkSize = 1024 * 1024
	// Place magic so it starts at chunkSize - 4 (spanning the boundary).
	dataSize := chunkSize + 1024
	data := make([]byte, dataSize)
	splitPos := chunkSize - 4
	copy(data[splitPos:], cfbfMagic)

	path := writeTempFile(t, t.TempDir(), "boundary.bin", data)

	off, err := findMagicOffset(path, cfbfMagic, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if off != int64(splitPos) {
		t.Errorf("offset = %d, want %d", off, splitPos)
	}
}
