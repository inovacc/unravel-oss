package bun

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildMinimalPE constructs a minimal PE binary with optional sections.
// Each section is described by name (8 bytes padded) and raw data.
func buildMinimalPE(sections []struct {
	name string
	data []byte
}) []byte {
	// DOS header (64 bytes minimum)
	dos := make([]byte, 0x40)
	dos[0] = 'M'
	dos[1] = 'Z'
	peOffset := uint32(0x40)
	binary.LittleEndian.PutUint32(dos[0x3C:0x40], peOffset)

	// PE signature (4 bytes) + COFF header (20 bytes) = 24 bytes
	peHdr := make([]byte, 24)
	copy(peHdr[0:4], "PE\x00\x00")
	binary.LittleEndian.PutUint16(peHdr[6:8], uint16(len(sections)))
	optHeaderSize := uint16(0)
	binary.LittleEndian.PutUint16(peHdr[20:22], optHeaderSize)

	sectionsStart := len(dos) + len(peHdr)

	// Calculate where raw data starts (after all section headers)
	sectionHeadersSize := len(sections) * 40
	dataStart := sectionsStart + sectionHeadersSize
	// Align to 512 for realism
	if dataStart%512 != 0 {
		dataStart = ((dataStart / 512) + 1) * 512
	}

	var sectionHeaders []byte
	var allData []byte
	currentDataOffset := dataStart

	for _, sec := range sections {
		hdr := make([]byte, 40)
		nameBytes := []byte(sec.name)
		if len(nameBytes) > 8 {
			nameBytes = nameBytes[:8]
		}
		copy(hdr[0:8], nameBytes)
		// VirtualSize
		binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(sec.data)))
		// VirtualAddress
		binary.LittleEndian.PutUint32(hdr[12:16], uint32(currentDataOffset))
		// SizeOfRawData
		binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(sec.data)))
		// PointerToRawData
		binary.LittleEndian.PutUint32(hdr[20:24], uint32(currentDataOffset))

		sectionHeaders = append(sectionHeaders, hdr...)
		allData = append(allData, sec.data...)
		currentDataOffset += len(sec.data)
	}

	// Assemble: DOS + PE header + section headers + padding + data
	result := make([]byte, 0, currentDataOffset)
	result = append(result, dos...)
	result = append(result, peHdr...)
	result = append(result, sectionHeaders...)

	// Pad to dataStart
	for len(result) < dataStart {
		result = append(result, 0)
	}
	result = append(result, allData...)

	return result
}

// buildBunSectionData constructs a valid .bun section payload with the
// data_length header, module graph data, offsets struct, and trailer.
func buildBunSectionData(files []struct {
	path     string
	contents string
	loader   byte
}, entryID uint32) []byte {
	// Build the module graph blob:
	// [string data: paths then contents]
	// [module metadata: N × 52 bytes]
	// [Offsets struct: 32 bytes]
	// [Trailer: 16 bytes]

	var stringData []byte
	type modInfo struct {
		nameOff, nameLen         uint32
		contentsOff, contentsLen uint32
		loader                   byte
	}
	var mods []modInfo

	for _, f := range files {
		nameOff := uint32(len(stringData))
		nameBytes := []byte(f.path)
		stringData = append(stringData, nameBytes...)
		nameLen := uint32(len(nameBytes))

		contentsOff := uint32(len(stringData))
		contentsBytes := []byte(f.contents)
		stringData = append(stringData, contentsBytes...)
		contentsLen := uint32(len(contentsBytes))

		mods = append(mods, modInfo{
			nameOff: nameOff, nameLen: nameLen,
			contentsOff: contentsOff, contentsLen: contentsLen,
			loader: f.loader,
		})
	}

	modulesPtrOffset := uint32(len(stringData))
	modulesPtrLength := uint32(len(mods) * moduleSize)

	// Build module entries (52 bytes each)
	var moduleEntries []byte
	for _, m := range mods {
		entry := make([]byte, moduleSize)
		binary.LittleEndian.PutUint32(entry[0:4], m.nameOff)
		binary.LittleEndian.PutUint32(entry[4:8], m.nameLen)
		binary.LittleEndian.PutUint32(entry[8:12], m.contentsOff)
		binary.LittleEndian.PutUint32(entry[12:16], m.contentsLen)
		// sourcemap: offset=0, len=0
		// bytecode: offset=0, len=0
		// module_info, bytecode_origin_path: zeros
		entry[49] = m.loader // loader byte
		moduleEntries = append(moduleEntries, entry...)
	}

	// Build Offsets struct (32 bytes)
	offsets := make([]byte, offsetsSize)
	// byteCount = total blob size (stringData + modules + offsets + trailer)
	totalBlobSize := uint64(len(stringData)) + uint64(len(moduleEntries)) + uint64(offsetsSize) + uint64(trailerSize)
	binary.LittleEndian.PutUint64(offsets[0:8], totalBlobSize)
	binary.LittleEndian.PutUint32(offsets[8:12], modulesPtrOffset)
	binary.LittleEndian.PutUint32(offsets[12:16], modulesPtrLength)
	binary.LittleEndian.PutUint32(offsets[16:20], entryID)

	// Assemble blob
	blob := make([]byte, 0, totalBlobSize)
	blob = append(blob, stringData...)
	blob = append(blob, moduleEntries...)
	blob = append(blob, offsets...)
	blob = append(blob, []byte(Trailer)...)

	// .bun section = [u64 LE data_length] + blob
	sectionData := make([]byte, sectionHdrSz+len(blob))
	binary.LittleEndian.PutUint64(sectionData[0:8], uint64(len(blob)))
	copy(sectionData[8:], blob)

	return sectionData
}

// writeTempFile writes data to a temporary file and returns its path.
func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}

// --- Tests ---

func TestIsBunBinary(t *testing.T) {
	// Build a valid PE with .bun section
	bunSection := buildBunSectionData([]struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "index.js", contents: "console.log('hello');", loader: LoaderJS},
	}, 0)

	peWithBun := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".text", data: make([]byte, 512)},
		{name: ".bun", data: bunSection},
	})

	peWithoutBun := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".text", data: make([]byte, 512)},
		{name: ".data", data: make([]byte, 256)},
	})

	// Non-PE binary with trailer near end
	nonPEWithTrailer := make([]byte, 1024)
	copy(nonPEWithTrailer[0:4], "\x7fELF") // ELF magic
	copy(nonPEWithTrailer[len(nonPEWithTrailer)-len(Trailer):], Trailer)

	// Tiny file (too small)
	tinyFile := []byte("hello")

	tests := []struct {
		name     string
		data     []byte
		fileName string
		want     bool
		wantErr  bool
	}{
		{
			name:     "PE with .bun section",
			data:     peWithBun,
			fileName: "app.exe",
			want:     true,
		},
		{
			name:     "PE without .bun section",
			data:     peWithoutBun,
			fileName: "plain.exe",
			want:     false,
		},
		{
			name:     "non-PE with trailer",
			data:     nonPEWithTrailer,
			fileName: "bunapp",
			want:     true,
		},
		{
			name:     "file too small",
			data:     tinyFile,
			fileName: "tiny",
			want:     false,
		},
		{
			name:     "empty file",
			data:     make([]byte, 600), // bigger than 512 but no magic
			fileName: "empty",
			want:     false,
		},
		{
			name:     "nonexistent file",
			data:     nil,
			fileName: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.data == nil {
				// Use a path that doesn't exist
				path = filepath.Join(t.TempDir(), "nonexistent.exe")
			} else {
				path = writeTempFile(t, tt.fileName, tt.data)
			}

			got, err := IsBunBinary(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("IsBunBinary() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name  string
		files []struct {
			path     string
			contents string
			loader   byte
		}
		entryID       uint32
		wantFileCount int
		wantEntry     string
		wantIsBun     bool
		wantErr       bool
	}{
		{
			name: "single JS file",
			files: []struct {
				path     string
				contents string
				loader   byte
			}{
				{path: "/$bunfs/root/index.js", contents: "console.log('hello');", loader: LoaderJS},
			},
			entryID:       0,
			wantFileCount: 1,
			wantEntry:     "/index.js",
			wantIsBun:     true,
		},
		{
			name: "multiple files with TS loader",
			files: []struct {
				path     string
				contents string
				loader   byte
			}{
				{path: "/$bunfs/root/main.ts", contents: "import { foo } from './foo';", loader: LoaderTS},
				{path: "/$bunfs/root/foo.ts", contents: "export const foo = 42;", loader: LoaderTS},
				{path: "/$bunfs/root/data.json", contents: `{"key":"value"}`, loader: LoaderJSON},
			},
			entryID:       0,
			wantFileCount: 3,
			wantEntry:     "/main.ts",
			wantIsBun:     true,
		},
		{
			name: "Windows BunFS root path",
			files: []struct {
				path     string
				contents string
				loader   byte
			}{
				{path: "B:/~BUN/root/app.tsx", contents: "const App = () => <div/>;", loader: LoaderTSX},
			},
			entryID:       0,
			wantFileCount: 1,
			wantEntry:     "app.tsx",
			wantIsBun:     true,
		},
		{
			name: "entrypoint is second file",
			files: []struct {
				path     string
				contents string
				loader   byte
			}{
				{path: "/$bunfs/root/util.js", contents: "module.exports = {};", loader: LoaderJS},
				{path: "/$bunfs/root/main.js", contents: "require('./util');", loader: LoaderJS},
			},
			entryID:       1,
			wantFileCount: 2,
			wantEntry:     "/main.js",
			wantIsBun:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bunSection := buildBunSectionData(tt.files, tt.entryID)
			peData := buildMinimalPE([]struct {
				name string
				data []byte
			}{
				{name: ".text", data: make([]byte, 256)},
				{name: ".bun", data: bunSection},
			})

			path := writeTempFile(t, "test.exe", peData)

			result, err := Analyze(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.IsBun != tt.wantIsBun {
				t.Errorf("IsBun = %v, want %v", result.IsBun, tt.wantIsBun)
			}
			if result.FileCount != tt.wantFileCount {
				t.Errorf("FileCount = %d, want %d", result.FileCount, tt.wantFileCount)
			}
			if result.Entrypoint != tt.wantEntry {
				t.Errorf("Entrypoint = %q, want %q", result.Entrypoint, tt.wantEntry)
			}
			if len(result.Files) != tt.wantFileCount {
				t.Errorf("len(Files) = %d, want %d", len(result.Files), tt.wantFileCount)
			}

			// Verify file contents match
			for i, f := range result.Files {
				if i >= len(tt.files) {
					break
				}
				wantContents := tt.files[i].contents
				if f.ContentsString() != wantContents {
					t.Errorf("Files[%d].Contents = %q, want %q", i, f.ContentsString(), wantContents)
				}
			}
		})
	}
}

func TestAnalyze_NonBunBinary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "plain text file",
			data: make([]byte, 1024),
		},
		{
			name: "PE without .bun section",
			data: buildMinimalPE([]struct {
				name string
				data []byte
			}{
				{name: ".text", data: make([]byte, 512)},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempFile(t, "test.exe", tt.data)
			result, err := Analyze(path)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsBun {
				t.Error("expected IsBun=false for non-bun binary")
			}
			if result.FileCount != 0 {
				t.Errorf("FileCount = %d, want 0", result.FileCount)
			}
		})
	}
}

func TestAnalyze_NonexistentFile(t *testing.T) {
	_, err := Analyze(filepath.Join(t.TempDir(), "nonexistent.bin"))
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestAnalyze_MalformedBunSection(t *testing.T) {
	tests := []struct {
		name        string
		sectionData []byte
		wantErr     bool
	}{
		{
			name: "section too small",
			sectionData: func() []byte {
				d := make([]byte, sectionHdrSz+10)
				binary.LittleEndian.PutUint64(d[0:8], 10)
				return d
			}(),
			wantErr: true, // raw bytes too small
		},
		{
			name: "data_length exceeds section",
			sectionData: func() []byte {
				d := make([]byte, sectionHdrSz+16)
				binary.LittleEndian.PutUint64(d[0:8], 9999)
				return d
			}(),
			wantErr: true,
		},
		{
			name: "trailer mismatch",
			sectionData: func() []byte {
				// Build a blob with correct size but wrong trailer
				blob := make([]byte, trailerSize+offsetsSize+10)
				// Put some offsets
				offs := blob[10 : 10+offsetsSize]
				binary.LittleEndian.PutUint64(offs[0:8], uint64(len(blob)))
				// Wrong trailer
				copy(blob[len(blob)-trailerSize:], "NOT A BUN TRAIL")

				d := make([]byte, sectionHdrSz+len(blob))
				binary.LittleEndian.PutUint64(d[0:8], uint64(len(blob)))
				copy(d[8:], blob)
				return d
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peData := buildMinimalPE([]struct {
				name string
				data []byte
			}{
				{name: ".bun", data: tt.sectionData},
			})

			path := writeTempFile(t, "malformed.exe", peData)
			_, err := Analyze(path)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestExtract(t *testing.T) {
	files := []struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "B:/~BUN/root/index.js", contents: "console.log('hi');", loader: LoaderJS},
		{path: "B:/~BUN/root/lib/util.js", contents: "module.exports = {};", loader: LoaderJS},
	}

	bunSection := buildBunSectionData(files, 0)
	peData := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".text", data: make([]byte, 256)},
		{name: ".bun", data: bunSection},
	})

	inputPath := writeTempFile(t, "app.exe", peData)
	outputDir := filepath.Join(t.TempDir(), "extracted")

	result, err := Extract(inputPath, outputDir, false)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if !result.IsBun {
		t.Error("expected IsBun=true")
	}
	if result.FileCount != 2 {
		t.Errorf("FileCount = %d, want 2", result.FileCount)
	}

	// Check extracted files exist
	indexPath := filepath.Join(outputDir, "index.js")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read extracted index.js: %v", err)
	}
	if string(data) != "console.log('hi');" {
		t.Errorf("index.js contents = %q, want %q", string(data), "console.log('hi');")
	}

	utilPath := filepath.Join(outputDir, "lib", "util.js")
	data, err = os.ReadFile(utilPath)
	if err != nil {
		t.Fatalf("read extracted lib/util.js: %v", err)
	}
	if string(data) != "module.exports = {};" {
		t.Errorf("lib/util.js contents = %q", string(data))
	}

	// Check metadata file
	metaPath := filepath.Join(outputDir, "UNRAVEL_META.json")
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Error("UNRAVEL_META.json not created")
	}
}

func TestExtract_NotBunBinary(t *testing.T) {
	path := writeTempFile(t, "plain.exe", make([]byte, 1024))
	outputDir := filepath.Join(t.TempDir(), "out")

	_, err := Extract(path, outputDir, false)
	if err == nil {
		t.Fatal("expected error for non-bun binary")
	}
	if !strings.Contains(err.Error(), "not a Bun standalone binary") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExtract_NonexistentInput(t *testing.T) {
	_, err := Extract(filepath.Join(t.TempDir(), "nope.exe"), t.TempDir(), false)
	if err == nil {
		t.Fatal("expected error for nonexistent input")
	}
}

func TestBundledFile_Contents(t *testing.T) {
	bf := BundledFile{
		Path:     "test.js",
		contents: []byte("var x = 1;"),
	}

	if string(bf.Contents()) != "var x = 1;" {
		t.Errorf("Contents() = %q", bf.Contents())
	}
	if bf.ContentsString() != "var x = 1;" {
		t.Errorf("ContentsString() = %q", bf.ContentsString())
	}
}

func TestBundledFile_EmptyContents(t *testing.T) {
	bf := BundledFile{Path: "empty.js"}
	if bf.Contents() != nil {
		t.Errorf("expected nil contents, got %v", bf.Contents())
	}
	if bf.ContentsString() != "" {
		t.Errorf("expected empty string, got %q", bf.ContentsString())
	}
}

func TestRemoveBunFSRoot(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/$bunfs/root/index.js", "/index.js"},
		{"B:/~BUN/root/app.ts", "app.ts"},
		{"B:\\~BUN\\root\\app.ts", "app.ts"},
		{"compiled://root/main.js", "/main.js"},
		{"/$bunfs/other.js", "other.js"},
		{"B:/~BUN/other.js", "other.js"},
		{"B:\\~BUN\\other.js", "other.js"},
		{"relative/path.js", "relative/path.js"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := removeBunFSRoot(tt.input)
			if got != tt.want {
				t.Errorf("removeBunFSRoot(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLoaderName(t *testing.T) {
	tests := []struct {
		loader byte
		want   string
	}{
		{LoaderJSX, "jsx"},
		{LoaderJS, "js"},
		{LoaderTSX, "tsx"},
		{LoaderTS, "ts"},
		{LoaderCSS, "css"},
		{LoaderFile, "file"},
		{LoaderJSON, "json"},
		{LoaderTOML, "toml"},
		{LoaderWASM, "wasm"},
		{LoaderText, "text"},
		{99, "unknown(99)"},
		{255, "unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := loaderName(tt.loader)
			if got != tt.want {
				t.Errorf("loaderName(%d) = %q, want %q", tt.loader, got, tt.want)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int
		want  string
	}{
		{0, "0 bytes"},
		{100, "100 bytes"},
		{1023, "1023 bytes"},
		{1024, "1.0 KB"},
		{2048, "2.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatSize(tt.bytes)
			if got != tt.want {
				t.Errorf("formatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantVersion string
		wantRev     string
	}{
		{
			name:        "no version marker",
			data:        []byte("just some random data with no version info"),
			wantVersion: "",
			wantRev:     "",
		},
		{
			name:        "new version format with revision",
			data:        append([]byte(VersionMatchNew), []byte("1.1.30 (abc123def)\x1b rest")...),
			wantVersion: "1.1.30",
			wantRev:     "abc123def",
		},
		{
			name:        "new version format without revision",
			data:        append([]byte(VersionMatchNew), []byte("1.2.0\x1b rest")...),
			wantVersion: "1.2.0",
			wantRev:     "",
		},
		{
			name:        "old version format",
			data:        append([]byte(VersionMatchOld), []byte("0.8.1: rest")...),
			wantVersion: "0.8.1",
			wantRev:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, rev := extractVersion(tt.data)
			if ver != tt.wantVersion {
				t.Errorf("version = %q, want %q", ver, tt.wantVersion)
			}
			if rev != tt.wantRev {
				t.Errorf("revision = %q, want %q", rev, tt.wantRev)
			}
		})
	}
}

func TestAnalyze_TrailerBased(t *testing.T) {
	// Build a non-PE binary that uses trailer-based detection
	files := []struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "/$bunfs/root/app.js", contents: "console.log('trailer');", loader: LoaderJS},
	}

	// Build just the blob (no PE section wrapper)
	var stringData []byte
	type modEntry struct {
		nameOff, nameLen, contentsOff, contentsLen uint32
		loader                                     byte
	}
	var mods []modEntry

	for _, f := range files {
		nOff := uint32(len(stringData))
		nb := []byte(f.path)
		stringData = append(stringData, nb...)
		nLen := uint32(len(nb))

		cOff := uint32(len(stringData))
		cb := []byte(f.contents)
		stringData = append(stringData, cb...)
		cLen := uint32(len(cb))

		mods = append(mods, modEntry{nameOff: nOff, nameLen: nLen, contentsOff: cOff, contentsLen: cLen, loader: f.loader})
	}

	modulesPtrOffset := uint32(len(stringData))
	modulesPtrLength := uint32(len(mods) * moduleSize)

	var moduleEntries []byte
	for _, m := range mods {
		entry := make([]byte, moduleSize)
		binary.LittleEndian.PutUint32(entry[0:4], m.nameOff)
		binary.LittleEndian.PutUint32(entry[4:8], m.nameLen)
		binary.LittleEndian.PutUint32(entry[8:12], m.contentsOff)
		binary.LittleEndian.PutUint32(entry[12:16], m.contentsLen)
		entry[49] = m.loader
		moduleEntries = append(moduleEntries, entry...)
	}

	offsets := make([]byte, offsetsSize)
	// byteCount for trailer-based extraction: the code does
	// data[rawEnd - byteCount - trailerSize : rawEnd]
	// so byteCount = blobSize - trailerSize (the non-trailer portion)
	blobContentSize := uint64(len(stringData)) + uint64(len(moduleEntries)) + uint64(offsetsSize)
	binary.LittleEndian.PutUint64(offsets[0:8], blobContentSize)
	binary.LittleEndian.PutUint32(offsets[8:12], modulesPtrOffset)
	binary.LittleEndian.PutUint32(offsets[12:16], modulesPtrLength)
	binary.LittleEndian.PutUint32(offsets[16:20], 0) // entryID

	blob := make([]byte, 0, blobContentSize+uint64(trailerSize))
	blob = append(blob, stringData...)
	blob = append(blob, moduleEntries...)
	blob = append(blob, offsets...)
	blob = append(blob, []byte(Trailer)...)

	// Prepend some padding (simulate ELF or other binary data)
	prefix := make([]byte, 2048)
	data := append(prefix, blob...)

	path := writeTempFile(t, "bunapp", data)
	result, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	if !result.IsBun {
		t.Error("expected IsBun=true for trailer-based binary")
	}
	if result.FileCount != 1 {
		t.Errorf("FileCount = %d, want 1", result.FileCount)
	}
	if result.Entrypoint != "/app.js" {
		t.Errorf("Entrypoint = %q, want %q", result.Entrypoint, "/app.js")
	}
}

func TestAnalyze_InvalidModulesLength(t *testing.T) {
	// Build a .bun section where modules_ptr length is not divisible by moduleSize
	blob := make([]byte, 100+offsetsSize+trailerSize)
	offs := blob[100 : 100+offsetsSize]
	binary.LittleEndian.PutUint64(offs[0:8], uint64(len(blob)))
	binary.LittleEndian.PutUint32(offs[8:12], 0)   // offset
	binary.LittleEndian.PutUint32(offs[12:16], 13) // length not divisible by 52
	copy(blob[100+offsetsSize:], Trailer)

	sectionData := make([]byte, sectionHdrSz+len(blob))
	binary.LittleEndian.PutUint64(sectionData[0:8], uint64(len(blob)))
	copy(sectionData[8:], blob)

	peData := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".bun", data: sectionData},
	})

	path := writeTempFile(t, "bad_modules.exe", peData)
	_, err := Analyze(path)
	if err == nil {
		t.Fatal("expected error for invalid modules_ptr length")
	}
	if !strings.Contains(err.Error(), "not divisible") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHasBunPESection(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		want   bool
	}{
		{
			name:   "too small",
			header: []byte{0, 1, 2},
			want:   false,
		},
		{
			name:   "not MZ",
			header: make([]byte, 4096),
			want:   false,
		},
		{
			name: "PE with .bun",
			header: func() []byte {
				pe := buildMinimalPE([]struct {
					name string
					data []byte
				}{
					{name: ".bun", data: make([]byte, 64)},
				})
				if len(pe) > 4096 {
					return pe[:4096]
				}
				return pe
			}(),
			want: true,
		},
		{
			name: "PE without .bun",
			header: func() []byte {
				pe := buildMinimalPE([]struct {
					name string
					data []byte
				}{
					{name: ".text", data: make([]byte, 64)},
				})
				if len(pe) > 4096 {
					return pe[:4096]
				}
				return pe
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasBunPESection(tt.header)
			if got != tt.want {
				t.Errorf("hasBunPESection() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtract_VerboseMode(t *testing.T) {
	files := []struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "B:/~BUN/root/main.js", contents: "// entry", loader: LoaderJS},
	}

	bunSection := buildBunSectionData(files, 0)
	peData := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".bun", data: bunSection},
	})

	inputPath := writeTempFile(t, "verbose.exe", peData)
	outputDir := filepath.Join(t.TempDir(), "verbose_out")

	// Verbose=true should not cause errors (just prints to stdout)
	result, err := Extract(inputPath, outputDir, true)
	if err != nil {
		t.Fatalf("Extract() with verbose: %v", err)
	}
	if result.FileCount != 1 {
		t.Errorf("FileCount = %d, want 1", result.FileCount)
	}
}

func TestExtract_EmptyContentsSkipped(t *testing.T) {
	// Build a module with empty contents - should be skipped during extraction
	files := []struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "B:/~BUN/root/empty.js", contents: "", loader: LoaderJS},
		{path: "B:/~BUN/root/real.js", contents: "// real", loader: LoaderJS},
	}

	bunSection := buildBunSectionData(files, 1)
	peData := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".bun", data: bunSection},
	})

	inputPath := writeTempFile(t, "empty_contents.exe", peData)
	outputDir := filepath.Join(t.TempDir(), "out")

	result, err := Extract(inputPath, outputDir, false)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	// empty.js should NOT be written
	emptyPath := filepath.Join(outputDir, "empty.js")
	if _, err := os.Stat(emptyPath); !os.IsNotExist(err) {
		t.Error("expected empty.js to be skipped (empty contents)")
	}

	// real.js should be written
	realPath := filepath.Join(outputDir, "real.js")
	if _, err := os.Stat(realPath); os.IsNotExist(err) {
		t.Error("expected real.js to be written")
	}

	if result.FileCount != 2 {
		t.Errorf("FileCount = %d, want 2", result.FileCount)
	}
}

func TestAnalyze_ModuleLoaders(t *testing.T) {
	files := []struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "/$bunfs/root/a.jsx", contents: "jsx", loader: LoaderJSX},
		{path: "/$bunfs/root/b.css", contents: "css", loader: LoaderCSS},
		{path: "/$bunfs/root/c.json", contents: "{}", loader: LoaderJSON},
		{path: "/$bunfs/root/d.toml", contents: "toml", loader: LoaderTOML},
		{path: "/$bunfs/root/e.wasm", contents: "wasm", loader: LoaderWASM},
		{path: "/$bunfs/root/f.txt", contents: "txt", loader: LoaderText},
	}

	bunSection := buildBunSectionData(files, 0)
	peData := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".bun", data: bunSection},
	})

	path := writeTempFile(t, "loaders.exe", peData)
	result, err := Analyze(path)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}

	expectedLoaders := []string{"jsx", "css", "json", "toml", "wasm", "text"}
	for i, want := range expectedLoaders {
		if i >= len(result.Files) {
			t.Fatalf("not enough files: got %d, want at least %d", len(result.Files), i+1)
		}
		if result.Files[i].Loader != want {
			t.Errorf("Files[%d].Loader = %q, want %q", i, result.Files[i].Loader, want)
		}
	}
}
