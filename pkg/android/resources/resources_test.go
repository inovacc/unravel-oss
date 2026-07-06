/* Copyright (c) 2026 Security Research */

package resources

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestCategorizeAsset(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected AssetCategory
	}{
		{"database db", "assets/data.db", AssetDatabase},
		{"database sqlite", "assets/data.sqlite", AssetDatabase},
		{"database sqlite3", "assets/data.sqlite3", AssetDatabase},
		{"config json", "assets/config.json", AssetConfig},
		{"config xml", "assets/config.xml", AssetConfig},
		{"config yaml", "assets/config.yaml", AssetConfig},
		{"config yml", "assets/config.yml", AssetConfig},
		{"config properties", "assets/app.properties", AssetConfig},
		{"config toml", "assets/app.toml", AssetConfig},
		{"config ini", "assets/app.ini", AssetConfig},
		{"certificate pem", "assets/cert.pem", AssetCertificate},
		{"certificate der", "assets/cert.der", AssetCertificate},
		{"certificate p12", "assets/cert.p12", AssetCertificate},
		{"certificate bks", "assets/cert.bks", AssetCertificate},
		{"native so", "assets/libfoo.so", AssetNative},
		{"media png", "assets/image.png", AssetMedia},
		{"media jpg", "assets/photo.jpg", AssetMedia},
		{"media mp3", "assets/sound.mp3", AssetMedia},
		{"media mp4", "assets/video.mp4", AssetMedia},
		{"media svg", "assets/icon.svg", AssetMedia},
		{"font ttf", "assets/font.ttf", AssetFont},
		{"font otf", "assets/font.otf", AssetFont},
		{"font woff", "assets/font.woff", AssetFont},
		{"unknown html", "assets/index.html", AssetData},
		{"unknown js", "assets/app.js", AssetData},
		{"unknown ext", "assets/unknown.xyz", AssetData},
		{"no extension", "assets/README", AssetData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := categorizeAsset(tt.path)
			if got != tt.expected {
				t.Errorf("categorizeAsset(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestShouldCheckSQLite(t *testing.T) {
	tests := []struct {
		name string
		ext  string
		want bool
	}{
		{"empty extension", "", true},
		{"dat extension", ".dat", true},
		{"bin extension", ".bin", true},
		{"png extension", ".png", false},
		{"txt extension", ".txt", false},
		{"db extension", ".db", false},
		{"sqlite extension", ".sqlite", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldCheckSQLite(tt.ext)
			if got != tt.want {
				t.Errorf("shouldCheckSQLite(%q) = %v, want %v", tt.ext, got, tt.want)
			}
		})
	}
}

func TestReadUTF8String(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name: "simple string",
			// charLen=5 (1 byte), byteLen=5 (1 byte), "Hello"
			data: []byte{5, 5, 'H', 'e', 'l', 'l', 'o', 0},
			want: "Hello",
		},
		{
			name: "empty string",
			// charLen=0, byteLen=0
			data: []byte{0, 0, 0},
			want: "",
		},
		{
			name:    "too short",
			data:    []byte{0x80},
			wantErr: true,
		},
		{
			name:    "nil data",
			data:    nil,
			wantErr: true,
		},
		{
			name: "two-byte char length",
			// charLen uses high bit: 0x80|0=0x80, 0x05 → 5 chars; byteLen=5; "World"
			data: []byte{0x80, 0x05, 5, 'W', 'o', 'r', 'l', 'd', 0},
			want: "World",
		},
		{
			name: "two-byte byte length",
			// charLen=3 (1 byte); byteLen uses high bit: 0x80|0=0x80, 0x03 → 3 bytes; "abc"
			data: []byte{3, 0x80, 0x03, 'a', 'b', 'c', 0},
			want: "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readUTF8String(tt.data)
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
				t.Errorf("readUTF8String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadUTF16String(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name: "simple ASCII via UTF-16",
			// charCount=2 (LE), then 'H'=0x0048, 'i'=0x0069
			data: func() []byte {
				buf := new(bytes.Buffer)
				binary.Write(buf, binary.LittleEndian, uint16(2))
				binary.Write(buf, binary.LittleEndian, uint16('H'))
				binary.Write(buf, binary.LittleEndian, uint16('i'))
				return buf.Bytes()
			}(),
			want: "Hi",
		},
		{
			name: "empty string zero count",
			data: []byte{0x00, 0x00},
			want: "",
		},
		{
			name:    "too short",
			data:    []byte{0x01},
			wantErr: true,
		},
		{
			name: "insufficient char data",
			// charCount=5 but only 1 char of data
			data:    []byte{0x05, 0x00, 0x41, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readUTF16String(tt.data)
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
				t.Errorf("readUTF16String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "Hello",
			data: func() []byte {
				s := "Hello"
				buf := make([]byte, len(s)*2+2) // +2 for null terminator
				for i, c := range s {
					binary.LittleEndian.PutUint16(buf[i*2:], uint16(c))
				}
				// null terminator already zero
				return buf
			}(),
			want: "Hello",
		},
		{
			name: "empty data",
			data: []byte{},
			want: "",
		},
		{
			name: "single byte ignored",
			data: []byte{0x41},
			want: "",
		},
		{
			name: "null terminated immediately",
			data: []byte{0x00, 0x00},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeUTF16LE(tt.data)
			if got != tt.want {
				t.Errorf("decodeUTF16LE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseARSC_TooSmall(t *testing.T) {
	r := &bytesReaderAt{data: []byte{0x01, 0x02, 0x03}}
	_, _, _, err := ParseARSC(r, 3)
	if err == nil {
		t.Error("expected error for data smaller than 12 bytes")
	}
}

func TestParseARSC_ValidHeader(t *testing.T) {
	// Build a minimal valid ARSC: resTableType header + string pool
	buf := new(bytes.Buffer)

	// Resource table header: type=0x0002, headerSize=12, totalSize (filled later)
	binary.Write(buf, binary.LittleEndian, uint16(resTableType))
	binary.Write(buf, binary.LittleEndian, uint16(12)) // headerSize
	binary.Write(buf, binary.LittleEndian, uint32(0))  // totalSize placeholder
	binary.Write(buf, binary.LittleEndian, uint32(0))  // packageCount

	// String pool chunk: type=0x0001, headerSize=28, chunkSize, stringCount=0, styleCount=0, flags=0, stringsStart=28, stylesStart=0
	poolStart := buf.Len()
	binary.Write(buf, binary.LittleEndian, uint16(stringPoolType))
	binary.Write(buf, binary.LittleEndian, uint16(28)) // headerSize
	binary.Write(buf, binary.LittleEndian, uint32(28)) // chunkSize (just the header, no strings)
	binary.Write(buf, binary.LittleEndian, uint32(0))  // stringCount
	binary.Write(buf, binary.LittleEndian, uint32(0))  // styleCount
	binary.Write(buf, binary.LittleEndian, uint32(0))  // flags
	binary.Write(buf, binary.LittleEndian, uint32(28)) // stringsStart
	binary.Write(buf, binary.LittleEndian, uint32(0))  // stylesStart
	_ = poolStart

	data := buf.Bytes()
	// Patch totalSize
	binary.LittleEndian.PutUint32(data[4:], uint32(len(data)))

	r := &bytesReaderAt{data: data}
	stringPool, _, _, err := ParseARSC(r, int64(len(data)))
	if err != nil {
		t.Fatalf("ParseARSC: %v", err)
	}

	if stringPool == nil {
		t.Fatal("expected non-nil string pool")
	}

	if stringPool.TotalStrings != 0 {
		t.Errorf("expected 0 strings, got %d", stringPool.TotalStrings)
	}
}

func TestParseARSC_WrongType(t *testing.T) {
	data := createInvalidARSC()
	r := &bytesReaderAt{data: data}
	_, _, _, err := ParseARSC(r, int64(len(data)))
	if err == nil {
		t.Error("expected error for wrong resource table type")
	}
}

func TestScanAPK_Nonexistent(t *testing.T) {
	_, err := ScanAPK("/nonexistent/path/app.apk")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseARSC_TruncatedAfterHeader(t *testing.T) {
	// Valid resTable header but truncated right after (no string pool)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(resTableType))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	binary.Write(buf, binary.LittleEndian, uint32(20))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	data := buf.Bytes()
	r := &bytesReaderAt{data: data}
	_, _, _, err := ParseARSC(r, int64(len(data)))
	if err == nil {
		t.Error("expected error for truncated ARSC after header")
	}
}

func TestParseARSC_WrongStringPoolType(t *testing.T) {
	// Valid resTable header, but next chunk is not a string pool
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(resTableType))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	binary.Write(buf, binary.LittleEndian, uint32(24))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// Wrong chunk type
	binary.Write(buf, binary.LittleEndian, uint16(0x0200))
	binary.Write(buf, binary.LittleEndian, uint16(8))
	binary.Write(buf, binary.LittleEndian, uint32(8))

	data := buf.Bytes()
	r := &bytesReaderAt{data: data}
	_, _, _, err := ParseARSC(r, int64(len(data)))
	if err == nil {
		t.Error("expected error for wrong string pool type")
	}
}

func TestBytesReaderAt(t *testing.T) {
	data := []byte("hello world")
	r := &bytesReaderAt{data: data}

	// Normal read
	buf := make([]byte, 5)
	n, err := r.ReadAt(buf, 0)
	if n != 5 || err != nil {
		t.Errorf("ReadAt(0): n=%d, err=%v", n, err)
	}
	if string(buf) != "hello" {
		t.Errorf("got %q, want %q", buf, "hello")
	}

	// Read past end
	buf2 := make([]byte, 5)
	n, err = r.ReadAt(buf2, 8)
	if n != 3 {
		t.Errorf("ReadAt(8): n=%d, want 3", n)
	}

	// Negative offset
	_, err = r.ReadAt(buf, -1)
	if err == nil {
		t.Error("expected error for negative offset")
	}

	// Offset past data
	_, err = r.ReadAt(buf, 100)
	if err == nil {
		t.Error("expected error for offset past data")
	}
}

func createTestAPK(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(content)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return apkPath
}

func buildMinimalARSC() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(resTableType))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	binary.Write(buf, binary.LittleEndian, uint32(0)) // placeholder
	binary.Write(buf, binary.LittleEndian, uint32(0)) // packageCount
	binary.Write(buf, binary.LittleEndian, uint16(stringPoolType))
	binary.Write(buf, binary.LittleEndian, uint16(28))
	binary.Write(buf, binary.LittleEndian, uint32(28))
	binary.Write(buf, binary.LittleEndian, uint32(0))  // stringCount
	binary.Write(buf, binary.LittleEndian, uint32(0))  // styleCount
	binary.Write(buf, binary.LittleEndian, uint32(0))  // flags
	binary.Write(buf, binary.LittleEndian, uint32(28)) // stringsStart
	binary.Write(buf, binary.LittleEndian, uint32(0))  // stylesStart
	data := buf.Bytes()
	binary.LittleEndian.PutUint32(data[4:], uint32(len(data)))
	return data
}

func TestScanAssets_WithFiles(t *testing.T) {
	apkPath := createTestAPK(t, map[string][]byte{
		"assets/index.html":    []byte("<html></html>"),
		"assets/app.js":        []byte(`console.log("hi")`),
		"assets/style.css":     []byte("body{}"),
		"assets/data.db":       []byte("some data"),
		"assets/image.png":     []byte("PNG data"),
		"META-INF/MANIFEST.MF": []byte("manifest"),
	})

	assets, err := ScanAssets(apkPath)
	if err != nil {
		t.Fatalf("ScanAssets: %v", err)
	}

	if len(assets) != 5 {
		t.Fatalf("expected 5 assets, got %d", len(assets))
	}

	found := make(map[string]AssetInfo)
	for _, a := range assets {
		found[a.Path] = a
	}

	// WebView assets
	for _, name := range []string{"assets/index.html", "assets/app.js", "assets/style.css"} {
		a, ok := found[name]
		if !ok {
			t.Errorf("missing asset %s", name)
			continue
		}
		if !a.IsWebView {
			t.Errorf("%s: expected IsWebView=true", name)
		}
		if a.Category != AssetWebView {
			t.Errorf("%s: expected category %s, got %s", name, AssetWebView, a.Category)
		}
	}

	// Database
	if a, ok := found["assets/data.db"]; !ok {
		t.Error("missing assets/data.db")
	} else if a.Category != AssetDatabase {
		t.Errorf("data.db: expected category %s, got %s", AssetDatabase, a.Category)
	}

	// Media
	if a, ok := found["assets/image.png"]; !ok {
		t.Error("missing assets/image.png")
	} else if a.Category != AssetMedia {
		t.Errorf("image.png: expected category %s, got %s", AssetMedia, a.Category)
	}
}

func TestScanAssets_SQLiteDetection(t *testing.T) {
	content := append([]byte("SQLite format 3\x00"), make([]byte, 100)...)
	apkPath := createTestAPK(t, map[string][]byte{
		"assets/hidden.dat": content,
	})

	assets, err := ScanAssets(apkPath)
	if err != nil {
		t.Fatalf("ScanAssets: %v", err)
	}

	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}

	if !assets[0].IsSQLite {
		t.Error("expected IsSQLite=true")
	}
	if assets[0].Category != AssetDatabase {
		t.Errorf("expected category %s, got %s", AssetDatabase, assets[0].Category)
	}
}

func TestScanAssets_NoAssets(t *testing.T) {
	apkPath := createTestAPK(t, map[string][]byte{
		"classes.dex": {},
	})

	assets, err := ScanAssets(apkPath)
	if err != nil {
		t.Fatalf("ScanAssets: %v", err)
	}

	if len(assets) != 0 {
		t.Errorf("expected 0 assets, got %d", len(assets))
	}
}

func TestScanAssets_Nonexistent(t *testing.T) {
	_, err := ScanAssets("/nonexistent/app.apk")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestScanAPK_WithResources(t *testing.T) {
	apkPath := createTestAPK(t, map[string][]byte{
		"assets/config.json": []byte(`{"key": "value"}`),
		"resources.arsc":     buildMinimalARSC(),
	})

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.StringPool == nil {
		t.Error("expected non-nil StringPool")
	}
	if result.TotalAssets != 1 {
		t.Errorf("expected TotalAssets=1, got %d", result.TotalAssets)
	}
	if result.Categories[AssetConfig] != 1 {
		t.Errorf("expected Categories[AssetConfig]=1, got %d", result.Categories[AssetConfig])
	}
}

func TestScanAPK_NoResources(t *testing.T) {
	apkPath := createTestAPK(t, map[string][]byte{
		"assets/font.ttf": []byte("font data"),
	})

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.StringPool != nil {
		t.Error("expected nil StringPool")
	}
	if result.TotalAssets != 1 {
		t.Errorf("expected TotalAssets=1, got %d", result.TotalAssets)
	}
	if result.Categories[AssetFont] != 1 {
		t.Errorf("expected Categories[AssetFont]=1, got %d", result.Categories[AssetFont])
	}
}

func TestScanAPK_WebViewDetection(t *testing.T) {
	apkPath := createTestAPK(t, map[string][]byte{
		"assets/index.html": []byte("<html></html>"),
		"assets/app.js":     []byte("console.log()"),
	})

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if !result.HasWebView {
		t.Error("expected HasWebView=true")
	}
}

func TestScanAPK_DatabaseDetection(t *testing.T) {
	content := append([]byte("SQLite format 3\x00"), make([]byte, 100)...)
	apkPath := createTestAPK(t, map[string][]byte{
		"assets/data.db": content,
	})

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if !result.HasDatabases {
		t.Error("expected HasDatabases=true")
	}
}

func createInvalidARSC() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x9999))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	binary.Write(buf, binary.LittleEndian, uint32(12))
	return buf.Bytes()
}

// buildARSCWithPackage builds a minimal but valid ARSC that includes a package chunk
// so that parsePackageChunk is exercised.
func buildARSCWithPackage(packageName string) []byte {
	// Helper: encode a UTF-16LE package name into exactly 256 bytes.
	encodePackageName := func(name string) []byte {
		out := make([]byte, 256)
		for i, r := range name {
			if i*2+1 >= 256 {
				break
			}
			binary.LittleEndian.PutUint16(out[i*2:], uint16(r))
		}
		return out
	}

	// Build the global string pool (empty, UTF-8).
	buildEmptyStringPool := func() []byte {
		b := new(bytes.Buffer)
		binary.Write(b, binary.LittleEndian, uint16(stringPoolType))
		binary.Write(b, binary.LittleEndian, uint16(28))                 // headerSize
		binary.Write(b, binary.LittleEndian, uint32(28))                 // chunkSize
		binary.Write(b, binary.LittleEndian, uint32(0))                  // stringCount
		binary.Write(b, binary.LittleEndian, uint32(0))                  // styleCount
		binary.Write(b, binary.LittleEndian, uint32(stringPoolUTF8Flag)) // flags = UTF-8
		binary.Write(b, binary.LittleEndian, uint32(28))                 // stringsStart
		binary.Write(b, binary.LittleEndian, uint32(0))                  // stylesStart
		return b.Bytes()
	}

	// Build the package chunk: minimum 288 bytes.
	// Layout: type(2) + headerSize(2) + chunkSize(4) + packageId(4) + name(256) + ...
	// We set headerSize=288 and include an empty type string pool after the header.
	buildPackageChunk := func() []byte {
		typePool := buildEmptyStringPool()
		headerSize := 288
		chunkSize := headerSize + len(typePool)

		b := new(bytes.Buffer)
		binary.Write(b, binary.LittleEndian, uint16(packageType))
		binary.Write(b, binary.LittleEndian, uint16(headerSize))
		binary.Write(b, binary.LittleEndian, uint32(chunkSize))
		binary.Write(b, binary.LittleEndian, uint32(0x7f)) // packageId
		b.Write(encodePackageName(packageName))
		// Pad remaining header fields to reach headerSize (288 - 12 = 276 bytes used so far for name+header prefix)
		// We have written: type(2)+headerSize(2)+chunkSize(4)+packageId(4)+name(256) = 268 bytes.
		// Need to pad to 288: 288 - 268 = 20 bytes of zeros.
		b.Write(make([]byte, headerSize-268))
		b.Write(typePool)
		return b.Bytes()
	}

	globalPool := buildEmptyStringPool()
	pkgChunk := buildPackageChunk()

	// Resource table header: type(2)+headerSize(2)+totalSize(4)+packageCount(4) = 12 bytes
	resTableHeaderSize := 12
	totalSize := resTableHeaderSize + len(globalPool) + len(pkgChunk)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(resTableType))
	binary.Write(buf, binary.LittleEndian, uint16(resTableHeaderSize))
	binary.Write(buf, binary.LittleEndian, uint32(totalSize))
	binary.Write(buf, binary.LittleEndian, uint32(1)) // packageCount
	buf.Write(globalPool)
	buf.Write(pkgChunk)

	return buf.Bytes()
}

func TestParseARSC_WithPackageChunk(t *testing.T) {
	data := buildARSCWithPackage("com.example.test")
	r := &bytesReaderAt{data: data}

	stringPool, packageName, typeNames, err := ParseARSC(r, int64(len(data)))
	if err != nil {
		t.Fatalf("ParseARSC: %v", err)
	}

	if stringPool == nil {
		t.Fatal("expected non-nil string pool")
	}
	if packageName != "com.example.test" {
		t.Errorf("packageName = %q, want %q", packageName, "com.example.test")
	}
	// typeNames may be empty (the type pool has no entries) but must not be nil from an error.
	_ = typeNames
}

func TestParsePackageChunk_TooSmall(t *testing.T) {
	_, _, err := parsePackageChunk(make([]byte, 100))
	if err == nil {
		t.Error("expected error for package chunk smaller than 288 bytes")
	}
}

func TestParsePackageChunk_InsufficientNameData(t *testing.T) {
	// Provide exactly 288 bytes but craft packageNameOffset+256 > len(data).
	// Use headerSize=288 so that packageNameOffset(12)+256=268 <= 288, which is fine.
	// To trigger the insufficient-name-data branch we need len(data) < 12+256 = 268.
	// That also means len(data) < 288, which triggers the too-small check first.
	// So this branch is only reachable if data is >= 288 but the constant offset math
	// can't exceed it — meaning the branch is unreachable in practice given constants.
	// We test the boundary: data of exactly 288 bytes should succeed at name extraction.
	data := make([]byte, 288)
	binary.LittleEndian.PutUint16(data[2:], 288) // headerSize
	_, _, err := parsePackageChunk(data)
	if err != nil {
		t.Errorf("parsePackageChunk with 288-byte chunk: unexpected error: %v", err)
	}
}

func TestParseStringPool_TooSmall(t *testing.T) {
	_, _, err := parseStringPool(make([]byte, 10))
	if err == nil {
		t.Error("expected error for string pool smaller than 28 bytes")
	}
}

func TestParseStringPool_ChunkSizeExceedsData(t *testing.T) {
	data := make([]byte, 28)
	binary.LittleEndian.PutUint16(data[0:], uint16(stringPoolType))
	binary.LittleEndian.PutUint16(data[2:], 28)
	binary.LittleEndian.PutUint32(data[4:], 9999) // chunkSize > len(data)
	_, _, err := parseStringPool(data)
	if err == nil {
		t.Error("expected error when chunkSize exceeds data length")
	}
}

func TestParseStringPool_TruncatedOffsets(t *testing.T) {
	// stringCount=10 but data ends before the offsets array is complete.
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(stringPoolType))
	binary.Write(buf, binary.LittleEndian, uint16(28))
	binary.Write(buf, binary.LittleEndian, uint32(32)) // chunkSize=32 (only 4 bytes of offset array)
	binary.Write(buf, binary.LittleEndian, uint32(10)) // stringCount=10
	binary.Write(buf, binary.LittleEndian, uint32(0))  // styleCount
	binary.Write(buf, binary.LittleEndian, uint32(0))  // flags
	binary.Write(buf, binary.LittleEndian, uint32(28)) // stringsStart
	binary.Write(buf, binary.LittleEndian, uint32(0))  // stylesStart
	// Only 4 bytes of offset data — far fewer than stringCount*4=40 bytes needed.
	binary.Write(buf, binary.LittleEndian, uint32(0))

	data := buf.Bytes()
	info, size, err := parseStringPool(data)
	if err != nil {
		t.Fatalf("parseStringPool: unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil StringPoolInfo")
	}
	if size != 32 {
		t.Errorf("chunkSize = %d, want 32", size)
	}
	// Truncated offsets array means no strings are added.
	if len(info.SampleStrings) != 0 {
		t.Errorf("expected 0 sample strings, got %d", len(info.SampleStrings))
	}
}

func TestParseStringPool_UTF8WithStrings(t *testing.T) {
	// Build a string pool with UTF-8 flag and two strings: "layout" and "color"
	buildUTF8String := func(s string) []byte {
		b := new(bytes.Buffer)
		// char length (1 byte, < 0x80)
		b.WriteByte(byte(len(s)))
		// byte length (1 byte)
		b.WriteByte(byte(len(s)))
		b.WriteString(s)
		b.WriteByte(0) // null terminator
		return b.Bytes()
	}

	str1 := buildUTF8String("layout")
	str2 := buildUTF8String("color")

	stringsData := append(str1, str2...)
	stringCount := 2
	stringsStart := 28 + stringCount*4 // header(28) + offsets(2*4)

	chunkSize := stringsStart + len(stringsData)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(stringPoolType))
	binary.Write(buf, binary.LittleEndian, uint16(28))
	binary.Write(buf, binary.LittleEndian, uint32(chunkSize))
	binary.Write(buf, binary.LittleEndian, uint32(stringCount))
	binary.Write(buf, binary.LittleEndian, uint32(0)) // styleCount
	binary.Write(buf, binary.LittleEndian, uint32(stringPoolUTF8Flag))
	binary.Write(buf, binary.LittleEndian, uint32(stringsStart))
	binary.Write(buf, binary.LittleEndian, uint32(0)) // stylesStart

	// Offsets: str1 at 0, str2 at len(str1)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(len(str1)))

	buf.Write(stringsData)

	data := buf.Bytes()
	info, _, err := parseStringPool(data)
	if err != nil {
		t.Fatalf("parseStringPool UTF-8: %v", err)
	}
	if info.TotalStrings != 2 {
		t.Errorf("TotalStrings = %d, want 2", info.TotalStrings)
	}
	if !info.UTF8 {
		t.Error("expected UTF8=true")
	}
	if len(info.SampleStrings) != 2 {
		t.Fatalf("expected 2 sample strings, got %d", len(info.SampleStrings))
	}
	if info.SampleStrings[0] != "layout" {
		t.Errorf("SampleStrings[0] = %q, want %q", info.SampleStrings[0], "layout")
	}
	if info.SampleStrings[1] != "color" {
		t.Errorf("SampleStrings[1] = %q, want %q", info.SampleStrings[1], "color")
	}
}

func TestReadUTF8String_TruncatedTwoByteLength(t *testing.T) {
	// charLen=3 (1 byte), then byte-length high bit set but only 1 byte remains.
	data := []byte{3, 0x80} // pos=1 after charLen; data[1]&0x80 != 0 but pos+1 >= len(data)
	_, err := readUTF8String(data)
	if err == nil {
		t.Error("expected error for truncated 2-byte byte-length")
	}
}

func TestReadUTF8String_DataExceedsBuffer(t *testing.T) {
	// charLen=10 (1 byte), byteLen=10 but data has only 3 bytes after length fields.
	data := []byte{10, 10, 'a', 'b', 'c'} // claims 10 bytes but only 3 available
	_, err := readUTF8String(data)
	if err == nil {
		t.Error("expected error when string data exceeds buffer")
	}
}

func TestCheckSQLiteFile_TooSmall(t *testing.T) {
	// Create an APK with a .db file that has fewer than 16 bytes.
	apkPath := createTestAPK(t, map[string][]byte{
		"assets/tiny.db": []byte("short"),
	})

	zipReader, err := zip.OpenReader(apkPath)
	if err != nil {
		t.Fatalf("open APK: %v", err)
	}
	defer zipReader.Close()

	var dbFile *zip.File
	for _, f := range zipReader.File {
		if f.Name == "assets/tiny.db" {
			dbFile = f
			break
		}
	}
	if dbFile == nil {
		t.Fatal("could not find assets/tiny.db in test APK")
	}

	isSQLite, err := checkSQLiteFile(dbFile)
	if err != nil {
		t.Fatalf("checkSQLiteFile: unexpected error: %v", err)
	}
	if isSQLite {
		t.Error("expected isSQLite=false for file smaller than 16 bytes")
	}
}

func TestScanAPK_InvalidResources(t *testing.T) {
	// An APK with a resources.arsc that has an invalid header type.
	invalidARSC := createInvalidARSC()
	// Pad to at least 12 bytes so the size check passes but the type check fails.
	if len(invalidARSC) < 12 {
		invalidARSC = append(invalidARSC, make([]byte, 12-len(invalidARSC))...)
	}

	apkPath := createTestAPK(t, map[string][]byte{
		"resources.arsc": invalidARSC,
	})

	_, err := ScanAPK(apkPath)
	if err == nil {
		t.Error("expected error when resources.arsc has invalid format")
	}
}
