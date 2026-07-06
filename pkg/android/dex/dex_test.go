/*
Copyright (c) 2026 Security Research
*/
package dex

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildMinimalDEX() []byte {
	buf := make([]byte, headerSize)

	// Magic: dex\n035\0
	copy(buf[0:], []byte("dex\n035\x00"))

	// File size = header only.
	binary.LittleEndian.PutUint32(buf[32:], headerSize)
	// Header size.
	binary.LittleEndian.PutUint32(buf[36:], headerSize)
	// Endian tag.
	binary.LittleEndian.PutUint32(buf[40:], endianConst)

	// All ID sizes remain zero.
	return buf
}

// buildPaddedDEX creates a DEX file padded to 256 bytes so ScanAPK's minimum
// size filter (200 bytes) accepts it inside a ZIP entry.
func buildPaddedDEX() []byte {
	const padSize = 256
	buf := make([]byte, padSize)

	copy(buf[0:], []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(buf[32:], padSize)
	binary.LittleEndian.PutUint32(buf[36:], headerSize)
	binary.LittleEndian.PutUint32(buf[40:], endianConst)

	return buf
}

func TestParse_MinimalHeader(t *testing.T) {
	data := buildMinimalDEX()
	r := bytes.NewReader(data)

	dex, err := Parse(r, int64(len(data)))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if dex.Version != "035" {
		t.Errorf("version = %q, want %q", dex.Version, "035")
	}
	if dex.Header.FileSize != headerSize {
		t.Errorf("file_size = %d, want %d", dex.Header.FileSize, headerSize)
	}
	if len(dex.Strings) != 0 {
		t.Errorf("strings count = %d, want 0", len(dex.Strings))
	}
	if len(dex.Classes) != 0 {
		t.Errorf("classes count = %d, want 0", len(dex.Classes))
	}
}

func TestParse_InvalidMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic [8]byte
	}{
		{"wrong prefix", [8]byte{'b', 'a', 'd', '\n', '0', '3', '5', 0}},
		{"no null terminator", [8]byte{'d', 'e', 'x', '\n', '0', '3', '5', 'X'}},
		{"unsupported version", [8]byte{'d', 'e', 'x', '\n', '0', '1', '0', 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildMinimalDEX()
			copy(data[0:8], tt.magic[:])
			r := bytes.NewReader(data)

			_, err := Parse(r, int64(len(data)))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestParse_FileTooSmall(t *testing.T) {
	data := make([]byte, 16)
	_, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err == nil {
		t.Fatal("expected error for small file")
	}
}

func TestScanAPK(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	// Build a minimal APK (ZIP) with a classes.dex entry.
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(buildPaddedDEX()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK failed: %v", err)
	}

	if len(result.DexFiles) != 1 {
		t.Errorf("dex file count = %d, want 1", len(result.DexFiles))
	}
	if result.MultiDex {
		t.Error("expected MultiDex = false for single DEX")
	}
	if result.DexFiles[0].Name != "classes.dex" {
		t.Errorf("dex name = %q, want %q", result.DexFiles[0].Name, "classes.dex")
	}
}

func TestAnalyzeRisk(t *testing.T) {
	tests := []struct {
		name     string
		methods  []MethodRef
		strings  []string
		wantCats []string
	}{
		{
			name: "reflection detected",
			methods: []MethodRef{
				{ClassName: "java/lang/reflect/Method", Name: "invoke"},
			},
			wantCats: []string{"reflection"},
		},
		{
			name: "dynamic loading detected",
			methods: []MethodRef{
				{ClassName: "dalvik/system/DexClassLoader", Name: "<init>"},
			},
			wantCats: []string{"dynamic_loading"},
		},
		{
			name: "native exec detected",
			methods: []MethodRef{
				{ClassName: "java/lang/Runtime", Name: "exec"},
			},
			wantCats: []string{"native_exec"},
		},
		{
			name:     "root detection strings",
			strings:  []string{"/system/xbin/su", "Superuser.apk"},
			wantCats: []string{"root_detection", "root_detection"},
		},
		{
			name:     "no risks",
			methods:  []MethodRef{{ClassName: "com/example/MyClass", Name: "doStuff"}},
			wantCats: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dex := &DexFile{
				Methods: tt.methods,
				Strings: tt.strings,
			}
			findings := AnalyzeRisk(dex)

			if len(findings) != len(tt.wantCats) {
				t.Fatalf("got %d findings, want %d", len(findings), len(tt.wantCats))
			}
			for i, f := range findings {
				if f.Category != tt.wantCats[i] {
					t.Errorf("finding[%d].Category = %q, want %q", i, f.Category, tt.wantCats[i])
				}
			}
		})
	}
}

// buildPopulatedDEX creates a synthetic DEX file with 2 strings, 2 types,
// 1 method, 1 field, and 1 class definition to exercise the parser fully.
func buildPopulatedDEX() []byte {
	// Layout:
	// [0x00..0x70)   header (112 bytes)
	// [0x70..0x78)   string_id offsets: 2 x uint32
	// [0x78..0x80)   type_id indices: 2 x uint32
	// [0x80..0x88)   method_id: classIdx(u16) + protoIdx(u16) + nameIdx(u32)
	// [0x88..0x90)   field_id:  classIdx(u16) + typeIdx(u16) + nameIdx(u32)
	// [0x90..0xB0)   class_def: 8 x uint32 = 32 bytes
	// [0xB0..)       string data (MUTF-8: ULEB128 len + bytes + null)

	stringDataOff := uint32(0xB0)

	// String 0: "Lcom/example/Foo;" (18 chars)
	str0 := "Lcom/example/Foo;"
	// String 1: "doStuff" (7 chars)
	str1 := "doStuff"

	// Build string data
	var strData []byte
	str0Off := stringDataOff
	strData = append(strData, byte(len(str0))) // ULEB128 length
	strData = append(strData, []byte(str0)...)
	strData = append(strData, 0) // null terminator

	str1Off := stringDataOff + uint32(len(strData))
	strData = append(strData, byte(len(str1)))
	strData = append(strData, []byte(str1)...)
	strData = append(strData, 0)

	totalSize := int(stringDataOff) + len(strData)

	buf := make([]byte, totalSize)

	// Header
	copy(buf[0:], []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(buf[32:], uint32(totalSize)) // FileSize
	binary.LittleEndian.PutUint32(buf[36:], headerSize)        // HeaderSize
	binary.LittleEndian.PutUint32(buf[40:], endianConst)       // EndianTag

	// StringIDsSize=2, StringIDsOff=0x70
	binary.LittleEndian.PutUint32(buf[56:], 2)
	binary.LittleEndian.PutUint32(buf[60:], 0x70)

	// TypeIDsSize=2, TypeIDsOff=0x78
	binary.LittleEndian.PutUint32(buf[64:], 2)
	binary.LittleEndian.PutUint32(buf[68:], 0x78)

	// FieldIDsSize=1, FieldIDsOff=0x88
	binary.LittleEndian.PutUint32(buf[80:], 1)
	binary.LittleEndian.PutUint32(buf[84:], 0x88)

	// MethodIDsSize=1, MethodIDsOff=0x80
	binary.LittleEndian.PutUint32(buf[88:], 1)
	binary.LittleEndian.PutUint32(buf[92:], 0x80)

	// ClassDefsSize=1, ClassDefsOff=0x90
	binary.LittleEndian.PutUint32(buf[96:], 1)
	binary.LittleEndian.PutUint32(buf[100:], 0x90)

	// String ID offsets at 0x70: [str0Off, str1Off]
	binary.LittleEndian.PutUint32(buf[0x70:], str0Off)
	binary.LittleEndian.PutUint32(buf[0x74:], str1Off)

	// Type IDs at 0x78: [0, 1] (indices into strings)
	binary.LittleEndian.PutUint32(buf[0x78:], 0)
	binary.LittleEndian.PutUint32(buf[0x7C:], 1)

	// Method ID at 0x80: classIdx=0, protoIdx=0, nameIdx=1
	binary.LittleEndian.PutUint16(buf[0x80:], 0)
	binary.LittleEndian.PutUint16(buf[0x82:], 0)
	binary.LittleEndian.PutUint32(buf[0x84:], 1)

	// Field ID at 0x88: classIdx=0, typeIdx=1, nameIdx=1
	binary.LittleEndian.PutUint16(buf[0x88:], 0)
	binary.LittleEndian.PutUint16(buf[0x8A:], 1)
	binary.LittleEndian.PutUint32(buf[0x8C:], 1)

	// Class def at 0x90: typeIdx=0, accessFlags=1(PUBLIC), superclassIdx=noIndex,
	// interfacesOff=0, sourceFileIdx=1, annotationsOff=0, classDataOff=0, staticValuesOff=0
	binary.LittleEndian.PutUint32(buf[0x90:], 0)       // typeIdx
	binary.LittleEndian.PutUint32(buf[0x94:], 1)       // accessFlags
	binary.LittleEndian.PutUint32(buf[0x98:], noIndex) // superclassIdx
	binary.LittleEndian.PutUint32(buf[0x9C:], 0)       // interfacesOff
	binary.LittleEndian.PutUint32(buf[0xA0:], 1)       // sourceFileIdx
	binary.LittleEndian.PutUint32(buf[0xA4:], 0)       // annotationsOff
	binary.LittleEndian.PutUint32(buf[0xA8:], 0)       // classDataOff
	binary.LittleEndian.PutUint32(buf[0xAC:], 0)       // staticValuesOff

	// String data at 0xB0
	copy(buf[0xB0:], strData)

	return buf
}

func TestParse_WithData(t *testing.T) {
	data := buildPopulatedDEX()
	r := bytes.NewReader(data)

	dex, err := Parse(r, int64(len(data)))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Strings
	if len(dex.Strings) != 2 {
		t.Fatalf("strings count = %d, want 2", len(dex.Strings))
	}
	if dex.Strings[0] != "Lcom/example/Foo;" {
		t.Errorf("strings[0] = %q, want %q", dex.Strings[0], "Lcom/example/Foo;")
	}
	if dex.Strings[1] != "doStuff" {
		t.Errorf("strings[1] = %q, want %q", dex.Strings[1], "doStuff")
	}

	// Types
	if len(dex.Types) != 2 {
		t.Fatalf("types count = %d, want 2", len(dex.Types))
	}
	if dex.Types[0] != "Lcom/example/Foo;" {
		t.Errorf("types[0] = %q", dex.Types[0])
	}

	// Methods
	if len(dex.Methods) != 1 {
		t.Fatalf("methods count = %d, want 1", len(dex.Methods))
	}
	if dex.Methods[0].ClassName != "Lcom/example/Foo;" {
		t.Errorf("method class = %q", dex.Methods[0].ClassName)
	}
	if dex.Methods[0].Name != "doStuff" {
		t.Errorf("method name = %q", dex.Methods[0].Name)
	}

	// Fields
	if len(dex.Fields) != 1 {
		t.Fatalf("fields count = %d, want 1", len(dex.Fields))
	}
	if dex.Fields[0].ClassName != "Lcom/example/Foo;" {
		t.Errorf("field class = %q", dex.Fields[0].ClassName)
	}
	if dex.Fields[0].Name != "doStuff" {
		t.Errorf("field name = %q", dex.Fields[0].Name)
	}

	// Classes
	if len(dex.Classes) != 1 {
		t.Fatalf("classes count = %d, want 1", len(dex.Classes))
	}
	if dex.Classes[0].ClassName != "Lcom/example/Foo;" {
		t.Errorf("class name = %q", dex.Classes[0].ClassName)
	}
	if dex.Classes[0].SourceFile != "doStuff" {
		t.Errorf("source file = %q", dex.Classes[0].SourceFile)
	}
	if dex.Classes[0].Superclass != "" {
		t.Errorf("superclass = %q, want empty (noIndex)", dex.Classes[0].Superclass)
	}
}

func TestParse_BadEndianTag(t *testing.T) {
	data := buildMinimalDEX()
	// Corrupt endian tag
	binary.LittleEndian.PutUint32(data[40:], 0xDEADBEEF)
	_, err := Parse(bytes.NewReader(data), int64(len(data)))
	if err == nil {
		t.Fatal("expected error for bad endian tag")
	}
}

func TestIsDexEntry(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"classes.dex", true},
		{"classes2.dex", true},
		{"classes3.dex", true},
		{"classes10.dex", true},
		{"AndroidManifest.xml", false},
		{"lib/armeabi-v7a/libnative.so", false},
		{"resources.arsc", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDexEntry(tt.name); got != tt.want {
				t.Errorf("isDexEntry(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestFindHighEntropyStrings(t *testing.T) {
	dex := &DexFile{
		Name: "classes.dex",
		Strings: []string{
			"short",
			"aaaaaaaaaaaaaaaa",
			"aB3$kL9!mNp2@Rs7tXyZ5#wQ",
			"AAAAAAAAAAAAAAAAAAAAAA",
		},
	}

	results := findHighEntropyStrings(dex)

	if len(results) != 1 {
		t.Fatalf("got %d high-entropy strings, want 1", len(results))
	}
	if results[0].Value != "aB3$kL9!mNp2@Rs7tXyZ5#wQ" {
		t.Errorf("value = %q, want %q", results[0].Value, "aB3$kL9!mNp2@Rs7tXyZ5#wQ")
	}
	if results[0].Source != "classes.dex" {
		t.Errorf("source = %q, want %q", results[0].Source, "classes.dex")
	}
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		name    string
		method  MethodRef
		pattern riskPattern
		want    bool
	}{
		{
			name:   "class match with no method filter",
			method: MethodRef{ClassName: "javax/crypto/Cipher", Name: "init"},
			pattern: riskPattern{
				classNames: []string{"javax/crypto/Cipher"},
			},
			want: true,
		},
		{
			name:   "class match with method filter match",
			method: MethodRef{ClassName: "java/lang/reflect/Method", Name: "invoke"},
			pattern: riskPattern{
				classNames:  []string{"java/lang/reflect/Method"},
				methodNames: []string{"invoke", "forName"},
			},
			want: true,
		},
		{
			name:   "class match with method filter miss",
			method: MethodRef{ClassName: "java/lang/reflect/Method", Name: "somethingElse"},
			pattern: riskPattern{
				classNames:  []string{"java/lang/reflect/Method"},
				methodNames: []string{"invoke", "forName"},
			},
			want: false,
		},
		{
			name:   "no class match",
			method: MethodRef{ClassName: "com/example/MyClass", Name: "invoke"},
			pattern: riskPattern{
				classNames:  []string{"java/lang/reflect/Method"},
				methodNames: []string{"invoke"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesPattern(tt.method, tt.pattern); got != tt.want {
				t.Errorf("matchesPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckRootDetection(t *testing.T) {
	tests := []struct {
		name      string
		strings   []string
		wantCount int
	}{
		{"exact su match", []string{"su"}, 1},
		{"multiple root strings", []string{"/system/xbin/su", "Superuser.apk"}, 2},
		{"partial match excluded", []string{"suburb"}, 0},
		{"empty strings", []string{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dex := &DexFile{Strings: tt.strings}
			findings := checkRootDetection(dex)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantCount)
			}
		})
	}
}

func TestAnalyzeRisk_Crypto(t *testing.T) {
	dex := &DexFile{
		Methods: []MethodRef{
			{ClassName: "javax/crypto/Cipher", Name: "getInstance"},
		},
	}
	findings := AnalyzeRisk(dex)

	found := false
	for _, f := range findings {
		if f.Category == "crypto" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding with category \"crypto\"")
	}
}

func TestAnalyzeRisk_SMS(t *testing.T) {
	dex := &DexFile{
		Methods: []MethodRef{
			{ClassName: "android/telephony/SmsManager", Name: "sendTextMessage"},
		},
	}
	findings := AnalyzeRisk(dex)

	found := false
	for _, f := range findings {
		if f.Category == "sms" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding with category \"sms\"")
	}
}

func TestAnalyzeRisk_DeviceAdmin(t *testing.T) {
	dex := &DexFile{
		Methods: []MethodRef{
			{ClassName: "android/app/admin/DevicePolicyManager", Name: "lockNow"},
		},
	}
	findings := AnalyzeRisk(dex)

	found := false
	for _, f := range findings {
		if f.Category == "device_admin" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding with category \"device_admin\"")
	}
}

func TestScanAPK_MultiDex(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "multidex.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	for _, name := range []string{"classes.dex", "classes2.dex"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(buildPaddedDEX()); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK failed: %v", err)
	}
	if !result.MultiDex {
		t.Error("expected MultiDex = true")
	}
	if len(result.DexFiles) != 2 {
		t.Errorf("got %d dex files, want 2", len(result.DexFiles))
	}
}

func TestScanAPK_NoDex(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "nodex.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = ScanAPK(apkPath)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no DEX files found") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "no DEX files found")
	}
}

func TestScanAPK_CorruptedDex(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "corrupt.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("not a dex file at all!!!")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = ScanAPK(apkPath)
	if err == nil {
		t.Fatal("expected error for corrupted DEX, got nil")
	}
}
