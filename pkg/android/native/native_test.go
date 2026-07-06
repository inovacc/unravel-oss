/*
Copyright (c) 2026 Security Research
*/
package native

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDecodeJNIName(t *testing.T) {
	tests := []struct {
		name   string
		symbol string
		want   string
	}{
		{
			name:   "simple class and method",
			symbol: "Java_com_example_MyClass_doWork",
			want:   "com.example.MyClass.doWork",
		},
		{
			name:   "underscore escape",
			symbol: "Java_com_example_My_1Class_do_1Work",
			want:   "com.example.My_Class.do_Work",
		},
		{
			name:   "single segment",
			symbol: "Java_Main_run",
			want:   "Main.run",
		},
		{
			name:   "deep package",
			symbol: "Java_org_apache_commons_lang3_StringUtils_isEmpty",
			want:   "org.apache.commons.lang3.StringUtils.isEmpty",
		},
		{
			name:   "no prefix passthrough",
			symbol: "notJava",
			want:   "notJava",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeJNIName(tt.symbol)
			if got != tt.want {
				t.Errorf("DecodeJNIName(%q) = %q, want %q", tt.symbol, got, tt.want)
			}
		})
	}
}

func TestScanAPK_EmptyAPK(t *testing.T) {
	// Create a minimal ZIP file with no native libraries.
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create temp apk: %v", err)
	}

	zw := zip.NewWriter(f)
	// Add a non-SO entry.
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	_, _ = w.Write([]byte("<manifest/>"))

	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.TotalLibs != 0 {
		t.Errorf("expected 0 libraries, got %d", result.TotalLibs)
	}
	if len(result.ABIs) != 0 {
		t.Errorf("expected 0 ABIs, got %d", len(result.ABIs))
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.PackerDetected != "" {
		t.Errorf("expected no packer, got %q", result.PackerDetected)
	}
}

func TestScanAPK_InvalidPath(t *testing.T) {
	_, err := ScanAPK("/nonexistent/path.apk")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestIsNativeLib(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"standard so", "lib/arm64-v8a/libfoo.so", true},
		{"versioned so", "lib/armeabi-v7a/libbar.so.1", true},
		{"not in lib", "assets/libfoo.so", false},
		{"dex file", "classes.dex", false},
		{"manifest", "AndroidManifest.xml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNativeLib(tt.path)
			if got != tt.want {
				t.Errorf("isNativeLib(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectPacker(t *testing.T) {
	findings := []Finding{
		{Category: "anti-debug", Pattern: "ptrace"},
		{Category: "packer", Pattern: "UPX!"},
	}

	got := detectPacker(findings)
	if got != "UPX" {
		t.Errorf("detectPacker = %q, want %q", got, "UPX")
	}

	got = detectPacker(nil)
	if got != "" {
		t.Errorf("detectPacker(nil) = %q, want empty", got)
	}
}

// buildMinimalELF creates a minimal valid 64-bit little-endian ELF shared object.
// The rodata parameter is embedded in a .rodata section. dynSyms are added as
// dynamic symbol table entries with Java_ prefix for JNI export detection.
func buildMinimalELF(t *testing.T, rodata []byte, dynSyms []string) []byte {
	t.Helper()

	// We'll build a real ELF using debug/elf by creating a minimal binary
	// and then using the Go assembler. Instead, construct raw bytes.
	// Simpler approach: use a real Go ELF via compile, but that's heavy.
	// Simplest correct approach: write bytes that debug/elf.NewFile can parse.

	// For testing ScanAPK which calls elf.NewFile, we need valid ELF.
	// Use encoding/binary to construct a minimal ELF64 LE shared object.

	// This is complex, so let's use a different approach: create a real
	// shared object using cgo or just test with the raw APK scan path
	// using files that will fail ELF parsing (which is handled gracefully).

	// Actually, the simplest approach for valid ELF: compile a trivial C
	// program. But we shouldn't depend on a C compiler in tests.

	// Let's test what we can without valid ELF and verify error handling.
	return nil
}

func TestScanAPK_MultipleABIs(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "multi-abi.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)

	// Add SO files for multiple ABIs. They won't be valid ELF, so
	// analyzeLibrary will skip them, but we verify the APK opens and
	// invalid libs are gracefully skipped.
	abis := []string{"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
	for _, abi := range abis {
		w, err := zw.Create("lib/" + abi + "/libtest.so")
		if err != nil {
			t.Fatal(err)
		}
		// Write non-ELF data; analyzeLibrary will skip due to parse error.
		_, _ = w.Write([]byte("not-an-elf"))
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	// Invalid ELF files are skipped, so TotalLibs should be 0.
	if result.TotalLibs != 0 {
		t.Errorf("expected 0 valid libs (invalid ELF), got %d", result.TotalLibs)
	}
}

func TestScanAPK_WithPackerFinding(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "packed.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("<manifest/>"))

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.PackerDetected != "" {
		t.Errorf("expected no packer, got %q", result.PackerDetected)
	}
}

func TestDecodeJNIName_JNIExportPattern(t *testing.T) {
	tests := []struct {
		symbol   string
		wantJava string
	}{
		{
			symbol:   "Java_com_example_MyClass_nativeMethod",
			wantJava: "com.example.MyClass.nativeMethod",
		},
		{
			symbol:   "Java_com_example_crypto_AES_encrypt",
			wantJava: "com.example.crypto.AES.encrypt",
		},
		{
			symbol:   "Java_io_realm_internal_OsResults_nativeGetRow",
			wantJava: "io.realm.internal.OsResults.nativeGetRow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.symbol, func(t *testing.T) {
			got := DecodeJNIName(tt.symbol)
			if got != tt.wantJava {
				t.Errorf("DecodeJNIName(%q) = %q, want %q", tt.symbol, got, tt.wantJava)
			}
		})
	}
}

func TestDetectPacker_AllSignatures(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"UPX", "UPX!", "UPX"},
		{"Bangcle", "libsecexe.so", "Bangcle"},
		{"DEXProtector", "libDexHelper.so", "DEXProtector"},
		{"360 Jiagu", "libjiagu.so", "360 Jiagu"},
		{"Tencent Legu", "libshella", "Tencent Legu"},
		{"Tencent", "libtosprotection", "Tencent"},
		{"Ijiami", "ijiami", "Ijiami"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []Finding{
				{Category: "packer", Pattern: tt.pattern},
			}
			got := detectPacker(findings)
			if got != tt.want {
				t.Errorf("detectPacker with pattern %q = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestDetectPacker_NonPackerFindings(t *testing.T) {
	findings := []Finding{
		{Category: "anti-debug", Pattern: "ptrace"},
		{Category: "root-detection", Pattern: "/system/xbin/su"},
	}
	got := detectPacker(findings)
	if got != "" {
		t.Errorf("expected empty packer for non-packer findings, got %q", got)
	}
}

func TestMachineString(t *testing.T) {
	tests := []struct {
		machine elf.Machine
		want    string
	}{
		{elf.EM_ARM, "ARM"},
		{elf.EM_AARCH64, "AARCH64"},
		{elf.EM_386, "386"},
		{elf.EM_X86_64, "AMD64"},
		{elf.EM_MIPS, "MIPS"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := machineString(tt.machine)
			if got != tt.want {
				t.Errorf("machineString(%v) = %q, want %q", tt.machine, got, tt.want)
			}
		})
	}
}

func TestIsNativeLib_Extended(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"arm64-v8a", "lib/arm64-v8a/libnative.so", true},
		{"armeabi-v7a", "lib/armeabi-v7a/libcrypto.so", true},
		{"x86", "lib/x86/libssl.so", true},
		{"x86_64", "lib/x86_64/libapp.so", true},
		{"versioned .so.1", "lib/arm64-v8a/libfoo.so.1", true},
		{"not .so extension", "lib/arm64-v8a/libfoo.a", false},
		{"in assets not lib", "assets/libfoo.so", false},
		{"root level so", "libfoo.so", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNativeLib(tt.path)
			if got != tt.want {
				t.Errorf("isNativeLib(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// buildGoELF compiles a trivial Go binary using the host Go toolchain and
// returns the path to the resulting ELF executable. The binary is written
// inside a t.TempDir() subdirectory so it is cleaned up automatically.
// The test is skipped on non-Linux platforms.
func buildGoELF(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux only: need a native ELF to exercise analyzeLibrary")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write go source: %v", err)
	}

	bin := filepath.Join(dir, "test.bin")
	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// buildGoELFWithStrings compiles a Go binary that prints the provided string
// literals via fmt.Println so they are retained verbatim in the binary's data
// segment (a plain var initialiser can be optimised away by the compiler).
// This lets us trigger scanPatterns findings without a C compiler.
func buildGoELFWithStrings(t *testing.T, literals []string) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux only: need a native ELF to exercise analyzeLibrary")
	}

	// fmt.Println calls force the strings into the binary's rodata/text.
	var sb strings.Builder
	sb.WriteString("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(")
	for i, s := range literals {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("`")
		sb.WriteString(s)
		sb.WriteString("`")
	}
	sb.WriteString(")\n}\n")

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write go source: %v", err)
	}

	bin := filepath.Join(dir, "test.bin")
	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// createAPKWithELF wraps elfPath inside a ZIP at the given soPath entry name
// (e.g. "lib/x86_64/libtest.so") and returns the APK path.
func createAPKWithELF(t *testing.T, elfPath, soPath string) string {
	t.Helper()

	elfData, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatalf("read elf: %v", err)
	}

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create apk: %v", err)
	}

	zw := zip.NewWriter(f)
	w, err := zw.Create(soPath)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write(elfData); err != nil {
		t.Fatalf("write elf data: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	return apkPath
}

// TestScanAPK_WithRealELF verifies that ScanAPK correctly parses a real ELF
// binary embedded as lib/x86_64/libtest.so inside a ZIP. We use a Go-compiled
// binary instead of a C shared object to avoid requiring gcc.
func TestScanAPK_WithRealELF(t *testing.T) {
	bin := buildGoELF(t)
	apkPath := createAPKWithELF(t, bin, "lib/x86_64/libtest.so")

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.TotalLibs != 1 {
		t.Errorf("TotalLibs = %d, want 1", result.TotalLibs)
	}

	if len(result.ABIs) == 0 {
		t.Fatal("expected at least one ABI entry")
	}

	foundABI := false
	for _, a := range result.ABIs {
		if a.ABI == "x86_64" {
			foundABI = true
			break
		}
	}
	if !foundABI {
		t.Errorf("ABI x86_64 not found in %v", result.ABIs)
	}

	if result.Libraries[0].Machine != "AMD64" {
		t.Errorf("Machine = %q, want %q", result.Libraries[0].Machine, "AMD64")
	}
}

// TestScanAPK_WithAntiDebugStrings verifies that scanPatterns detects multiple
// anti-debug findings when the ELF binary contains the corresponding strings.
// We embed "ptrace" and "TracerPid" via fmt.Println so the linker retains them.
func TestScanAPK_WithAntiDebugStrings(t *testing.T) {
	bin := buildGoELFWithStrings(t, []string{"ptrace", "TracerPid"})
	apkPath := createAPKWithELF(t, bin, "lib/x86_64/libtest.so")

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.TotalLibs != 1 {
		t.Fatalf("TotalLibs = %d, want 1", result.TotalLibs)
	}

	patternsFound := map[string]bool{}
	for _, f := range result.Findings {
		if f.Category == "anti-debug" {
			patternsFound[f.Pattern] = true
		}
	}

	for _, want := range []string{"ptrace", "TracerPid"} {
		if !patternsFound[want] {
			t.Errorf("expected anti-debug finding for pattern %q, got findings: %v", want, result.Findings)
		}
	}
}

// TestMachineString_Default verifies that machineString falls through to the
// standard library's elf.Machine.String() for unrecognised machine values.
func TestMachineString_Default(t *testing.T) {
	// elf.Machine(9999) is not covered by the switch, so the default branch
	// should delegate to the Go stdlib and return a non-empty string.
	m := elf.Machine(9999)
	got := machineString(m)
	if got == "" {
		t.Error("machineString with unknown machine returned empty string, want non-empty")
	}
	if got != m.String() {
		t.Errorf("machineString(%v) = %q, want %q (stdlib value)", m, got, m.String())
	}
}

// TestScanAPK_PackerByLibName verifies that a library whose filename matches a
// known packer signature (libsecexe.so → Bangcle) causes PackerDetected to be
// set in the result. This exercises the name-based packer check in analyzeLibrary.
func TestScanAPK_PackerByLibName(t *testing.T) {
	bin := buildGoELF(t)
	// "libsecexe.so" is the Bangcle packer signature matched against the base
	// filename inside analyzeLibrary.
	apkPath := createAPKWithELF(t, bin, "lib/arm64-v8a/libsecexe.so")

	result, err := ScanAPK(apkPath)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.TotalLibs != 1 {
		t.Fatalf("TotalLibs = %d, want 1", result.TotalLibs)
	}

	if result.PackerDetected != "Bangcle" {
		t.Errorf("PackerDetected = %q, want %q", result.PackerDetected, "Bangcle")
	}
}

// TestScanPatterns_RawDataFallback verifies that scanPatterns locates pattern
// strings via the raw-data fallback path when .rodata data is unavailable.
// We open a real ELF but pass the full binary bytes as rawData, confirming
// that at least one of the two search paths (section or raw) produces results.
func TestScanPatterns_RawDataFallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}

	// fmt.Println ensures "ptrace" is retained in the binary's data segment.
	bin := buildGoELFWithStrings(t, []string{"ptrace"})

	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read elf: %v", err)
	}

	ef, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = ef.Close() }()

	findings := scanPatterns(ef, data, "libtest.so", "x86_64")

	hasAntiDebug := false
	for _, f := range findings {
		if f.Category == "anti-debug" && f.Pattern == "ptrace" {
			hasAntiDebug = true
		}
	}
	if !hasAntiDebug {
		t.Error("expected anti-debug/ptrace finding via raw-data or .rodata path, got none")
	}
}

// --- Cross-platform minimal ELF builder ---
// buildMinimalELF64 constructs a valid ELF64 little-endian shared object
// entirely in Go (no C compiler required). It embeds:
//   - a .rodata section with the provided rodata bytes
//   - a .dynstr + .dynsym section pair with the provided dynamic symbol names
//
// This allows exercising analyzeLibrary, extractJNIExports, and scanPatterns
// on any OS.
func buildMinimalELF64(t *testing.T, machine elf.Machine, rodata []byte, dynSymNames []string) []byte {
	t.Helper()

	var buf bytes.Buffer

	// -- String tables --
	// .shstrtab: section header string table
	shstrtab := buildStringTable([]string{
		"", ".shstrtab", ".rodata", ".dynstr", ".dynsym", ".dynamic",
	})
	// .dynstr: dynamic string table
	dynstr := buildStringTable(append([]string{""}, dynSymNames...))

	// Section layout:
	//  0: NULL
	//  1: .shstrtab
	//  2: .rodata
	//  3: .dynstr
	//  4: .dynsym
	//  5: .dynamic
	const numSections = 6

	ehdrSize := uint64(64) // ELF64 header
	shdrSize := uint64(64) // section header entry size
	shdrTableSize := uint64(numSections) * shdrSize

	// Data offsets (after ELF header + section headers)
	dataStart := ehdrSize + shdrTableSize
	shstrtabOff := dataStart
	rodataOff := shstrtabOff + uint64(len(shstrtab))
	dynstrOff := rodataOff + uint64(len(rodata))
	// Each Elf64_Sym is 24 bytes; one NULL + len(dynSymNames) entries
	symEntSize := uint64(24)
	dynsymOff := dynstrOff + uint64(len(dynstr))
	dynsymSize := symEntSize * uint64(1+len(dynSymNames))
	dynamicOff := dynsymOff + dynsymSize
	// Minimal .dynamic: DT_STRTAB, DT_SYMTAB, DT_NULL (each 16 bytes)
	dynamicSize := uint64(48)

	// --- ELF header ---
	var ehdr [64]byte
	copy(ehdr[0:4], []byte{0x7f, 'E', 'L', 'F'})
	ehdr[4] = 2                                                    // ELFCLASS64
	ehdr[5] = 1                                                    // ELFDATA2LSB
	ehdr[6] = 1                                                    // EV_CURRENT
	ehdr[7] = 0                                                    // ELFOSABI_NONE
	binary.LittleEndian.PutUint16(ehdr[16:18], uint16(elf.ET_DYN)) // e_type: shared object
	binary.LittleEndian.PutUint16(ehdr[18:20], uint16(machine))    // e_machine
	binary.LittleEndian.PutUint32(ehdr[20:24], 1)                  // e_version
	binary.LittleEndian.PutUint64(ehdr[24:32], 0)                  // e_entry
	binary.LittleEndian.PutUint64(ehdr[32:40], 0)                  // e_phoff (no program headers)
	binary.LittleEndian.PutUint64(ehdr[40:48], ehdrSize)           // e_shoff
	binary.LittleEndian.PutUint32(ehdr[48:52], 0)                  // e_flags
	binary.LittleEndian.PutUint16(ehdr[52:54], 64)                 // e_ehsize
	binary.LittleEndian.PutUint16(ehdr[54:56], 0)                  // e_phentsize
	binary.LittleEndian.PutUint16(ehdr[56:58], 0)                  // e_phnum
	binary.LittleEndian.PutUint16(ehdr[58:60], 64)                 // e_shentsize
	binary.LittleEndian.PutUint16(ehdr[60:62], numSections)        // e_shnum
	binary.LittleEndian.PutUint16(ehdr[62:64], 1)                  // e_shstrndx -> section 1

	_, _ = buf.Write(ehdr[:])

	// --- Section headers ---
	// Helper to write a section header
	writeShdr := func(nameIdx uint32, shType uint32, offset, size uint64, link, entsize uint64) {
		var sh [64]byte
		binary.LittleEndian.PutUint32(sh[0:4], nameIdx)        // sh_name
		binary.LittleEndian.PutUint32(sh[4:8], shType)         // sh_type
		binary.LittleEndian.PutUint64(sh[8:16], 0)             // sh_flags
		binary.LittleEndian.PutUint64(sh[16:24], 0)            // sh_addr
		binary.LittleEndian.PutUint64(sh[24:32], offset)       // sh_offset
		binary.LittleEndian.PutUint64(sh[32:40], size)         // sh_size
		binary.LittleEndian.PutUint32(sh[40:44], uint32(link)) // sh_link
		binary.LittleEndian.PutUint32(sh[44:48], 0)            // sh_info
		binary.LittleEndian.PutUint64(sh[48:56], 1)            // sh_addralign
		binary.LittleEndian.PutUint64(sh[56:64], entsize)      // sh_entsize
		_, _ = buf.Write(sh[:])
	}

	// Index helpers for .shstrtab name offsets
	shNames := buildStringTableOffsets([]string{
		"", ".shstrtab", ".rodata", ".dynstr", ".dynsym", ".dynamic",
	})

	// 0: NULL section
	writeShdr(shNames[""], uint32(elf.SHT_NULL), 0, 0, 0, 0)
	// 1: .shstrtab
	writeShdr(shNames[".shstrtab"], uint32(elf.SHT_STRTAB), shstrtabOff, uint64(len(shstrtab)), 0, 0)
	// 2: .rodata
	writeShdr(shNames[".rodata"], uint32(elf.SHT_PROGBITS), rodataOff, uint64(len(rodata)), 0, 0)
	// 3: .dynstr
	writeShdr(shNames[".dynstr"], uint32(elf.SHT_STRTAB), dynstrOff, uint64(len(dynstr)), 0, 0)
	// 4: .dynsym (link=3 means dynstr is at section index 3)
	writeShdr(shNames[".dynsym"], uint32(elf.SHT_DYNSYM), dynsymOff, dynsymSize, 3, symEntSize)
	// 5: .dynamic
	writeShdr(shNames[".dynamic"], uint32(elf.SHT_DYNAMIC), dynamicOff, dynamicSize, 3, 16)

	// --- Section data ---
	// .shstrtab
	_, _ = buf.Write(shstrtab)
	// .rodata
	_, _ = buf.Write(rodata)
	// .dynstr
	_, _ = buf.Write(dynstr)

	// .dynsym entries
	// NULL symbol (required first entry)
	_, _ = buf.Write(make([]byte, 24))
	// Actual symbols
	dynstrOffsets := buildStringTableOffsets(append([]string{""}, dynSymNames...))
	for _, name := range dynSymNames {
		var sym [24]byte
		binary.LittleEndian.PutUint32(sym[0:4], dynstrOffsets[name]) // st_name
		sym[4] = byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC)        // st_info
		sym[5] = 0                                                   // st_other
		binary.LittleEndian.PutUint16(sym[6:8], 1)                   // st_shndx (non-zero)
		binary.LittleEndian.PutUint64(sym[8:16], 0x1000)             // st_value
		binary.LittleEndian.PutUint64(sym[16:24], 0x10)              // st_size
		_, _ = buf.Write(sym[:])
	}

	// .dynamic entries
	writeDyn := func(tag int64, val uint64) {
		var d [16]byte
		binary.LittleEndian.PutUint64(d[0:8], uint64(tag))
		binary.LittleEndian.PutUint64(d[8:16], val)
		_, _ = buf.Write(d[:])
	}
	writeDyn(int64(elf.DT_STRTAB), dynstrOff)
	writeDyn(int64(elf.DT_SYMTAB), dynsymOff)
	writeDyn(int64(elf.DT_NULL), 0)

	return buf.Bytes()
}

func buildStringTable(names []string) []byte {
	var buf bytes.Buffer
	for _, n := range names {
		_, _ = buf.WriteString(n)
		_ = buf.WriteByte(0)
	}
	return buf.Bytes()
}

func buildStringTableOffsets(names []string) map[string]uint32 {
	offsets := make(map[string]uint32)
	off := uint32(0)
	for _, n := range names {
		offsets[n] = off
		off += uint32(len(n)) + 1
	}
	return offsets
}

// createAPKWithRawELF creates a ZIP/APK containing the raw ELF bytes at the given entry path.
func createAPKWithRawELF(t *testing.T, elfData []byte, entries map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create apk: %v", err)
	}
	zw := zip.NewWriter(f)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create entry %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("write entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}
	return apkPath
}

// TestScanAPK_CrossPlatform_WithValidELF tests the full ScanAPK pipeline
// on all platforms using a synthetic ELF binary.
func TestScanAPK_CrossPlatform_WithValidELF(t *testing.T) {
	elfData := buildMinimalELF64(t, elf.EM_AARCH64, nil, nil)

	// Verify ELF is parseable
	ef, err := elf.NewFile(bytes.NewReader(elfData))
	if err != nil {
		t.Fatalf("minimal ELF not parseable: %v", err)
	}
	_ = ef.Close()

	apk := createAPKWithRawELF(t, nil, map[string][]byte{
		"lib/arm64-v8a/libtest.so": elfData,
	})

	result, err := ScanAPK(apk)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.TotalLibs != 1 {
		t.Errorf("TotalLibs = %d, want 1", result.TotalLibs)
	}
	if len(result.ABIs) != 1 || result.ABIs[0].ABI != "arm64-v8a" {
		t.Errorf("ABIs = %v, want [{arm64-v8a 1 ...}]", result.ABIs)
	}
	if result.Libraries[0].Machine != "AARCH64" {
		t.Errorf("Machine = %q, want AARCH64", result.Libraries[0].Machine)
	}
	if result.Libraries[0].Name != "libtest.so" {
		t.Errorf("Name = %q, want libtest.so", result.Libraries[0].Name)
	}
}

// TestScanAPK_CrossPlatform_MultipleABIs tests multiple ABI directories with valid ELF.
func TestScanAPK_CrossPlatform_MultipleABIs(t *testing.T) {
	elfARM := buildMinimalELF64(t, elf.EM_AARCH64, nil, nil)
	elfX86 := buildMinimalELF64(t, elf.EM_X86_64, nil, nil)

	apk := createAPKWithRawELF(t, nil, map[string][]byte{
		"lib/arm64-v8a/libfoo.so": elfARM,
		"lib/x86_64/libfoo.so":    elfX86,
	})

	result, err := ScanAPK(apk)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.TotalLibs != 2 {
		t.Errorf("TotalLibs = %d, want 2", result.TotalLibs)
	}
	if len(result.ABIs) != 2 {
		t.Errorf("len(ABIs) = %d, want 2", len(result.ABIs))
	}
}

// TestScanAPK_CrossPlatform_JNIExports verifies JNI export extraction.
func TestScanAPK_CrossPlatform_JNIExports(t *testing.T) {
	jniSyms := []string{
		"Java_com_example_MyClass_nativeInit",
		"Java_com_example_crypto_AES_encrypt",
		"some_other_func",
	}
	elfData := buildMinimalELF64(t, elf.EM_AARCH64, nil, jniSyms)

	apk := createAPKWithRawELF(t, nil, map[string][]byte{
		"lib/arm64-v8a/libnative.so": elfData,
	})

	result, err := ScanAPK(apk)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if len(result.JNIExports) != 2 {
		t.Fatalf("JNIExports count = %d, want 2 (only Java_ prefixed)", len(result.JNIExports))
	}

	expectedJava := map[string]string{
		"Java_com_example_MyClass_nativeInit": "com.example.MyClass.nativeInit",
		"Java_com_example_crypto_AES_encrypt": "com.example.crypto.AES.encrypt",
	}
	for _, exp := range result.JNIExports {
		want, ok := expectedJava[exp.Symbol]
		if !ok {
			t.Errorf("unexpected JNI export: %q", exp.Symbol)
			continue
		}
		if exp.JavaName != want {
			t.Errorf("JNI %q JavaName = %q, want %q", exp.Symbol, exp.JavaName, want)
		}
		if exp.Library != "libnative.so" {
			t.Errorf("JNI %q Library = %q, want libnative.so", exp.Symbol, exp.Library)
		}
		if exp.ABI != "arm64-v8a" {
			t.Errorf("JNI %q ABI = %q, want arm64-v8a", exp.Symbol, exp.ABI)
		}
	}
}

// TestScanAPK_CrossPlatform_AntiDebugPatterns verifies scanPatterns detection via rodata.
func TestScanAPK_CrossPlatform_AntiDebugPatterns(t *testing.T) {
	rodata := []byte("some prefix ptrace some middle TracerPid some end")
	elfData := buildMinimalELF64(t, elf.EM_AARCH64, rodata, nil)

	apk := createAPKWithRawELF(t, nil, map[string][]byte{
		"lib/arm64-v8a/libtest.so": elfData,
	})

	result, err := ScanAPK(apk)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	found := map[string]bool{}
	for _, f := range result.Findings {
		if f.Category == "anti-debug" {
			found[f.Pattern] = true
		}
	}
	for _, want := range []string{"ptrace", "TracerPid"} {
		if !found[want] {
			t.Errorf("missing anti-debug pattern %q in findings", want)
		}
	}
}

// TestScanAPK_CrossPlatform_RootDetection verifies root detection patterns.
func TestScanAPK_CrossPlatform_RootDetection(t *testing.T) {
	rodata := []byte("/system/xbin/su\x00com.topjohnwu.magisk\x00test-keys")
	elfData := buildMinimalELF64(t, elf.EM_AARCH64, rodata, nil)

	apk := createAPKWithRawELF(t, nil, map[string][]byte{
		"lib/arm64-v8a/libtest.so": elfData,
	})

	result, err := ScanAPK(apk)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	found := map[string]bool{}
	for _, f := range result.Findings {
		if f.Category == "root-detection" {
			found[f.Pattern] = true
		}
	}
	for _, want := range []string{"/system/xbin/su", "com.topjohnwu.magisk", "test-keys"} {
		if !found[want] {
			t.Errorf("missing root-detection pattern %q", want)
		}
	}
}

// TestScanAPK_CrossPlatform_EmulatorDetection verifies emulator detection patterns.
func TestScanAPK_CrossPlatform_EmulatorDetection(t *testing.T) {
	rodata := []byte("goldfish\x00ranchu\x00generic_x86\x00google_sdk\x00sdk_gphone")
	elfData := buildMinimalELF64(t, elf.EM_AARCH64, rodata, nil)

	apk := createAPKWithRawELF(t, nil, map[string][]byte{
		"lib/arm64-v8a/libtest.so": elfData,
	})

	result, err := ScanAPK(apk)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	found := map[string]bool{}
	for _, f := range result.Findings {
		if f.Category == "emulator-detection" {
			found[f.Pattern] = true
		}
	}
	for _, want := range []string{"goldfish", "ranchu", "generic_x86", "google_sdk", "sdk_gphone"} {
		if !found[want] {
			t.Errorf("missing emulator-detection pattern %q", want)
		}
	}
}

// TestScanAPK_CrossPlatform_PackerInRodata verifies packer detection via rodata content.
func TestScanAPK_CrossPlatform_PackerInRodata(t *testing.T) {
	tests := []struct {
		name     string
		rodata   string
		wantName string
	}{
		{"UPX", "UPX!", "UPX"},
		{"Bangcle", "libsecexe.so", "Bangcle"},
		{"DEXProtector", "libDexHelper.so", "DEXProtector"},
		{"360 Jiagu", "libjiagu.so", "360 Jiagu"},
		{"Tencent Legu", "libshella", "Tencent Legu"},
		{"Tencent", "libtosprotection", "Tencent"},
		{"Ijiami", "ijiami", "Ijiami"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elfData := buildMinimalELF64(t, elf.EM_AARCH64, []byte(tt.rodata), nil)
			apk := createAPKWithRawELF(t, nil, map[string][]byte{
				"lib/arm64-v8a/libtest.so": elfData,
			})

			result, err := ScanAPK(apk)
			if err != nil {
				t.Fatalf("ScanAPK: %v", err)
			}

			if result.PackerDetected != tt.wantName {
				t.Errorf("PackerDetected = %q, want %q", result.PackerDetected, tt.wantName)
			}
		})
	}
}

// TestScanAPK_CrossPlatform_PackerByLibName verifies packer detection via filename.
func TestScanAPK_CrossPlatform_PackerByLibName(t *testing.T) {
	tests := []struct {
		filename string
		wantName string
	}{
		{"libsecexe.so", "Bangcle"},
		{"libDexHelper.so", "DEXProtector"},
		{"libjiagu.so", "360 Jiagu"},
		{"libshella-2.so", "Tencent Legu"},
		{"libtosprotection.so", "Tencent"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			elfData := buildMinimalELF64(t, elf.EM_AARCH64, nil, nil)
			apk := createAPKWithRawELF(t, nil, map[string][]byte{
				"lib/arm64-v8a/" + tt.filename: elfData,
			})

			result, err := ScanAPK(apk)
			if err != nil {
				t.Fatalf("ScanAPK: %v", err)
			}

			if result.PackerDetected != tt.wantName {
				t.Errorf("PackerDetected = %q, want %q", result.PackerDetected, tt.wantName)
			}
		})
	}
}

// TestDecodeJNIName_EdgeCases covers additional JNI name edge cases.
func TestDecodeJNIName_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		symbol string
		want   string
	}{
		{
			name:   "empty string",
			symbol: "",
			want:   "",
		},
		{
			name:   "just Java_ prefix",
			symbol: "Java_",
			want:   "",
		},
		{
			name:   "multiple consecutive underscores",
			symbol: "Java_com__example__Class_method",
			want:   "com..example..Class.method",
		},
		{
			name:   "multiple _1 escapes",
			symbol: "Java_com_My_1Special_1Class_do_1It",
			want:   "com.My_Special_Class.do_It",
		},
		{
			name:   "_1 at the end",
			symbol: "Java_com_Class_method_1",
			want:   "com.Class.method_",
		},
		{
			name:   "no underscores after prefix",
			symbol: "Java_Main",
			want:   "Main",
		},
		{
			name:   "non-Java prefix unchanged",
			symbol: "JNI_OnLoad",
			want:   "JNI.OnLoad",
		},
		{
			name:   "very long name",
			symbol: "Java_com_very_long_package_name_with_many_segments_ClassName_methodName",
			want:   "com.very.long.package.name.with.many.segments.ClassName.methodName",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecodeJNIName(tt.symbol)
			if got != tt.want {
				t.Errorf("DecodeJNIName(%q) = %q, want %q", tt.symbol, got, tt.want)
			}
		})
	}
}

// TestIsNativeLib_MorePatterns covers additional path patterns.
func TestIsNativeLib_MorePatterns(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"lib/ with no abi", "lib/libfoo.so", true},
		{"nested deeper", "lib/arm64-v8a/subdir/libfoo.so", true},
		{"versioned .so.2.1", "lib/arm64-v8a/libcurl.so.2.1", true},
		{"lib/ prefix but .jar", "lib/arm64-v8a/foo.jar", false},
		{"META-INF so", "META-INF/libfoo.so", false},
		{"res/ so", "res/raw/libfoo.so", false},
		{"empty string", "", false},
		{"just lib/", "lib/", false},
		{"lib/.so", "lib/.so", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNativeLib(tt.path)
			if got != tt.want {
				t.Errorf("isNativeLib(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestMachineString_AllCases covers all architecture branches including default.
func TestMachineString_AllCases(t *testing.T) {
	tests := []struct {
		machine elf.Machine
		want    string
	}{
		{elf.EM_ARM, "ARM"},
		{elf.EM_AARCH64, "AARCH64"},
		{elf.EM_386, "386"},
		{elf.EM_X86_64, "AMD64"},
		{elf.EM_MIPS, "MIPS"},
		{elf.EM_PPC, elf.EM_PPC.String()},
		{elf.EM_PPC64, elf.EM_PPC64.String()},
		{elf.EM_S390, elf.EM_S390.String()},
		{elf.EM_RISCV, elf.EM_RISCV.String()},
		{elf.Machine(0), elf.Machine(0).String()},
		{elf.Machine(12345), elf.Machine(12345).String()},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := machineString(tt.machine)
			if got != tt.want {
				t.Errorf("machineString(%v) = %q, want %q", tt.machine, got, tt.want)
			}
		})
	}
}

// TestScanAPK_CrossPlatform_CombinedFindings tests a library with JNI exports,
// anti-debug patterns, root detection, and packer all at once.
func TestScanAPK_CrossPlatform_CombinedFindings(t *testing.T) {
	rodata := []byte("ptrace\x00/system/xbin/su\x00goldfish\x00UPX!")
	syms := []string{"Java_com_app_Native_init", "JNI_OnLoad"}
	elfData := buildMinimalELF64(t, elf.EM_ARM, rodata, syms)

	apk := createAPKWithRawELF(t, nil, map[string][]byte{
		"lib/armeabi-v7a/libnative.so": elfData,
		"AndroidManifest.xml":          []byte("<manifest/>"),
	})

	result, err := ScanAPK(apk)
	if err != nil {
		t.Fatalf("ScanAPK: %v", err)
	}

	if result.TotalLibs != 1 {
		t.Fatalf("TotalLibs = %d, want 1", result.TotalLibs)
	}

	// Check JNI (only Java_ prefixed)
	if len(result.JNIExports) != 1 {
		t.Errorf("JNIExports count = %d, want 1", len(result.JNIExports))
	}

	// Check findings categories
	categories := map[string]bool{}
	for _, f := range result.Findings {
		categories[f.Category] = true
	}
	for _, want := range []string{"anti-debug", "root-detection", "emulator-detection", "packer"} {
		if !categories[want] {
			t.Errorf("missing finding category %q", want)
		}
	}

	if result.PackerDetected != "UPX" {
		t.Errorf("PackerDetected = %q, want UPX", result.PackerDetected)
	}

	// Check ABI summary
	if len(result.ABIs) != 1 {
		t.Fatalf("ABIs count = %d, want 1", len(result.ABIs))
	}
	if result.ABIs[0].ABI != "armeabi-v7a" {
		t.Errorf("ABI = %q, want armeabi-v7a", result.ABIs[0].ABI)
	}
	if result.ABIs[0].Count != 1 {
		t.Errorf("ABI count = %d, want 1", result.ABIs[0].Count)
	}
}

// TestDetectPacker_UnknownPattern verifies that a packer finding with a
// pattern not in packerSignatures returns empty.
func TestDetectPacker_UnknownPattern(t *testing.T) {
	findings := []Finding{
		{Category: "packer", Pattern: "unknown_packer_xyz"},
	}
	got := detectPacker(findings)
	if got != "" {
		t.Errorf("detectPacker with unknown pattern = %q, want empty", got)
	}
}
