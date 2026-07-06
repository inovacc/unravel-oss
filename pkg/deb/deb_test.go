/* Copyright (c) 2026 Security Research */
package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestParseControlFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    func(*Control) bool
		desc    string
	}{
		{
			name: "basic fields",
			content: `Package: test-pkg
Version: 1.2.3
Architecture: amd64
Maintainer: Test User <test@example.com>
Description: A test package
 with a long description
 spanning multiple lines`,
			want: func(c *Control) bool {
				return c.Package == "test-pkg" &&
					c.Version == "1.2.3" &&
					c.Architecture == "amd64" &&
					c.Maintainer == "Test User <test@example.com>" &&
					strings.Contains(c.Description, "test package")
			},
			desc: "basic fields parsed correctly",
		},
		{
			name: "with optional fields",
			content: `Package: foo
Version: 2.0
Architecture: all
Maintainer: Dev <dev@test.com>
Description: Foo package
Section: utils
Priority: optional
Homepage: https://example.com
Depends: libc6, libssl3
Installed-Size: 1024`,
			want: func(c *Control) bool {
				return c.Section == "utils" &&
					c.Priority == "optional" &&
					c.Homepage == "https://example.com" &&
					c.Depends == "libc6, libssl3" &&
					c.InstalledSize == "1024"
			},
			desc: "optional fields parsed",
		},
		{
			name:    "empty content",
			content: "",
			want: func(c *Control) bool {
				return c.Package == "" && len(c.AllFields) == 0
			},
			desc: "empty control file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseControlFile(tt.content)
			if !tt.want(got) {
				t.Errorf("parseControlFile: %s failed\nPackage=%q Version=%q Arch=%q",
					tt.desc, got.Package, got.Version, got.Architecture)
			}
		})
	}
}

func TestInfo_NonexistentFile(t *testing.T) {
	_, err := Info("/tmp/nonexistent-deb-12345.deb", false)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestInfo_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "invalid.deb")

	if err := os.WriteFile(f, []byte("not a deb file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Info(f, false)
	if err == nil {
		t.Error("expected error for invalid deb file")
	}
}

func TestExtract_NonexistentFile(t *testing.T) {
	_, err := Extract("/tmp/nonexistent-deb-12345.deb", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestVerify_NonexistentFile(t *testing.T) {
	_, err := Verify("/tmp/nonexistent-deb-12345.deb")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestReadArArchive_InvalidMagic(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "bad.ar")

	if err := os.WriteFile(f, []byte("not an ar archive!!"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := readArArchive(f)
	if err == nil {
		t.Error("expected error for invalid ar magic")
	}
}

func TestReadArArchive_ValidMinimal(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.ar")

	// Minimal ar archive: magic + one entry with "debian-binary" name
	// ar magic: "!<arch>\n" (8 bytes)
	// Entry header: 60 bytes
	var data []byte
	data = append(data, []byte("!<arch>\n")...)

	// ar entry header (60 bytes):
	// name[16] + mtime[12] + uid[6] + gid[6] + mode[8] + size[10] + magic[2]
	header := "debian-binary   1234567890  0     0     100644  4         `\n"
	data = append(data, []byte(header)...)
	data = append(data, []byte("2.0\n")...)

	if err := os.WriteFile(f, data, 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := readArArchive(f)
	if err != nil {
		t.Fatalf("readArArchive: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if !strings.HasPrefix(entries[0].Name, "debian-binary") {
		t.Errorf("expected name starting with 'debian-binary', got %q", entries[0].Name)
	}
}

func TestInfo_ValidMinimalDeb(t *testing.T) {
	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "test.deb")

	data := buildMinimalDeb(t)
	if err := os.WriteFile(debFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Info(debFile, true)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Control == nil {
		t.Fatal("expected non-nil Control")
	}

	if result.Control.Package != "test-pkg" {
		t.Errorf("expected package 'test-pkg', got %q", result.Control.Package)
	}

	if result.FormatVersion == "" {
		t.Error("expected non-empty format version")
	}
}

func TestExtract_ValidMinimalDeb(t *testing.T) {
	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "test.deb")
	outDir := filepath.Join(tmpDir, "output")

	data := buildMinimalDeb(t)
	if err := os.WriteFile(debFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Extract(debFile, outDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if report.Source != debFile {
		t.Errorf("expected source %q, got %q", debFile, report.Source)
	}
}

func TestVerify_ValidMinimalDeb(t *testing.T) {
	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "test.deb")

	data := buildMinimalDeb(t)
	if err := os.WriteFile(debFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(debFile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.HasSignature {
		t.Error("minimal deb should not have a signature")
	}
}

// buildMinimalDeb constructs a minimal valid .deb archive in memory.
// casesPath resolves a path relative to the cases/ directory at the project root.
// Skips the test if the file doesn't exist.
func casesPath(t *testing.T, relPath string) string {
	t.Helper()
	// Walk up to find go.mod (project root)
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

func TestGolden_Info_HelloDeb(t *testing.T) {
	debPath := casesPath(t, "linux/input/hello_2.10-5_amd64.deb")

	result, err := Info(debPath, true)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Control == nil {
		t.Fatal("expected non-nil Control")
	}
	if result.Control.Package != "hello" {
		t.Errorf("Package = %q, want %q", result.Control.Package, "hello")
	}
	if result.Control.Version != "2.10-5" {
		t.Errorf("Version = %q, want %q", result.Control.Version, "2.10-5")
	}
	if result.Control.Architecture != "amd64" {
		t.Errorf("Architecture = %q, want %q", result.Control.Architecture, "amd64")
	}
	if result.FormatVersion != "2.0" {
		t.Errorf("FormatVersion = %q, want %q", result.FormatVersion, "2.0")
	}
	if result.FileCount == 0 {
		t.Error("expected FileCount > 0")
	}
	if len(result.Files) == 0 {
		t.Error("expected Files to be populated (includeFiles=true)")
	}
}

func TestGolden_Extract_HelloDeb(t *testing.T) {
	debPath := casesPath(t, "linux/input/hello_2.10-5_amd64.deb")
	outDir := filepath.Join(t.TempDir(), "extracted")

	report, err := Extract(debPath, outDir)
	if err != nil {
		t.Fatalf("Extract: %v", err)
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
}

func TestGolden_Verify_HelloDeb(t *testing.T) {
	debPath := casesPath(t, "linux/input/hello_2.10-5_amd64.deb")

	result, err := Verify(debPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// hello_2.10-5 is a standard Debian package; signature presence may vary
	// but the function should succeed without error
	if result.FileName != "hello_2.10-5_amd64.deb" {
		t.Errorf("FileName = %q, want %q", result.FileName, "hello_2.10-5_amd64.deb")
	}
}

func TestReadArEntry_Valid(t *testing.T) {
	// Build a single ar entry in a buffer
	entryData := []byte("hello")
	header := fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10d`\n", "test.txt", "1234567890", "0", "0", "100644", len(entryData))

	var buf bytes.Buffer
	buf.WriteString(header)
	buf.Write(entryData)
	// Odd size needs padding byte
	buf.WriteByte('\n')

	rs := bytes.NewReader(buf.Bytes())
	entry, err := readArEntry(rs)
	if err != nil {
		t.Fatalf("readArEntry: %v", err)
	}

	if entry.Name != "test.txt" {
		t.Errorf("Name = %q, want %q", entry.Name, "test.txt")
	}
	if entry.Size != 5 {
		t.Errorf("Size = %d, want 5", entry.Size)
	}
	if string(entry.Data) != "hello" {
		t.Errorf("Data = %q, want %q", string(entry.Data), "hello")
	}
}

func TestReadArEntry_InvalidMagic(t *testing.T) {
	// 60-byte header with bad magic (last 2 bytes)
	header := make([]byte, 60)
	for i := range header {
		header[i] = ' '
	}
	header[58] = 'X'
	header[59] = 'X'

	rs := bytes.NewReader(header)
	_, err := readArEntry(rs)
	if err == nil {
		t.Error("expected error for invalid ar entry magic")
	}
}

func TestReadArEntry_EOF(t *testing.T) {
	rs := bytes.NewReader(nil)
	_, err := readArEntry(rs)
	if err == nil {
		t.Error("expected error for empty reader")
	}
}

func TestDecompressReader_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte("compressed data"))
	_ = gw.Close()

	r, err := decompressReader(buf.Bytes(), "data.tar.gz")
	if err != nil {
		t.Fatalf("decompressReader(.gz): %v", err)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "compressed data" {
		t.Errorf("got %q, want %q", string(got), "compressed data")
	}
}

func TestDecompressReader_Uncompressed(t *testing.T) {
	data := []byte("plain data")
	r, err := decompressReader(data, "data.tar")
	if err != nil {
		t.Fatalf("decompressReader(plain): %v", err)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "plain data" {
		t.Errorf("got %q, want %q", string(got), "plain data")
	}
}

func TestDecompressReader_InvalidGzip(t *testing.T) {
	_, err := decompressReader([]byte("not gzip"), "data.tar.gz")
	if err == nil {
		t.Error("expected error for invalid gzip data")
	}
}

func TestListTarContents_Synthetic(t *testing.T) {
	// Build a real tar archive in memory
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	_ = tw.WriteHeader(&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "dir/file.txt", Typeflag: tar.TypeReg, Size: 5, Mode: 0o644})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "dir/file.txt"})
	_ = tw.Close()

	files, err := listTarContents(buf.Bytes(), "data.tar")
	if err != nil {
		t.Fatalf("listTarContents: %v", err)
	}

	if len(files) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(files))
	}

	// dir
	if !files[0].IsDir {
		t.Error("expected first entry to be a directory")
	}
	// file
	if files[1].Size != 5 {
		t.Errorf("file size = %d, want 5", files[1].Size)
	}
	// symlink
	if !files[2].IsLink || files[2].LinkTarget != "dir/file.txt" {
		t.Errorf("expected symlink to dir/file.txt, got IsLink=%v LinkTarget=%q", files[2].IsLink, files[2].LinkTarget)
	}
}

func TestListTarContents_GzipCompressed(t *testing.T) {
	// Build tar, then gzip it
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: "test.txt", Typeflag: tar.TypeReg, Size: 4, Mode: 0o644})
	_, _ = tw.Write([]byte("data"))
	_ = tw.Close()

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(tarBuf.Bytes())
	_ = gw.Close()

	files, err := listTarContents(gzBuf.Bytes(), "data.tar.gz")
	if err != nil {
		t.Fatalf("listTarContents(.gz): %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(files))
	}
	if files[0].Name != "test.txt" {
		t.Errorf("name = %q, want %q", files[0].Name, "test.txt")
	}
}

func TestDecompressReader_Zstd(t *testing.T) {
	// zstd-compressed data
	// We can't easily create zstd without the library, but we can test the path exists
	// by passing invalid data and checking it doesn't panic
	_, err := decompressReader([]byte("not zstd"), "data.tar.zst")
	// zstd reader may or may not error on creation (it's lazy), so we just check no panic
	_ = err
}

func TestDecompressReader_Bz2(t *testing.T) {
	// bz2 returns a reader directly (no error), test it doesn't panic
	r, err := decompressReader([]byte("not bz2"), "data.tar.bz2")
	if err != nil {
		t.Fatalf("decompressReader(.bz2) unexpected creation error: %v", err)
	}
	// Reading should fail since data is invalid
	_, err = io.ReadAll(r)
	if err == nil {
		t.Error("expected error reading invalid bz2 data")
	}
}

func TestExtractTar_Synthetic(t *testing.T) {
	if runtime.GOOS == "windows" {
		tmp := t.TempDir()
		if err := os.Symlink("target", filepath.Join(tmp, "link")); err != nil {
			t.Skip("symlinks require elevated privileges on Windows")
		}
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Directory
	_ = tw.WriteHeader(&tar.Header{Name: "mydir/", Typeflag: tar.TypeDir, Mode: 0o755})
	// Regular file
	_ = tw.WriteHeader(&tar.Header{Name: "mydir/hello.txt", Typeflag: tar.TypeReg, Size: 5, Mode: 0o644})
	_, _ = tw.Write([]byte("hello"))
	// Symlink
	_ = tw.WriteHeader(&tar.Header{Name: "mydir/link", Typeflag: tar.TypeSymlink, Linkname: "hello.txt"})
	_ = tw.Close()

	outDir := filepath.Join(t.TempDir(), "extract")
	files, dirs, totalSize, errs := extractTar(buf.Bytes(), "data.tar", outDir)

	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if dirs != 1 {
		t.Errorf("dirs = %d, want 1", dirs)
	}
	if files != 2 { // regular file + symlink
		t.Errorf("files = %d, want 2", files)
	}
	if totalSize != 5 {
		t.Errorf("totalSize = %d, want 5", totalSize)
	}

	// Verify file content
	content, err := os.ReadFile(filepath.Join(outDir, "mydir", "hello.txt"))
	if err != nil {
		t.Fatalf("failed to read extracted file: %v", err)
	}
	if string(content) != "hello" {
		t.Errorf("file content = %q, want %q", string(content), "hello")
	}
}

func TestExtractTar_InvalidCompression(t *testing.T) {
	files, dirs, totalSize, errs := extractTar([]byte("not gzip"), "data.tar.gz", t.TempDir())
	if len(errs) == 0 {
		t.Error("expected errors for invalid gzip")
	}
	if files != 0 || dirs != 0 || totalSize != 0 {
		t.Error("expected zero counts for failed extraction")
	}
}

func TestVerify_WithSignature(t *testing.T) {
	// Build a deb with a _gpgorigin signature entry
	var buf []byte
	buf = append(buf, []byte("!<arch>\n")...)
	buf = appendArEntry(buf, "debian-binary", []byte("2.0\n"))
	buf = appendArEntry(buf, "_gpgorigin", []byte("-----BEGIN PGP SIGNATURE-----\nfakedata\n-----END PGP SIGNATURE-----\n"))

	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "signed.deb")
	if err := os.WriteFile(debFile, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(debFile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if result.SignatureType != "debsigs" {
		t.Errorf("SignatureType = %q, want %q", result.SignatureType, "debsigs")
	}
}

func TestVerify_DpkgSigType(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("!<arch>\n")...)
	buf = appendArEntry(buf, "debian-binary", []byte("2.0\n"))
	buf = appendArEntry(buf, "_gpgbuilder", []byte("Role: builder\nsome data\n"))

	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "dpkgsig.deb")
	if err := os.WriteFile(debFile, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(debFile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.SignatureType != "dpkg-sig" {
		t.Errorf("SignatureType = %q, want %q", result.SignatureType, "dpkg-sig")
	}
}

func TestVerify_UnknownSigType(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("!<arch>\n")...)
	buf = appendArEntry(buf, "debian-binary", []byte("2.0\n"))
	buf = appendArEntry(buf, "_gpgwhatever", []byte("random data\n"))

	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "unknownsig.deb")
	if err := os.WriteFile(debFile, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(debFile)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.SignatureType != "unknown" {
		t.Errorf("SignatureType = %q, want %q", result.SignatureType, "unknown")
	}
}

func TestExtract_DefaultOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "mypackage.deb")

	data := buildMinimalDeb(t)
	if err := os.WriteFile(debFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Pass empty output dir to trigger default naming
	report, err := Extract(debFile, "")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if !strings.HasSuffix(report.Output, "mypackage_extracted") {
		t.Errorf("expected output dir ending in 'mypackage_extracted', got %q", report.Output)
	}
}

func TestInfo_WithSignatureEntry(t *testing.T) {
	var buf []byte
	buf = append(buf, []byte("!<arch>\n")...)
	buf = appendArEntry(buf, "debian-binary", []byte("2.0\n"))
	buf = appendArEntry(buf, "_gpgorigin", []byte("sig data\n"))

	tmpDir := t.TempDir()
	debFile := filepath.Join(tmpDir, "siginfo.deb")
	if err := os.WriteFile(debFile, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Info(debFile, false)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !result.HasSignature {
		t.Error("expected HasSignature=true")
	}
	if len(result.SignatureFiles) != 1 {
		t.Errorf("expected 1 signature file, got %d", len(result.SignatureFiles))
	}
}

func TestParseControlFile_AdditionalFields(t *testing.T) {
	content := `Package: extra-pkg
Version: 3.0
Architecture: arm64
Maintainer: Test <test@test.com>
Description: Extra
Pre-Depends: base-files
Recommends: nice-pkg
Suggests: optional-pkg
Conflicts: old-pkg
Replaces: old-pkg
Provides: virtual-pkg`

	ctrl := parseControlFile(content)
	if ctrl.PreDepends != "base-files" {
		t.Errorf("PreDepends = %q, want %q", ctrl.PreDepends, "base-files")
	}
	if ctrl.Recommends != "nice-pkg" {
		t.Errorf("Recommends = %q, want %q", ctrl.Recommends, "nice-pkg")
	}
	if ctrl.Suggests != "optional-pkg" {
		t.Errorf("Suggests = %q, want %q", ctrl.Suggests, "optional-pkg")
	}
	if ctrl.Conflicts != "old-pkg" {
		t.Errorf("Conflicts = %q, want %q", ctrl.Conflicts, "old-pkg")
	}
	if ctrl.Replaces != "old-pkg" {
		t.Errorf("Replaces = %q, want %q", ctrl.Replaces, "old-pkg")
	}
	if ctrl.Provides != "virtual-pkg" {
		t.Errorf("Provides = %q, want %q", ctrl.Provides, "virtual-pkg")
	}
}

func buildMinimalDeb(t *testing.T) []byte {
	t.Helper()

	var buf []byte
	buf = append(buf, []byte("!<arch>\n")...)

	// debian-binary entry
	buf = appendArEntry(buf, "debian-binary", []byte("2.0\n"))

	// control.tar (uncompressed tar with control file)
	controlContent := "Package: test-pkg\nVersion: 1.0\nArchitecture: all\nMaintainer: Test\nDescription: Test\n"
	controlTar := buildTar(t, map[string]string{"./control": controlContent})
	buf = appendArEntry(buf, "control.tar", controlTar)

	// data.tar (empty tar)
	dataTar := buildTar(t, nil)
	buf = appendArEntry(buf, "data.tar", dataTar)

	return buf
}

func appendArEntry(buf []byte, name string, data []byte) []byte {
	// ar entry header: name[16] + mtime[12] + uid[6] + gid[6] + mode[8] + size[10] + magic[2] = 60
	header := fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10d`\n", name, "0", "0", "0", "100644", len(data))
	buf = append(buf, []byte(header)...)
	buf = append(buf, data...)

	// Pad to even byte boundary
	if len(data)%2 != 0 {
		buf = append(buf, '\n')
	}

	return buf
}

func buildTar(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf []byte

	for name, content := range files {
		header := make([]byte, 512)
		copy(header[0:100], name)
		copy(header[100:108], "0000644\x00")
		copy(header[108:116], "0001000\x00")
		copy(header[116:124], "0001000\x00")
		copy(header[124:136], fmt.Sprintf("%011o\x00", len(content)))
		copy(header[136:148], "14516523436\x00")
		copy(header[148:156], "        ") // checksum placeholder
		header[156] = '0'
		copy(header[257:262], "ustar")
		copy(header[263:265], "00")

		// Compute checksum
		var cksum int
		for _, b := range header {
			cksum += int(b)
		}

		copy(header[148:155], fmt.Sprintf("%06o\x00", cksum))

		buf = append(buf, header...)
		buf = append(buf, []byte(content)...)

		// Pad to 512-byte boundary
		padding := 512 - (len(content) % 512)
		if padding < 512 {
			buf = append(buf, make([]byte, padding)...)
		}
	}

	// EOF marker
	buf = append(buf, make([]byte, 1024)...)

	return buf
}
