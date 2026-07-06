/*
Copyright (c) 2026 Security Research
*/
package upx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAvailable(t *testing.T) {
	// Just verify it returns a bool without panic.
	_ = IsAvailable()
}

func TestHasUPXMarker_RegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regular.bin")

	// Write a file without UPX marker
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if HasUPXMarker(path) {
		t.Error("expected no UPX marker in regular file")
	}
}

func TestHasUPXMarker_WithMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upx.bin")

	// Write a file with UPX! marker near the end
	data := make([]byte, 2048)
	copy(data[2000:], []byte("UPX!"))

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if !HasUPXMarker(path) {
		t.Error("expected UPX marker to be detected")
	}
}

func TestHasUPXMarker_TooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.bin")

	if err := os.WriteFile(path, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	if HasUPXMarker(path) {
		t.Error("expected no UPX marker in tiny file")
	}
}

func TestHasUPXMarker_SmallFileWithMarker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small_upx.bin")

	// File between 512 and 4096 bytes — triggers readSize = info.Size() branch
	data := make([]byte, 600)
	copy(data[580:], []byte("UPX!"))

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if !HasUPXMarker(path) {
		t.Error("expected UPX marker in small file")
	}
}

func TestHasUPXMarker_NonExistent(t *testing.T) {
	if HasUPXMarker("/nonexistent/file") {
		t.Error("expected false for non-existent file")
	}
}

func TestInfo_NotPacked(t *testing.T) {
	if !IsAvailable() {
		t.Skip("upx not in PATH")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "notpacked.bin")

	// Write a regular file (not a valid binary)
	if err := os.WriteFile(path, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Info(path)
	if err == nil {
		t.Error("expected error for non-packed file")
	}
}

func TestParseInfo_ValidOutput(t *testing.T) {
	output := `                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    123456 ->     65432   53.01%   linux/amd64   mybinary
   --------------------   ------   -----------   -----------
Packed 1 file.
`

	result, err := parseInfo(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.OriginalSize != 123456 {
		t.Errorf("OriginalSize = %d, want 123456", result.OriginalSize)
	}

	if result.PackedSize != 65432 {
		t.Errorf("PackedSize = %d, want 65432", result.PackedSize)
	}

	if result.Ratio != 53.01 {
		t.Errorf("Ratio = %f, want 53.01", result.Ratio)
	}

	if result.Format != "linux/amd64" {
		t.Errorf("Format = %q, want %q", result.Format, "linux/amd64")
	}
}

func TestParseInfo_InvalidOutput(t *testing.T) {
	_, err := parseInfo("some garbage output")
	if err == nil {
		t.Error("expected error for invalid output")
	}
}

func TestParseInfo_MultipleFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"win32/pe", "win32/pe"},
		{"linux/elf64", "linux/elf64"},
		{"linux/arm64", "linux/arm64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := "        File size         Ratio      Format      Name\n" +
				"   --------------------   ------   -----------   -----------\n" +
				"    500000 ->    250000   50.00%   " + tt.format + "   testbin\n"

			result, err := parseInfo(output)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Format != tt.format {
				t.Errorf("Format = %q, want %q", result.Format, tt.format)
			}

			if result.OriginalSize != 500000 {
				t.Errorf("OriginalSize = %d, want 500000", result.OriginalSize)
			}

			if result.PackedSize != 250000 {
				t.Errorf("PackedSize = %d, want 250000", result.PackedSize)
			}
		})
	}
}

func TestParseInfo_EmptyOutput(t *testing.T) {
	_, err := parseInfo("")
	if err == nil {
		t.Error("expected error for empty output")
	}
}

func TestParseInfo_NoDataLine(t *testing.T) {
	output := "        File size         Ratio      Format      Name\n" +
		"   --------------------   ------   -----------   -----------\n"

	_, err := parseInfo(output)
	if err == nil {
		t.Error("expected error when no data line present")
	}
}

func TestParseInfo_MalformedNumbers(t *testing.T) {
	// Non-numeric original size — line skipped, no valid data → error
	output := "    abc ->     65432   53.01%   linux/amd64   mybinary\n"
	_, err := parseInfo(output)
	if err == nil {
		t.Error("expected error for malformed original size")
	}

	// Non-numeric packed size — line skipped → error
	output = "    123456 ->     xyz   53.01%   linux/amd64   mybinary\n"
	_, err = parseInfo(output)
	if err == nil {
		t.Error("expected error for malformed packed size")
	}

	// Too few fields — line skipped → error
	output = "    123456 ->     65432   53.01%\n"
	_, err = parseInfo(output)
	if err == nil {
		t.Error("expected error for too few fields")
	}
}

func TestParseInfo_BadRatio(t *testing.T) {
	// Non-numeric ratio — sizes still parse, ratio defaults to 0
	output := "    123456 ->     65432   bad%   linux/amd64   mybinary\n"
	result, err := parseInfo(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Ratio != 0 {
		t.Errorf("Ratio = %f, want 0 for bad ratio string", result.Ratio)
	}
}

func TestInfo_NonExistent(t *testing.T) {
	if !IsAvailable() {
		t.Skip("upx not in PATH")
	}

	_, err := Info("/nonexistent/binary")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestUnpack_NonExistentInput(t *testing.T) {
	if !IsAvailable() {
		t.Skip("upx not in PATH")
	}

	err := Unpack("/nonexistent/binary", filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Error("expected error for non-existent input")
	}
}

func TestUnpack_OutputDirCreation(t *testing.T) {
	if !IsAvailable() {
		t.Skip("upx not in PATH")
	}

	dir := filepath.Join(t.TempDir(), "nested", "dir")
	err := Unpack("/nonexistent/binary", filepath.Join(dir, "out"))
	// upx will fail on the input, but the directory should have been created
	if err == nil {
		t.Error("expected error for non-existent input")
	}
}

func TestUnpack_MkdirAllError(t *testing.T) {
	// Use /dev/null as parent to trigger MkdirAll failure —
	// cannot create a subdirectory under a device file.
	err := Unpack("/nonexistent/binary", "/dev/null/impossible/path/out")
	if err == nil {
		t.Error("expected error for invalid output directory")
	}
}
