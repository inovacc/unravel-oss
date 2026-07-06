package snapshot

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func buildCRX3(t *testing.T, files map[string]string) []byte {
	t.Helper()
	zipBuf := buildZIP(t, files)

	var buf bytes.Buffer
	buf.WriteString("Cr24")                                // magic
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3)) // version
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // header length 0
	buf.Write(zipBuf)
	return buf.Bytes()
}

func buildCRX2(t *testing.T, files map[string]string, pubKeyLen, sigLen uint32) []byte {
	t.Helper()
	zipBuf := buildZIP(t, files)

	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	_ = binary.Write(&buf, binary.LittleEndian, pubKeyLen)
	_ = binary.Write(&buf, binary.LittleEndian, sigLen)
	buf.Write(make([]byte, pubKeyLen+sigLen)) // fake key+sig
	buf.Write(zipBuf)
	return buf.Bytes()
}

func buildZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes()
}

func TestExtractCRX3(t *testing.T) {
	data := buildCRX3(t, map[string]string{
		"manifest.json": `{"name":"test"}`,
		"background.js": `console.log("bg")`,
	})
	dest := t.TempDir()
	if err := ExtractCRX(data, dest); err != nil {
		t.Fatalf("ExtractCRX3: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != `{"name":"test"}` {
		t.Errorf("got %q", content)
	}
}

func TestExtractCRX2(t *testing.T) {
	data := buildCRX2(t, map[string]string{"hello.txt": "world"}, 10, 20)
	dest := t.TempDir()
	if err := ExtractCRX(data, dest); err != nil {
		t.Fatalf("ExtractCRX2: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "world" {
		t.Errorf("got %q", content)
	}
}

func TestExtractCRX_TooShort(t *testing.T) {
	if err := ExtractCRX([]byte("abc"), ""); err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestExtractCRX_BadMagic(t *testing.T) {
	if err := ExtractCRX([]byte("XXXX12345678"), ""); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestExtractCRX_UnsupportedVersion(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(99))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	if err := ExtractCRX(buf.Bytes(), ""); err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestExtractCRX_ZipOffsetBeyondData(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(9999)) // header len beyond data
	if err := ExtractCRX(buf.Bytes(), ""); err == nil {
		t.Fatal("expected error for offset beyond data")
	}
}

func TestExtractCRX_CRX2TooShort(t *testing.T) {
	// CRX2 needs 16 bytes minimum but we only give 12
	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
	// only 8+4=12 bytes, need 16
	if err := ExtractCRX(buf.Bytes(), ""); err == nil {
		t.Fatal("expected error for short CRX2")
	}
}

func TestExtractCRX_PathTraversal(t *testing.T) {
	// Create a zip with a path traversal entry
	var zipBuf bytes.Buffer
	w := zip.NewWriter(&zipBuf)
	fw, _ := w.Create("../../../etc/passwd")
	_, _ = fw.Write([]byte("root:x:0:0"))
	_ = w.Close()

	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.Write(zipBuf.Bytes())

	dest := t.TempDir()
	// Should not error but should skip the traversal file
	_ = ExtractCRX(buf.Bytes(), dest)

	// The file should NOT exist outside dest
	if _, err := os.Stat(filepath.Join(dest, "..", "etc", "passwd")); err == nil {
		t.Fatal("path traversal was not blocked")
	}
}

func TestExtractCRX3_WithHeaderData(t *testing.T) {
	zipBuf := buildZIP(t, map[string]string{"a.txt": "hello"})

	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(50)) // 50 bytes of header
	buf.Write(make([]byte, 50))                             // fake header
	buf.Write(zipBuf)

	dest := t.TempDir()
	if err := ExtractCRX(buf.Bytes(), dest); err != nil {
		t.Fatalf("ExtractCRX3 with header: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello" {
		t.Errorf("got %q", content)
	}
}

func TestExtractCRX_SubDirectories(t *testing.T) {
	data := buildCRX3(t, map[string]string{
		"sub/dir/file.txt": "nested",
	})
	dest := t.TempDir()
	if err := ExtractCRX(data, dest); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(dest, "sub", "dir", "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "nested" {
		t.Errorf("got %q", content)
	}
}
