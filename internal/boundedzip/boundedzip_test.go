package boundedzip

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// buildZip builds an in-memory zip from a set of entries.
type zipEntry struct {
	name string
	data []byte
	mode os.FileMode // if non-zero, applied via SetMode
	// lyingUncompressed forces UncompressedSize64 to a specific value (post-write override).
	lyingUncompressed uint64
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			hdr.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("CreateHeader %q: %v", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatalf("Write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zw.Close: %v", err)
	}
	return buf.Bytes()
}

func TestBoundedZip(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		raw := buildZip(t, []zipEntry{
			{name: "a.txt", data: []byte("hello")},
			{name: "b.txt", data: []byte("world!")},
		})
		br, err := NewReader(bytes.NewReader(raw), int64(len(raw)), DefaultOptions())
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		var total int64
		for _, f := range br.File {
			data, err := br.ReadEntry(f)
			if err != nil {
				t.Fatalf("ReadEntry %q: %v", f.Name, err)
			}
			total += int64(len(data))
		}
		if total != int64(len("hello")+len("world!")) {
			t.Fatalf("total mismatch: got %d", total)
		}
		if br.TotalRead() != total {
			t.Fatalf("TotalRead %d != %d", br.TotalRead(), total)
		}
	})

	t.Run("per_file_cap_exceeded", func(t *testing.T) {
		big := bytes.Repeat([]byte("x"), 1024)
		raw := buildZip(t, []zipEntry{{name: "big.bin", data: big}})
		opts := Options{MaxPerFile: 512, MaxTotal: 1 << 20}
		br, err := NewReader(bytes.NewReader(raw), int64(len(raw)), opts)
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		_, err = br.ReadEntry(br.File[0])
		if err == nil {
			t.Fatal("expected per-file cap error")
		}
		if !errors.Is(err, ErrPerFileExceeded) {
			t.Fatalf("want ErrPerFileExceeded, got %v", err)
		}
	})

	t.Run("total_cap_exceeded", func(t *testing.T) {
		chunk := bytes.Repeat([]byte("y"), 300)
		raw := buildZip(t, []zipEntry{
			{name: "1", data: chunk},
			{name: "2", data: chunk},
			{name: "3", data: chunk},
		})
		opts := Options{MaxPerFile: 1024, MaxTotal: 700}
		br, err := NewReader(bytes.NewReader(raw), int64(len(raw)), opts)
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		var lastErr error
		for _, f := range br.File {
			if _, err := br.ReadEntry(f); err != nil {
				lastErr = err
				break
			}
		}
		if lastErr == nil {
			t.Fatal("expected total cap error")
		}
		if !errors.Is(lastErr, ErrTotalExceeded) {
			t.Fatalf("want ErrTotalExceeded, got %v", lastErr)
		}
	})

	t.Run("symlink_rejected", func(t *testing.T) {
		raw := buildZip(t, []zipEntry{
			{name: "link", data: []byte("/etc/passwd"), mode: os.ModeSymlink | 0o777},
		})
		br, err := NewReader(bytes.NewReader(raw), int64(len(raw)), DefaultOptions())
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		_, err = br.ReadEntry(br.File[0])
		if err == nil {
			t.Fatal("expected symlink error")
		}
		if !errors.Is(err, ErrSymlinkRejected) {
			t.Fatalf("want ErrSymlinkRejected, got %v", err)
		}
		// CheckEntry should also reject.
		if _, err := br.CheckEntry(br.File[0], t.TempDir()); !errors.Is(err, ErrSymlinkRejected) {
			t.Fatalf("CheckEntry want ErrSymlinkRejected, got %v", err)
		}
	})

	t.Run("zip_slip_rejected", func(t *testing.T) {
		raw := buildZip(t, []zipEntry{
			{name: "../evil.txt", data: []byte("x")},
			{name: "ok.txt", data: []byte("ok")},
		})
		br, err := NewReader(bytes.NewReader(raw), int64(len(raw)), DefaultOptions())
		if err != nil {
			t.Fatalf("NewReader: %v", err)
		}
		dest := t.TempDir()
		if _, err := br.CheckEntry(br.File[0], dest); !errors.Is(err, ErrZipSlip) {
			t.Fatalf("relative escape: want ErrZipSlip, got %v", err)
		}
		// Absolute-path entry — build separately because filepath.IsAbs is platform-aware.
		absName := "/abs/evil.txt"
		if filepath.IsAbs(absName) || filepath.IsAbs(filepath.Clean(absName)) {
			rawAbs := buildZip(t, []zipEntry{{name: absName, data: []byte("x")}})
			brAbs, err := NewReader(bytes.NewReader(rawAbs), int64(len(rawAbs)), DefaultOptions())
			if err != nil {
				t.Fatalf("NewReader abs: %v", err)
			}
			if _, err := brAbs.CheckEntry(brAbs.File[0], dest); !errors.Is(err, ErrZipSlip) {
				t.Fatalf("abs entry: want ErrZipSlip, got %v", err)
			}
		}
		// Stream-mode (destDir="") should also reject parent traversal.
		if _, err := br.CheckEntry(br.File[0], ""); !errors.Is(err, ErrZipSlip) {
			t.Fatalf("stream-mode parent traversal: want ErrZipSlip, got %v", err)
		}
		// Safe entry should pass.
		if _, err := br.CheckEntry(br.File[1], dest); err != nil {
			t.Fatalf("safe entry: unexpected error %v", err)
		}
	})

	t.Run("errors_is_wrapping", func(t *testing.T) {
		// All sentinels must satisfy errors.Is on themselves.
		for _, s := range []error{ErrPerFileExceeded, ErrTotalExceeded, ErrSymlinkRejected, ErrZipSlip} {
			wrapped := errors.Join(errors.New("ctx"), s)
			if !errors.Is(wrapped, s) {
				t.Fatalf("errors.Is failed for %v", s)
			}
		}
	})

	t.Run("openreader_roundtrip", func(t *testing.T) {
		raw := buildZip(t, []zipEntry{{name: "x.txt", data: []byte("hi")}})
		path := filepath.Join(t.TempDir(), "t.zip")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		br, err := OpenReader(path, DefaultOptions())
		if err != nil {
			t.Fatalf("OpenReader: %v", err)
		}
		defer func() { _ = br.Close() }()
		var w bytes.Buffer
		if _, err := br.CopyEntry(br.File[0], &w); err != nil {
			t.Fatalf("CopyEntry: %v", err)
		}
		if w.String() != "hi" {
			t.Fatalf("got %q", w.String())
		}
		_ = io.Discard // keep import alive in case future test reuses it
	})
}
