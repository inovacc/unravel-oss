package archive

import (
	"archive/zip"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// buildBombJAR writes a .jar at dir/name containing `entries` deflate-compressed
// files, each `size` bytes of zeros (highly compressible). Returns the path.
func buildBombJAR(t *testing.T, dir, name string, entries, size int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)
	payload := make([]byte, size) // zeros -> compresses to near nothing
	for i := 0; i < entries; i++ {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:   "bomb/file" + strconv.Itoa(i) + ".bin",
			Method: zip.Deflate,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// budgetWithCap returns a budget using the current package aggregate cap.
func budgetWithCap() *safeio.Budget {
	b := safeio.NewBudget()
	b.MaxTotalBytes = maxArchiveTotalBytes
	return b
}

// TestExtractZip_AggregateBudgetExceeded verifies that an archive whose total
// uncompressed bytes exceed the (injected, small) aggregate budget is aborted
// with an error, rather than writing tens of GB to disk. Without the fix the
// per-file cap never trips and extractZip returns nil.
func TestExtractZip_AggregateBudgetExceeded(t *testing.T) {
	orig := maxArchiveTotalBytes
	maxArchiveTotalBytes = 256 * 1024 // 256 KiB injected cap
	defer func() { maxArchiveTotalBytes = orig }()

	dir := t.TempDir()
	// 8 entries x 64 KiB = 512 KiB uncompressed > 256 KiB budget.
	jar := buildBombJAR(t, dir, "bomb.jar", 8, 64*1024)

	e := New(slog.Default())
	dest := t.TempDir()

	err := e.extractZip(context.Background(), jar, dest, budgetWithCap())
	if err == nil {
		t.Fatal("expected aggregate budget error, got nil")
	}
}

// TestExtractZip_LegitArchivePasses verifies a small legit archive extracts
// fine under the default generous budget.
func TestExtractZip_LegitArchivePasses(t *testing.T) {
	dir := t.TempDir()
	jar := buildBombJAR(t, dir, "ok.jar", 3, 1024) // 3 KiB total

	e := New(slog.Default())
	dest := t.TempDir()
	if err := e.extractZip(context.Background(), jar, dest, budgetWithCap()); err != nil {
		t.Fatalf("legit archive should extract: %v", err)
	}
}
